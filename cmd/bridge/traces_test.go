package main

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

// collector is an OTLP/HTTP traces receiver: the spans it was sent.
type collector struct {
	mu    sync.Mutex
	names []string
	spans []seen
}

// seen is a span as its trace backend files it: by service, with its parent (if any) and the traces it links to.
type seen struct {
	name, service string
	parent        bool
	links         []string // trace ids, hex
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var req coltrace.ExportTraceServiceRequest
	if r.URL.Path != "/v1/traces" || proto.Unmarshal(b, &req) != nil {
		http.Error(w, "not an OTLP traces export", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rs := range req.ResourceSpans {
		service := ""
		for _, a := range rs.GetResource().GetAttributes() {
			if a.GetKey() == "service.name" {
				service = a.GetValue().GetStringValue()
			}
		}
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				c.names = append(c.names, s.Name)
				sn := seen{name: s.Name, service: service, parent: len(s.ParentSpanId) > 0}
				for _, l := range s.Links {
					sn.links = append(sn.links, hex.EncodeToString(l.TraceId))
				}
				c.spans = append(c.spans, sn)
			}
		}
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	_, _ = w.Write(nil)
}

func (c *collector) got() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := map[string]int{}
	for _, n := range c.names {
		m[n]++
	}
	return m
}

// TestMainTraces runs the real binary (main, in a child process) with OTEL_EXPORTER_OTLP_TRACES_ENDPOINT set: a span
// per webhook route and per API call reaches the collector, and so does the span of a request still in flight at
// SIGTERM (main waits for handlers before it shuts the tracer down). Every span is service ukubi-bridge's and a root:
// a caller's traceparent (on one webhook and one API call) is linked, never a parent. Needs BRIDGE_TEST_DATABASE_URL.
func TestMainTraces(t *testing.T) {
	if os.Getenv("BRIDGE_MAIN_CHILD") == "1" {
		main()
		return
	}
	base := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP DATABASE IF EXISTS bridge_main_test WITH (FORCE)`, `CREATE DATABASE bridge_main_test`} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	u, _ := url.Parse(base)
	u.Path = "/bridge_main_test"

	col := &collector{}
	otlp := httptest.NewServer(col)
	defer otlp.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	addr := "http://" + ln.Addr().String()

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainTraces$")
	cmd.Env = append(os.Environ(), "BRIDGE_MAIN_CHILD=1", "BRIDGE_DATABASE_URL="+u.String(), "BRIDGE_GITHUB_WEBHOOK_SECRET=s",
		"PORT="+strconv.Itoa(port), "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="+otlp.URL+"/v1/traces")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	for i := 0; ; i++ {
		if r, err := http.Get(addr + "/healthz"); err == nil {
			_ = r.Body.Close()
			break
		}
		if i == 100 {
			t.Fatalf("the bridge never answered: %s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	const caller = "0af7651916cd43dd8448eb211c80319c"
	traceparent := "00-" + caller + "-b7ad6b7169203331-01"
	for _, p := range []string{"/webhook/github", "/webhook/alertmanager", "/webhook/grafana"} {
		req, _ := http.NewRequest(http.MethodPost, addr+p, strings.NewReader("{}"))
		if p == "/webhook/github" {
			req.Header.Set("traceparent", traceparent)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
	}
	api := bridgev1connect.NewBridgeServiceClient(http.DefaultClient, addr)
	pub := connect.NewRequest(&bridgev1.PublishRequest{})
	pub.Header().Set("traceparent", traceparent)
	if _, err := api.Publish(ctx, pub); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("Publish without a token: %v", err)
	}
	if s, err := api.Subscribe(ctx, connect.NewRequest(&bridgev1.SubscribeRequest{})); err == nil {
		for s.Receive() {
		}
		if connect.CodeOf(s.Err()) != connect.CodeUnauthenticated {
			t.Fatalf("Subscribe without a token: %v", s.Err())
		}
	}

	// A webhook whose body never ends: the GitHub handler reads the body before it can check the signature, so it is
	// in flight when SIGTERM comes, and returns only after srv.Close (the alert handlers refuse before reading).
	body, feed := io.Pipe()
	defer func() { _ = feed.Close() }()
	req, _ := http.NewRequest(http.MethodPost, addr+"/webhook/github", body)
	go func() {
		if r, err := http.DefaultClient.Do(req); err == nil {
			_ = r.Body.Close()
		}
	}()
	_, _ = feed.Write([]byte("{"))
	time.Sleep(200 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("exit: %v: %s", err, out.String())
	}
	want := map[string]int{
		"POST /webhook/github": 2, "POST /webhook/alertmanager": 1, "POST /webhook/grafana": 1,
		"bridge.v1.BridgeService/Publish": 1, "bridge.v1.BridgeService/Subscribe": 1,
	}
	got := col.got()
	for n, c := range want {
		if got[n] != c {
			t.Errorf("%d spans %q, want %d (all: %v)", got[n], n, c, got)
		}
	}
	linked := map[string]int{}
	for _, s := range col.spans {
		if s.service != "ukubi-bridge" || s.parent || len(s.links) > 1 || len(s.links) == 1 && s.links[0] != caller {
			t.Errorf("%s: service %q parent %v links %v", s.name, s.service, s.parent, s.links)
		}
		linked[s.name] += len(s.links)
	}
	if linked["POST /webhook/github"] != 1 || linked["bridge.v1.BridgeService/Publish"] != 1 {
		t.Errorf("the caller's trace is not linked once from each traced call: %v", linked) // the positive control
	}
}

// TestHandlersWait: wait returns false while a request is in flight past d, and true once none is.
func TestHandlersWait(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	h := &handlers{h: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release })}
	if !h.wait(0) {
		t.Fatal("nothing in flight, and wait says otherwise")
	}
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		close(done)
	}()
	<-entered
	if h.wait(30 * time.Millisecond) {
		t.Fatal("wait returned true with a request in flight")
	}
	close(release)
	<-done
	if !h.wait(time.Second) {
		t.Fatal("the request finished, and wait says otherwise")
	}
}
