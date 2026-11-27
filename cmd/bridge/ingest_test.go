package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-go/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/ingest"
	"github.com/MohammadBnei/ukubi-bridge/internal/metrics"
	"github.com/MohammadBnei/ukubi-bridge/internal/store"
)

// laptopKey is a made-up key of the right shape.
func laptopKey() string {
	sum := sha256.Sum256([]byte("not a credential"))
	return hex.EncodeToString(sum[:])
}

func laptopPost(key, body string, at time.Time) *http.Request {
	ts := strconv.FormatInt(at.Unix(), 10)
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte("ingest/laptop\n" + ts + "\n" + body))
	r := httptest.NewRequest(http.MethodPost, "/ingest/laptop", strings.NewReader(body))
	r.Header.Set(ingest.TimestampHeader, ts)
	r.Header.Set(ingest.SignatureHeader, hex.EncodeToString(m.Sum(nil)))
	return r
}

// Without its secret there is no route (404) and the flow reads 0; with it, an unsigned request is a 401.
func TestLaptopRouteOff(t *testing.T) {
	for secret, want := range map[string]int{"": http.StatusNotFound, laptopKey(): http.StatusUnauthorized} {
		cfg, cerr := load(envOf(map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_INGEST_LAPTOP_SECRET": secret}))
		if cerr != nil {
			t.Fatal(cerr)
		}
		metrics.SetEnabled(metrics.IngestLaptop, secret == "") // the other way round
		mux := http.NewServeMux()
		laptopRoute(func(p string, h http.Handler) { mux.Handle(p, h) }, func(context.Context, event.Event) (bool, error) {
			t.Error("stored")
			return false, nil
		}, cfg)
		on := 0.0
		if secret != "" {
			on = 1
		}
		if got := testutil.ToFloat64(metrics.EnabledFor(metrics.IngestLaptop)); got != on {
			t.Errorf("bridge_flow_enabled %v, want %v", got, on)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, laptopPost("", "{}", time.Now()))
		if w.Code != want {
			t.Errorf("secret set %v: status %d, want %d", secret != "", w.Code, want)
		}
	}
}

// A secret that is not a key never stops the bridge: one error that does not hold it, no route, and the flow reads 0.
func TestLaptopSecretNotAKey(t *testing.T) {
	k := laptopKey()
	for _, v := range []string{"", " ", "x", k[:63], k + "\n", " " + k, strings.ToUpper(k), strings.Repeat("0", 64)} {
		c, cerr := load(envOf(map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_INGEST_LAPTOP_SECRET": v}))
		if cerr != nil {
			t.Errorf("%q: the bridge refuses to start", v)
			continue
		}
		var buf bytes.Buffer
		old := slog.Default()
		slog.SetDefault(newLogger(&buf))
		metrics.SetEnabled(metrics.IngestLaptop, true)
		mux := http.NewServeMux()
		laptopRoute(func(p string, h http.Handler) { mux.Handle(p, h) }, nil, c)
		slog.SetDefault(old)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, laptopPost(v, "{}", time.Now()))
		if w.Code != http.StatusNotFound || testutil.ToFloat64(metrics.EnabledFor(metrics.IngestLaptop)) != 0 {
			t.Errorf("%q: status %d", v, w.Code)
		}
		line := buf.String()
		if strings.Count(line, "\n") != 1 || !strings.Contains(line, `"level":"ERROR"`) || len(v) > 8 && strings.Contains(line, strings.TrimSpace(v)) {
			t.Errorf("%q: logged %s", v, line)
		}
		if strings.HasSuffix(v, "\n") != strings.Contains(line, "ends with a newline") {
			t.Errorf("%q: logged %s", v, line)
		}
	}
}

// The route stops reading a body that does not come, through the tracing main wraps it in.
func TestLaptopReadDeadline(t *testing.T) {
	tel, err := telemetry.New("", "ukubi-bridge")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	laptopRoute(func(p string, h http.Handler) { mux.Handle(p, tel.Handler(p, h)) }, func(context.Context, event.Event) (bool, error) { return true, nil }, Config{LaptopSecret: laptopKey()})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	start := time.Now()
	_, _ = io.WriteString(conn, "POST /ingest/laptop HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{")
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if d := time.Since(start); err != nil || !strings.Contains(line, "400") || d > 8*time.Second {
		t.Errorf("after %v: %q %v", d, line, err)
	}
}

// The repos a post may be about are a fixed list; an entry that is not a repo is skipped with a warning.
func TestConfigLaptopRepos(t *testing.T) {
	c, err := load(envOf(map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_INGEST_LAPTOP_REPOS": " o/r, o/s,"}))
	if err != nil || len(c.LaptopRepos) != 2 || !c.LaptopRepos["o/r"] || !c.LaptopRepos["o/s"] {
		t.Errorf("%v %v", c.LaptopRepos, err)
	}
	c, err = load(envOf(map[string]string{"BRIDGE_GITHUB_WEBHOOK_SECRET": "s", "BRIDGE_INGEST_LAPTOP_REPOS": "o/r,x"}))
	if err != nil || len(c.LaptopRepos) != 1 || len(c.Warnings) != 1 || !strings.HasPrefix(c.Warnings[0].msg, "BRIDGE_INGEST_LAPTOP_REPOS") {
		t.Errorf("%v %v %v", c.LaptopRepos, c.Warnings, err)
	}
}

// main wires the route to the store.
func TestLaptopWired(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\n\tlaptopRoute(route, st.Insert, cfg)\n") {
		t.Error("main does not call laptopRoute")
	}
}

// A post is stored once, masked: a request replayed in the window, or signed again later, is the same event. Needs
// BRIDGE_TEST_DATABASE_URL.
func TestLaptopStores(t *testing.T) {
	base := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	dbn := fmt.Sprintf("bridge_ingest_test_%d", time.Now().UnixNano()) // a name of its own: concurrent CI runs share one Postgres
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbn+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u, _ := url.Parse(base)
	u.Path = "/" + dbn
	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	mux := http.NewServeMux()
	laptopRoute(func(p string, h http.Handler) { mux.Handle(p, h) }, st.Insert, Config{LaptopSecret: laptopKey()})
	now := time.Now()
	body := func(id string) string {
		return `{"session":"11111111-2222-4333-8444-555555555555","post_id":"` + id + `","text":"password: hunter22","needs_you":[]}`
	}
	one, two := body("66666666-7777-4888-9999-000000000000"), body("66666666-7777-4888-9999-000000000001")
	for i, c := range []struct {
		r     *http.Request
		isNew string
	}{{laptopPost(laptopKey(), one, now), "true"}, {laptopPost(laptopKey(), one, now), "false"}, {laptopPost(laptopKey(), one, now.Add(-time.Minute)), "false"}, {laptopPost(laptopKey(), two, now), "true"}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, c.r)
		if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"new":`+c.isNew) {
			t.Fatalf("post %d: status %d %s, want new %s", i, w.Code, w.Body, c.isNew)
		}
	}
	db, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	var n int
	var clean bool
	if err := db.QueryRow(ctx, `SELECT count(*), bool_and(source = 'ingest/laptop' AND actor = 'machine' AND NOT actor_trusted AND NOT thread_owned
		AND data::text NOT LIKE '%hunter%' AND data->'needs_you' = '[]' AND producer->>'name' = 'ingest-laptop') FROM events`).Scan(&n, &clean); err != nil {
		t.Fatal(err)
	}
	if n != 2 || !clean {
		t.Errorf("stored %d rows, as expected %v; want 2 posts", n, clean)
	}
}
