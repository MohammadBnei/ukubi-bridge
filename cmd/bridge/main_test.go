package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/MohammadBnei/ukubi-bridge/internal/bus"
	"github.com/MohammadBnei/ukubi-bridge/internal/github"
	"github.com/MohammadBnei/ukubi-bridge/internal/metrics"
	"github.com/MohammadBnei/ukubi-bridge/internal/store"
)

// An oversized body is refused before the HMAC check, whether it announces its
// length or streams chunked. The store is never reached, so nil is fine.
func TestGithubHandlerRejectsOversizedBody(t *testing.T) {
	h := githubHandler(nil, github.Policy{}, []byte("s"))
	big := strings.Repeat("x", maxBody+1)

	for name, r := range map[string]*http.Request{
		"content-length": httptest.NewRequest("POST", "/webhook/github", strings.NewReader(big)),
		"chunked":        httptest.NewRequest("POST", "/webhook/github", io.NopCloser(strings.NewReader(big))),
	} {
		if name == "chunked" {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 413", name, w.Code)
		}
	}

	// At the cap it still reads, then fails the signature as unsigned.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/webhook/github", strings.NewReader(big[:maxBody])))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("at cap: status %d, want 401", w.Code)
	}
}

// forgejoPost is a Forgejo delivery. sig "" signs body with secret; "-" sends
// an empty signature, as Forgejo does for a webhook without a secret.
func forgejoPost(secret []byte, kind, delivery, body, sig string) *http.Request {
	switch sig {
	case "":
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(body))
		sig = hex.EncodeToString(m.Sum(nil))
	case "-":
		sig = ""
	}
	r := httptest.NewRequest("POST", "/webhook/forgejo", strings.NewReader(body))
	r.Header.Set("X-Forgejo-Event-Type", kind)
	r.Header.Set("X-Forgejo-Delivery", delivery)
	r.Header.Set("X-Forgejo-Signature", sig)
	return r
}

// Forgejo's route checks X-Forgejo-Signature before it reads a header, answers
// 204 to a signed event it does not carry and 400 to one it cannot use. None
// reaches the store, so nil is fine.
func TestForgejoHandler(t *testing.T) {
	secret := []byte("s")
	h := forgejoHandler(nil, github.Policy{}, secret)
	const id = "8a0f7c1e-5d2b-4e3a-9c6f-1b2d3e4f5a6b"
	push := `{"ref":"refs/heads/main","repository":{"full_name":"MohammadBnei/editable-blog"}}`
	// synchronized keeps the delivery id as its ce_id (forgejo.factID).
	synced, err := os.ReadFile("../../internal/forgejo/testdata/pull_request_synchronized.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name                 string
		kind, delivery, body string
		sig                  string // see forgejoPost
		want                 int
	}{
		{"ignored", "push", id, push, "", http.StatusNoContent},
		{"unsigned", "push", id, push, "-", http.StatusUnauthorized},
		{"github form", "push", id, push, "sha256=" + forgejoPost(secret, "", "", push, "").Header.Get("X-Forgejo-Signature"), http.StatusUnauthorized},
		{"bad json", "pull_request", id, `{"action":`, "", http.StatusBadRequest},
		{"no delivery", "pull_request_sync", "", string(synced), "", http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, forgejoPost(secret, c.kind, c.delivery, c.body, c.sig))
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
	}
}

// Without BRIDGE_FORGEJO_WEBHOOK_SECRET there is no route: a delivery is a 404,
// never read.
func TestForgejoRouteOff(t *testing.T) {
	for secret, want := range map[string]int{"": http.StatusNotFound, "s": http.StatusUnauthorized} {
		mux := http.NewServeMux()
		forgejoRoute(func(p string, h http.Handler) { mux.Handle(p, h) }, nil, Config{ForgejoSecret: secret})
		on := 0.0
		if secret != "" {
			on = 1
		}
		if got := testutil.ToFloat64(metrics.EnabledFor(metrics.ForgejoWebhook)); got != on {
			t.Errorf("secret %q: bridge_flow_enabled %v, want %v", secret, got, on)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, forgejoPost(nil, "push", "d", "{}", "-"))
		if w.Code != want {
			t.Errorf("secret %q: status %d, want %d", secret, w.Code, want)
		}
	}
}

// A carried fact is stored once, with the Forgejo policy: an opened is keyed on
// its content, so a redelivery under a new X-Forgejo-Delivery is the same
// event. Needs BRIDGE_TEST_DATABASE_URL.
func TestForgejoHandlerStores(t *testing.T) {
	base := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP DATABASE IF EXISTS bridge_forgejo_test WITH (FORCE)`, `CREATE DATABASE bridge_forgejo_test`} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	u, _ := url.Parse(base)
	u.Path = "/bridge_forgejo_test"
	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	body, err := os.ReadFile("../../internal/forgejo/testdata/pull_request_opened.json")
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("s")
	h := forgejoHandler(st, github.Policy{Agents: map[string]bool{"ukubi-fleet": true}}, secret)
	for i, delivery := range []string{"8a0f7c1e-5d2b-4e3a-9c6f-1b2d3e4f5a6b", "a-manual-redelivery"} { // the second is a 202 too, stored once
		w := httptest.NewRecorder()
		h.ServeHTTP(w, forgejoPost(secret, "pull_request", delivery, string(body), ""))
		if w.Code != http.StatusAccepted {
			t.Fatalf("post %d: status %d, want 202: %s", i, w.Code, w.Body)
		}
	}
	db, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	var n int
	var owned bool
	if err := db.QueryRow(ctx, `SELECT count(*), bool_and(thread_owned) FROM events WHERE ce_id = 'pr/42/opened'`).Scan(&n, &owned); err != nil {
		t.Fatal(err)
	}
	if n != 1 || !owned {
		t.Errorf("stored %d rows, owned=%v; want 1, true", n, owned)
	}
}

// TestMainWarnings runs the real main in a child process: an optional setting that does not satisfy its rule is one
// JSON WARN line and its default, and the start goes on (to the store, a closed port here, which ends it). The
// positive control is the missing webhook secret: an ERROR line, and the store is never reached.
func TestMainWarnings(t *testing.T) {
	if os.Getenv("BRIDGE_WARN_CHILD") == "1" {
		main()
		return
	}
	run := func(env ...string) []map[string]any {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainWarnings$")
		cmd.Env = append([]string{"BRIDGE_WARN_CHILD=1", "PATH=" + os.Getenv("PATH"), "GOCOVERDIR=" + t.TempDir(),
			"BRIDGE_DATABASE_URL=postgres://u:p@127.0.0.1:1/x?connect_timeout=2"}, env...)
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		_ = cmd.Run() // exit 1 either way: at the store, or at the refusal
		var lines []map[string]any
		sc := bufio.NewScanner(strings.NewReader(out.String()))
		for sc.Scan() {
			var l map[string]any
			if json.Unmarshal(sc.Bytes(), &l) == nil {
				lines = append(lines, l)
			}
		}
		return lines
	}
	find := func(lines []map[string]any, level, prefix string) bool {
		for _, l := range lines {
			if l["level"] == level && strings.HasPrefix(l["msg"].(string), prefix) {
				return true
			}
		}
		return false
	}
	lines := run("BRIDGE_GITHUB_WEBHOOK_SECRET=s", "BRIDGE_RETENTION=nope", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=nope")
	for _, prefix := range []string{"BRIDGE_RETENTION must be", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not", "flow off: BRIDGE_K8S_SA_KEY is unset"} {
		if !find(lines, "WARN", prefix) {
			t.Errorf("no WARN line %q: %v", prefix, lines)
		}
	}
	if !find(lines, "ERROR", "open store") {
		t.Errorf("the start did not go on to the store: %v", lines)
	}
	// A cluster key that does not parse is a trust input: refused, closed, before the store.
	lines = run("BRIDGE_GITHUB_WEBHOOK_SECRET=s", "BRIDGE_K8S_SA_KEY=not a key")
	if !find(lines, "ERROR", "k8s sa") || find(lines, "ERROR", "open store") {
		t.Errorf("a bad cluster key: %v", lines)
	}
	lines = run("BRIDGE_RETENTION=nope")
	if !find(lines, "ERROR", "BRIDGE_GITHUB_WEBHOOK_SECRET is required") || find(lines, "ERROR", "open store") {
		t.Errorf("a missing secret: %v", lines)
	}
}

// A client's flow is on only while the API can verify one of its tokens: authentik's for any row, the cluster's for
// a row with an sa.
func TestClientFlows(t *testing.T) {
	clients := map[string]bus.Client{"t-pub": {PublishTypes: []string{"dev.bnei.x."}}, "t-sa": {PublishTypes: []string{"dev.bnei.x."}, SA: "ns:x"},
		"t-sub": {}}
	for _, c := range []struct {
		oidc, sa    bool
		pub, withSA float64
	}{{true, false, 1, 1}, {false, false, 0, 0}, {false, true, 0, 1}, {true, true, 1, 1}} {
		clientFlows(clients, c.oidc, c.sa)
		if got, got2 := testutil.ToFloat64(metrics.EnabledFor("t-pub")), testutil.ToFloat64(metrics.EnabledFor("t-sa")); got != c.pub || got2 != c.withSA {
			t.Errorf("oidc %v sa %v: t-pub %v t-sa %v, want %v %v", c.oidc, c.sa, got, got2, c.pub, c.withSA)
		}
	}
}

// TestInCluster: the JWKS client trusts the given CA and sends the token file's current contents as its bearer.
func TestInCluster(t *testing.T) {
	var got []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(dir+"/ca.crt", ca, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := inCluster(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"one\n", "two"} {
		if err := os.WriteFile(dir+"/token", []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
	}
	if strings.Join(got, ",") != "Bearer one,Bearer two" {
		t.Errorf("bearers %v", got)
	}
	// A redirect is not followed: the token goes to the URL that was set, nowhere else.
	res, err := c.Get(srv.URL + "/moved")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound || len(got) != 3 {
		t.Errorf("redirect: status %d, %d requests", res.StatusCode, len(got))
	}
	if _, err := inCluster(t.TempDir()); err == nil {
		t.Error("no CA file: a client anyway")
	}
}
