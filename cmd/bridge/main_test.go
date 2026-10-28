package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/github"
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
	for _, prefix := range []string{"BRIDGE_RETENTION must be", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not"} {
		if !find(lines, "WARN", prefix) {
			t.Errorf("no WARN line %q: %v", prefix, lines)
		}
	}
	if !find(lines, "ERROR", "open store") {
		t.Errorf("the start did not go on to the store: %v", lines)
	}
	lines = run("BRIDGE_RETENTION=nope")
	if !find(lines, "ERROR", "BRIDGE_GITHUB_WEBHOOK_SECRET is required") || find(lines, "ERROR", "open store") {
		t.Errorf("a missing secret: %v", lines)
	}
}
