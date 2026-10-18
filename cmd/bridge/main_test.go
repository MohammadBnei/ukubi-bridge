package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
