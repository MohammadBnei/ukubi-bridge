package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// verifyJWT checks an App JWT the way GitHub does: RS256 over the public key.
func verifyJWT(pub *rsa.PublicKey, tok string, now time.Time) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return errors.New("not a JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return err
	}
	var hdr struct{ Alg string }
	var c struct {
		Iat, Exp int64
		Iss      string
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(h, &hdr) != nil || json.Unmarshal(b, &c) != nil {
		return errors.New("bad JSON")
	}
	if hdr.Alg != "RS256" || c.Iss != "12345" || c.Iat > now.Unix() || c.Exp <= now.Unix() || c.Exp-c.Iat > 600 {
		return fmt.Errorf("bad claims %+v %+v", hdr, c)
	}
	return nil
}

type fakeGitHub struct {
	t       *testing.T
	pub     *rsa.PublicKey
	now     time.Time
	pages   [][]map[string]any
	limitOn string // path that answers 429
	mu      sync.Mutex
	posted  []string
	lists   int
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := verifyJWT(f.pub, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), f.now); err != nil {
		f.t.Errorf("JWT: %v", err)
		http.Error(w, "bad jwt", http.StatusUnauthorized)
		return
	}
	if r.URL.Path == f.limitOn {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/app/hook/deliveries":
		f.lists++
		page := 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			fmt.Sscan(c, &page)
		}
		if page+1 < len(f.pages) {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/app/hook/deliveries?per_page=100&cursor=%d>; rel="next"`, r.Host, page+1))
		}
		json.NewEncoder(w).Encode(f.pages[page])
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/attempts"):
		f.mu.Lock()
		f.posted = append(f.posted, r.URL.Path)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	default:
		http.NotFound(w, r)
	}
}

func d(id int64, guid string, ago time.Duration, status int, now time.Time) map[string]any {
	return map[string]any{"id": id, "guid": guid, "delivered_at": now.Add(-ago).Format(time.RFC3339),
		"status_code": status, "event": "pull_request", "repository_id": 1}
}

func setup(t *testing.T, pages [][]map[string]any, limitOn string) (*Reconciler, *fakeGitHub) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through PEM as the env var carries it.
	k, err := ParseKey(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	gh := &fakeGitHub{t: t, pub: &key.PublicKey, now: now, pages: pages, limitOn: limitOn}
	srv := httptest.NewServer(gh)
	t.Cleanup(srv.Close)
	known := map[string]bool{"in-log": true, "ok": true, "retried-ok": true}
	return &Reconciler{
		API: srv.URL, AppID: "12345", Key: k, Lookback: 6 * time.Hour, Client: srv.Client(),
		Known: func(_ context.Context, guids []string) (map[string]bool, error) {
			m := map[string]bool{}
			for _, g := range guids {
				m[g] = known[g]
			}
			return m, nil
		},
	}, gh
}

func TestReconcileRedeliversOnlyMissing(t *testing.T) {
	now := time.Now()
	pages := [][]map[string]any{
		{
			d(10, "missing", time.Minute, 503, now),      // bridge down: redeliver
			d(11, "in-log", 2*time.Minute, 503, now),     // failed but landed: skip
			d(12, "ok", 3*time.Minute, 202, now),         // accepted and in the log: skip
			d(13, "retried-ok", 4*time.Minute, 202, now), // a later redelivery succeeded...
			d(14, "conn-refused", 5*time.Minute, 0, now), // no response at all: redeliver
			d(15, "ignored", 6*time.Minute, 204, now),    // check_run etc.: skip
			d(50, "lost", 11*time.Minute, 202, now),      // acknowledged, then lost to a failover: redeliver
		},
		{
			d(20, "retried-ok", 2*time.Hour, 502, now), // ...so this failure is settled
			d(21, "missing-2", 3*time.Hour, 500, now),  // second page: redeliver (latest id)
			d(22, "missing-2", 3*time.Hour+10*time.Minute, 500, now),
			d(23, "too-old", 7*time.Hour, 500, now), // before the window: stop paging here
		},
		{d(30, "never-reached", 8*time.Hour, 500, now)},
	}
	for i := range maxAttempts {
		pages[0] = append(pages[0], d(int64(40+i), "hopeless", time.Duration(6+i)*time.Minute, 400, now))
	}
	r, gh := setup(t, pages, "")
	n, err := r.Run(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	// Oldest original delivery first.
	want := []string{"/app/hook/deliveries/21/attempts", "/app/hook/deliveries/50/attempts", "/app/hook/deliveries/14/attempts", "/app/hook/deliveries/10/attempts"}
	if n != len(want) || !slices.Equal(gh.posted, want) {
		t.Fatalf("redelivered %d %v, want %v", n, gh.posted, want)
	}
	if gh.lists != 2 {
		t.Fatalf("listed %d pages, want 2: paging must stop at the lookback window", gh.lists)
	}
}

func TestReconcileStopsOnRateLimit(t *testing.T) {
	now := time.Now()
	pages := [][]map[string]any{{d(10, "a", time.Minute, 503, now), d(11, "b", time.Minute, 503, now)}}
	r, gh := setup(t, pages, "/app/hook/deliveries/10/attempts")
	if _, err := r.Run(context.Background(), now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err=%v, want ErrRateLimited", err)
	}
	if len(gh.posted) != 0 {
		t.Fatalf("kept going after 429: %v", gh.posted)
	}
	r, _ = setup(t, pages, "/app/hook/deliveries")
	if _, err := r.Run(context.Background(), now); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("list: err=%v, want ErrRateLimited", err)
	}
}

func TestPickCapsRejectsNotOutages(t *testing.T) {
	now := time.Now()
	at := func(ago time.Duration, status int, redelivery bool) delivery {
		return delivery{DeliveredAt: now.Add(-ago), StatusCode: status, Redelivery: redelivery}
	}
	var outage, rejected []delivery // newest first: redeliveries, then the original
	for i := range maxAttempts - 1 {
		outage = append(outage, at(time.Duration(i)*time.Minute, 502, true))
		rejected = append(rejected, at(time.Duration(i)*time.Minute, 400, true))
	}
	attempts := map[string][]delivery{
		"retry":    {at(time.Minute, 502, true), at(time.Hour, 202, false)},
		"fresh":    {at(2*time.Minute, 0, false)},
		"outage":   append(slices.Clone(outage), at(5*time.Hour, 502, false)),   // 5xx: keep retrying
		"rejected": append(slices.Clone(rejected), at(5*time.Hour, 400, false)), // maxAttempts 4xx: give up
		"orphaned": outage,                                                      // original left the window
		"ignored":  {at(time.Minute, 204, false)},
	}
	redeliver, givenUp := pick(attempts, []string{"fresh", "retry", "outage", "rejected", "orphaned", "ignored"})
	if !slices.Equal(redeliver, []string{"outage", "retry", "fresh"}) || !slices.Equal(givenUp, []string{"rejected", "orphaned"}) {
		t.Fatalf("redeliver %v, given up %v", redeliver, givenUp)
	}
}
