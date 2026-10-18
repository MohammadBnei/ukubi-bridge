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
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"time"
)

// maxAttempts caps redelivery of a GUID the bridge rejected as unusable (400 on
// every attempt), so it is not retried every run for the whole lookback. Any
// other failure (0, 401, 403, 5xx) retries until it leaves the window: those
// are outages, which is what the loop is for.
const maxAttempts = 5

// Reconciler redelivers App webhook deliveries missing from the log, failed or
// acknowledged: bridge downtime, or an event lost to a Pigsty failover (ADR-0059 §5).
type Reconciler struct {
	API      string // "https://api.github.com"
	AppID    string
	Key      *rsa.PrivateKey
	Lookback time.Duration
	// Known reports which delivery GUIDs are already in events (store.Known).
	Known  func(ctx context.Context, guids []string) (map[string]bool, error)
	Client *http.Client
}

// ErrRateLimited stops a run; the next tick tries again.
var ErrRateLimited = errors.New("github rate limit")

// ParseKey reads the App private key, PKCS#1 as GitHub issues it or PKCS#8.
func ParseKey(pemText string) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(pemText))
	if b == nil {
		return nil, errors.New("no PEM block in private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

// AppJWT signs the App's RS256 JWT. iat is backdated 60s for clock drift;
// GitHub refuses exp more than 10 minutes out.
func AppJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	signing := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

type delivery struct {
	ID          int64     `json:"id"`
	GUID        string    `json:"guid"`
	DeliveredAt time.Time `json:"delivered_at"`
	StatusCode  int       `json:"status_code"`
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Run does one pass and returns how many deliveries it asked GitHub to redeliver.
func (r *Reconciler) Run(ctx context.Context, now time.Time) (int, error) {
	jwt, err := AppJWT(r.AppID, r.Key, now)
	if err != nil {
		return 0, err
	}
	call := func(method, url string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := r.Client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			return nil, fmt.Errorf("%w: %s %s: %d, retry-after %q, reset %q", ErrRateLimited, method, url,
				resp.StatusCode, resp.Header.Get("Retry-After"), resp.Header.Get("X-RateLimit-Reset"))
		}
		return resp, nil
	}

	// Newest first; page back until the lookback window ends.
	since := now.Add(-r.Lookback)
	attempts := map[string][]delivery{} // by GUID: the original and its redeliveries
	var order []string
	url := r.API + "/app/hook/deliveries?per_page=100"
	for url != "" {
		resp, err := call(http.MethodGet, url)
		if err != nil {
			return 0, err
		}
		var page []delivery
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil {
			return 0, fmt.Errorf("list deliveries: status %d: %v", resp.StatusCode, err)
		}
		url = ""
		if m := nextLink.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			url = m[1]
		}
		for _, d := range page {
			if d.DeliveredAt.Before(since) {
				url = ""
				break
			}
			if attempts[d.GUID] == nil {
				order = append(order, d.GUID)
			}
			attempts[d.GUID] = append(attempts[d.GUID], d)
		}
	}

	// Candidates: every GUID not deliberately ignored. A 202 is checked too: it
	// can be lost to an async failover after the bridge acknowledged it.
	var failed []string
	for _, guid := range order {
		ignored, rejected := false, true
		for _, d := range attempts[guid] {
			ignored = ignored || d.StatusCode == http.StatusNoContent
			rejected = rejected && d.StatusCode == http.StatusBadRequest
		}
		if ignored {
			continue // check_run etc.: never in the log by design
		}
		if rejected && len(attempts[guid]) >= maxAttempts {
			slog.Warn("reconcile: giving up on delivery", "guid", guid, "attempts", len(attempts[guid]), "status", 400)
			continue
		}
		failed = append(failed, guid)
	}
	if len(failed) == 0 {
		return 0, nil
	}
	// Oldest first, by original delivery, so a missed opened lands before its closed.
	// ponytail: best effort only; GitHub redelivers asynchronously.
	first := func(g string) delivery { a := attempts[g]; return a[len(a)-1] }
	slices.SortStableFunc(failed, func(a, b string) int {
		return first(a).DeliveredAt.Compare(first(b).DeliveredAt)
	})
	// A failed status can still have landed (the store wrote, the response was lost).
	known, err := r.Known(ctx, failed)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, guid := range failed {
		if known[guid] {
			continue
		}
		latest := attempts[guid][0]
		resp, err := call(http.MethodPost, fmt.Sprintf("%s/app/hook/deliveries/%d/attempts", r.API, latest.ID))
		if err != nil {
			return n, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			slog.Warn("reconcile: redeliver refused", "guid", guid, "id", latest.ID, "status", resp.StatusCode)
			continue
		}
		slog.Info("reconcile: redelivered", "guid", guid, "id", latest.ID)
		n++
	}
	return n, nil
}

// Loop runs every interval until ctx ends, starting now.
func (r *Reconciler) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		n, err := r.Run(ctx, time.Now())
		if err != nil {
			slog.Error("reconcile", "redelivered", n, "err", err)
		} else if n > 0 {
			slog.Info("reconcile done", "redelivered", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
