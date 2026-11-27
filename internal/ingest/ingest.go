// Package ingest serves the /ingest/<route> endpoints: signed events from sources outside the cluster. The server sets
// the source and the actor, and a body carries its own route's fields only, never a trust attribute.
package ingest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/metrics"
	"github.com/MohammadBnei/ukubi-bridge/internal/store"
)

// LaptopSource is the laptop route's event source and the first line of what it signs.
const LaptopSource = "ingest/laptop"

// The request's headers: unix seconds, and the hex HMAC-SHA256 of "<source>\n<timestamp>\n<body>".
const (
	TimestampHeader = "X-Ingest-Timestamp"
	SignatureHeader = "X-Ingest-Signature"
)

const (
	maxBody = 16 << 10
	skew    = 5 * time.Minute
	reading = 5 * time.Second // of the body
	working = 2 * time.Second // on a post, before the store
)

// Key reports why s cannot be a route's key: "" when it can, a string of 64 lowercase hex characters.
func Key(s string) string {
	seen := map[rune]bool{}
	for _, r := range s {
		seen[r] = true
	}
	switch {
	case s == "":
		return "it is unset"
	case strings.HasSuffix(s, "\n"):
		return "it ends with a newline"
	case strings.TrimSpace(s) != s:
		return "it starts or ends with a space"
	case !hexKey.MatchString(s):
		return "it is not 64 lowercase hex characters"
	case len(seen) < 8:
		return "it is not random"
	}
	return ""
}

var hexKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Verify checks signature over source, timestamp and body.
func Verify(key []byte, source, timestamp string, body []byte, signature string) bool {
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(source + "\n" + timestamp + "\n"))
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}

// fresh reports a timestamp at most skew away from now, either way.
func fresh(timestamp string, now time.Time) bool {
	sec, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	t := time.Unix(sec, 0)
	return !t.Before(now.Truncate(time.Second).Add(-skew)) && !t.After(now.Add(skew))
}

// answer is what a request gets: the post's id and whether it is new, or why it was refused; and the fields
// something was masked in, never what.
type answer struct {
	PostID string   `json:"post_id,omitempty"`
	New    bool     `json:"new"`
	Error  string   `json:"error,omitempty"`
	Masked []string `json:"masked,omitempty"`
}

func reply(w http.ResponseWriter, code int, a answer) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(a)
}

// Laptop serves POST /ingest/laptop. repos are the repos a post may be about; insert is store.Insert.
func Laptop(key string, repos map[string]bool, insert func(context.Context, event.Event) (bool, error)) http.Handler {
	// 10 a minute, 20 at once.
	return handler([]byte(key), repos, insert, time.Now, rate.NewLimiter(rate.Every(6*time.Second), 20))
}

func handler(key []byte, repos map[string]bool, insert func(context.Context, event.Event) (bool, error), now func() time.Time, bucket *rate.Limiter) http.Handler {
	const flow = metrics.IngestLaptop
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refuse := func(code int, reason string, a answer) {
			metrics.IngestRefused(flow, reason)
			if a.Error == "" {
				a.Error = http.StatusText(code)
			}
			reply(w, code, a)
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(reading)) // only a recorder (a test) has none
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				refuse(http.StatusRequestEntityTooLarge, "too_large", answer{})
			} else {
				refuse(http.StatusBadRequest, "unreadable", answer{})
			}
			return
		}
		_ = rc.SetReadDeadline(time.Time{})
		t, timestamp, signature := now(), r.Header.Values(TimestampHeader), r.Header.Values(SignatureHeader)
		if len(timestamp) != 1 || len(signature) != 1 || !Verify(key, LaptopSource, timestamp[0], body, signature[0]) {
			refuse(http.StatusUnauthorized, "bad_signature", answer{})
			return
		}
		if !fresh(timestamp[0], t) {
			slog.Warn("ingest: timestamp outside the window", "flow", flow)
			refuse(http.StatusUnauthorized, "skew", answer{Error: "timestamp: more than 5 minutes from the server's clock"})
			return
		}
		if !bucket.AllowN(t, 1) {
			slog.Warn("ingest: over the rate", "flow", flow)
			w.Header().Set("Retry-After", "6")
			refuse(http.StatusTooManyRequests, "rate", answer{})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), working)
		e, masked, err := Post(ctx, body, repos, t)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			slog.Warn("ingest: busy", "flow", flow)
			w.Header().Set("Retry-After", "2")
			refuse(http.StatusServiceUnavailable, "busy", answer{})
			return
		}
		if err != nil {
			slog.Warn("ingest: unusable body", "flow", flow, "err", err, "masked", masked) // Post's words: never the body's
			refuse(http.StatusBadRequest, "invalid_body", answer{Error: err.Error(), Masked: masked})
			return
		}
		e.Producer = event.Producer("route", flow)
		inserted, err := insert(r.Context(), e)
		if store.Invalid(err) {
			slog.Warn("ingest: store refused the event", "flow", flow)
			refuse(http.StatusBadRequest, "store_refused", answer{Masked: masked})
			return
		}
		if err != nil {
			slog.Error("ingest: store", "flow", flow, "err", err)
			refuse(http.StatusServiceUnavailable, "store_unavailable", answer{})
			return
		}
		metrics.Event(flow, e.Type)
		slog.Info("ingest: event", "type", e.Type, "subject", e.Subject, "masked", masked, "new", inserted)
		reply(w, http.StatusAccepted, answer{PostID: e.ID[strings.LastIndexByte(e.ID, '/')+1:], New: inserted, Masked: masked})
	})
}
