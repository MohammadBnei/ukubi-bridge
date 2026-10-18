// Package alert ingests Alertmanager and Grafana webhook notifications. Both
// send the same alerts[] shape (status, fingerprint, startsAt, labels); the
// parsing mirrors agent-fleet core's internal/alertwebhook.
package alert

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

// errSkip marks an alert that can't become an event (no dedup key, unknown status).
var errSkip = errors.New("alert skipped")

type alert struct {
	Status      string            `json:"status"`
	Fingerprint string            `json:"fingerprint"`
	StartsAt    string            `json:"startsAt"`
	Labels      map[string]string `json:"labels"`
}

// Normalize builds the bus event for one alert of a notification. The ce_id
// is fingerprint:status:startsAt, so Alertmanager's repeat_interval resends of
// the same firing coalesce into one event, while its resolution, or a later
// firing of the same alert, is a new one (ADR-0071 §6).
func Normalize(source string, raw json.RawMessage, now time.Time) (event.Event, error) {
	var a alert
	if err := json.Unmarshal(raw, &a); err != nil {
		return event.Event{}, err
	}
	if a.Status != "firing" && a.Status != "resolved" {
		return event.Event{}, errSkip
	}
	// Without both there is no stable dedup key and every resend would be a new event.
	if a.Fingerprint == "" || a.StartsAt == "" {
		return event.Event{}, errSkip
	}
	return event.Event{
		ID:      a.Fingerprint + ":" + a.Status + ":" + a.StartsAt,
		Source:  source,
		Type:    "dev.bnei.alert." + a.Status,
		Subject: "alert/" + a.Fingerprint,
		Time:    now,
		Data:    raw, // verbatim: every label, annotation and URL survives
		Actor:   event.ActorMachine,
		Trusted: false, // an alert never wakes a session on its own (ADR-0071 §6)
	}, nil
}

// Handler serves one sender. source is "alertmanager" or "grafana"; token is
// the shared bearer both send. insert is store.Insert.
func Handler(source, token string, insert func(context.Context, event.Event) (bool, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(token) == "" {
			// Fail closed: a missing token means alerts don't arrive, never
			// that anyone in-cluster can write to the bus.
			http.Error(w, "alert webhook disabled: no token configured", http.StatusServiceUnavailable)
			return
		}
		supplied, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var p struct {
			Alerts []json.RawMessage `json:"alerts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 5<<20)).Decode(&p); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		now := time.Now()
		for _, raw := range p.Alerts {
			e, err := Normalize(source, raw, now)
			if err != nil {
				// One bad alert must not drop the rest of the group.
				slog.Warn(source+": alert skipped", "err", err, "alert", string(raw))
				continue
			}
			inserted, err := insert(r.Context(), e)
			if err != nil {
				// 503: the sender retries the whole group; what already landed dedups.
				slog.Error(source+": store", "id", e.ID, "err", err)
				http.Error(w, "store unavailable", http.StatusServiceUnavailable)
				return
			}
			slog.Info(source+": event", "type", e.Type, "subject", e.Subject, "new", inserted)
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
