package alert

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

// Trimmed real Alertmanager v4 webhook body.
const amFiring = `{"receiver":"bridge","status":"firing","alerts":[{"status":"firing",
"labels":{"alertname":"EtcdDown","namespace":"kube-system","severity":"critical"},
"annotations":{"summary":"etcd is down"},"startsAt":"2026-10-18T09:00:00.123Z","endsAt":"0001-01-01T00:00:00Z",
"generatorURL":"http://prometheus/graph?g0.expr=up==0","fingerprint":"abc123"}],
"groupLabels":{"alertname":"EtcdDown"},"commonLabels":{},"commonAnnotations":{},"externalURL":"http://alertmanager","version":"4","groupKey":"{}:{alertname=\"EtcdDown\"}","truncatedAlerts":0}`

// Same alert, now resolved: same fingerprint and startsAt, endsAt set.
var amResolved = strings.NewReplacer(`"status":"firing"`, `"status":"resolved"`, `"endsAt":"0001-01-01T00:00:00Z"`, `"endsAt":"2026-10-18T09:10:00Z"`).Replace(amFiring)

// Trimmed real Grafana unified-alerting webhook body, plus a malformed alert
// and one without a fingerprint, which are skipped without dropping the good one.
const grafanaFiring = `{"receiver":"bridge","status":"firing","orgId":1,"alerts":[["junk"],
{"status":"firing","labels":{"alertname":"monitoring-blind"}},
{"status":"firing","labels":{"alertname":"monitoring-blind","grafana_folder":"platform"},
"annotations":{"summary":"Prometheus is not scraping"},"startsAt":"2026-10-18T09:00:00Z","endsAt":"0001-01-01T00:00:00Z",
"generatorURL":"https://grafana.bnei.dev/alerting/grafana/x/view","fingerprint":"0f1e2d3c4b5a6978",
"silenceURL":"https://grafana.bnei.dev/alerting/silence/new","dashboardURL":"","panelURL":"","values":{"A":0}}],
"groupLabels":{},"commonLabels":{},"commonAnnotations":{},"externalURL":"https://grafana.bnei.dev/","version":"1","groupKey":"{}","truncatedAlerts":0,"title":"[FIRING:1]","state":"alerting","message":""}`

// fakeLog dedups on (source, ce_id) like the events table.
type fakeLog struct {
	rows []event.Event
	seen map[string]bool
	err  error
}

func (f *fakeLog) insert(_ context.Context, e event.Event) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	if f.seen[e.Source+"\x00"+e.ID] {
		return false, nil
	}
	f.seen[e.Source+"\x00"+e.ID] = true
	f.rows = append(f.rows, e)
	return true, nil
}

func post(h http.Handler, auth, body string) int {
	req := httptest.NewRequest(http.MethodPost, "/webhook/alertmanager", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestAlertmanagerFiringRepeatResolved(t *testing.T) {
	log := &fakeLog{}
	h := Handler("alertmanager", "tok", log.insert)
	for _, body := range []string{amFiring, amFiring, amResolved} { // second firing = repeat_interval resend
		if code := post(h, "Bearer tok", body); code != http.StatusAccepted {
			t.Fatalf("got %d, want 202", code)
		}
	}
	if len(log.rows) != 2 {
		t.Fatalf("got %d events, want 2 (repeat firing coalesced, resolved distinct): %+v", len(log.rows), log.rows)
	}
	f, r := log.rows[0], log.rows[1]
	if f.ID != "abc123:firing:2026-10-18T09:00:00.123Z" || f.Type != "dev.bnei.alert.firing" ||
		f.Subject != "alert/abc123" || f.Source != "alertmanager" || f.Actor != event.ActorMachine || f.Trusted {
		t.Errorf("firing envelope: %+v", f)
	}
	if r.Type != "dev.bnei.alert.resolved" || r.Subject != f.Subject || r.ID == f.ID {
		t.Errorf("resolved envelope: %+v", r)
	}
	if !strings.Contains(string(f.Data), "generatorURL") {
		t.Errorf("raw alert not kept: %s", f.Data)
	}
}

func TestGrafanaSkipsBadAlerts(t *testing.T) {
	log := &fakeLog{}
	if code := post(Handler("grafana", "tok", log.insert), "Bearer tok", grafanaFiring); code != http.StatusAccepted {
		t.Fatalf("got %d, want 202", code)
	}
	if len(log.rows) != 1 || log.rows[0].Source != "grafana" || log.rows[0].Subject != "alert/0f1e2d3c4b5a6978" {
		t.Fatalf("rows: %+v", log.rows)
	}
}

func TestAuth(t *testing.T) {
	log := &fakeLog{}
	h := Handler("alertmanager", "tok", log.insert)
	for _, auth := range []string{"", "Bearer ", "Bearer wrong", "tok", "Basic tok"} {
		if code := post(h, auth, amFiring); code != http.StatusUnauthorized {
			t.Errorf("auth %q: got %d, want 401", auth, code)
		}
	}
	// No token configured: closed, even to a caller sending an empty bearer.
	for _, tok := range []string{"", "  "} {
		if code := post(Handler("alertmanager", tok, log.insert), "Bearer "+tok, amFiring); code != http.StatusServiceUnavailable {
			t.Errorf("token %q: got %d, want 503", tok, code)
		}
	}
	if len(log.rows) != 0 {
		t.Fatalf("unauthenticated alert stored: %+v", log.rows)
	}
}

func TestStoreDownIs503(t *testing.T) {
	log := &fakeLog{err: errors.New("pg down")}
	if code := post(Handler("alertmanager", "tok", log.insert), "Bearer tok", amFiring); code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 so Alertmanager retries", code)
	}
}
