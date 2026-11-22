// Package metrics is the bridge's Prometheus series (rule R2: a flow never
// fails silently). They live on the default registry; main serves it on
// BRIDGE_METRICS_ADDR, never on the public port. Label sets are bounded: the
// built-in flows below plus one per API client row.
package metrics

import (
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The built-in flows. An API client's flow is its row name.
const (
	ForgejoWebhook  = "forgejo-webhook"
	ForgejoRelist   = "forgejo-relist"
	GithubWebhook   = "github-webhook"
	GithubReconcile = "github-reconcile"
	Alertmanager    = "alertmanager"
	Grafana         = "grafana"
	OIDCJWKS        = "oidc-jwks" // the hourly JWKS check against the pinned certificate
)

var (
	flowEnabled = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "bridge_flow_enabled",
		Help: "1 if the flow is on, 0 if it is off (its setting is missing or unusable)."}, []string{"flow"})
	lastEvent = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "bridge_flow_last_event_timestamp",
		Help: "Unix seconds of the last event accepted on the flow."}, []string{"flow"})
	events = promauto.NewCounterVec(prometheus.CounterOpts{Name: "bridge_flow_events_total",
		Help: "Events accepted per flow and type prefix (the type up to its third dot)."}, []string{"flow", "type_prefix"})
	relistRuns = promauto.NewCounterVec(prometheus.CounterOpts{Name: "bridge_relist_runs_total",
		Help: "Forgejo relist runs by result (ok or error)."}, []string{"result"})
	// TagsWritten counts the tags the Tag RPC stored.
	TagsWritten = promauto.NewCounter(prometheus.CounterOpts{Name: "bridge_tags_written_total",
		Help: "Tags stored through the Tag RPC."})
)

// Builtin reports whether name is one of the built-in flows.
func Builtin(name string) bool {
	switch name {
	case ForgejoWebhook, ForgejoRelist, GithubWebhook, GithubReconcile, Alertmanager, Grafana, OIDCJWKS:
		return true
	}
	return false
}

// Enable sets the flow's gauge to 1.
func Enable(flow string) { flowEnabled.WithLabelValues(flow).Set(1) }

// SetEnabled sets the flow's gauge to 1 or 0, for a flow that can come back.
func SetEnabled(flow string, on bool) {
	v := 0.0
	if on {
		v = 1
	}
	flowEnabled.WithLabelValues(flow).Set(v)
}

// Disable sets the flow's gauge to 0 and logs one warning naming the missing setting.
func Disable(flow, setting string) {
	flowEnabled.WithLabelValues(flow).Set(0)
	slog.Warn("flow off: "+setting, "flow", flow)
}

// Event records one event accepted on the flow.
func Event(flow, typ string) {
	events.WithLabelValues(flow, Prefix(typ)).Inc()
	lastEvent.WithLabelValues(flow).SetToCurrentTime()
}

// EnabledFor is the enabled gauge of flow (tests).
func EnabledFor(flow string) prometheus.Gauge { return flowEnabled.WithLabelValues(flow) }

// EventsFor is the events_total child for flow and a type's prefix (tests).
func EventsFor(flow, typ string) prometheus.Counter { return events.WithLabelValues(flow, Prefix(typ)) }

// RelistRun records a relist run: ok or error.
func RelistRun(err error) {
	if err != nil {
		relistRuns.WithLabelValues("error").Inc()
		return
	}
	relistRuns.WithLabelValues("ok").Inc()
}

// Prefix is typ up to its third dot: dev.bnei.forge.pull_request.opened gives dev.bnei.forge.
func Prefix(typ string) string {
	p := strings.SplitN(typ, ".", 4)
	if len(p) < 4 {
		return typ
	}
	return strings.Join(p[:3], ".")
}
