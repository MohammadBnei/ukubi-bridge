package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"dev.bnei.forge.pull_request.opened": "dev.bnei.forge",
		"dev.bnei.alert.firing":              "dev.bnei.alert",
		"dev.bnei.x":                         "dev.bnei.x",
	} {
		if got := Prefix(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestEventAndEnabled(t *testing.T) {
	Event("t-flow", "dev.bnei.k8s.pod.warning")
	Event("t-flow", "dev.bnei.k8s.pod.warning")
	if got := testutil.ToFloat64(events.WithLabelValues("t-flow", "dev.bnei.k8s")); got != 2 {
		t.Errorf("events_total %v, want 2", got)
	}
	if testutil.ToFloat64(lastEvent.WithLabelValues("t-flow")) == 0 {
		t.Error("last event timestamp unset")
	}
	Disable("t-flow", "X is unset")
	if testutil.ToFloat64(flowEnabled.WithLabelValues("t-flow")) != 0 {
		t.Error("Disable left the flow on")
	}
	Enable("t-flow")
	if testutil.ToFloat64(flowEnabled.WithLabelValues("t-flow")) != 1 {
		t.Error("Enable left the flow off")
	}
}
