package main

import (
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	good := map[string]string{
		"BRIDGE_URL":       "http://ukubi-bridge.ukubi-bridge.svc.cluster.local:8080",
		"BRIDGE_TOKEN_URL": "http://platform-authentik-server.authentik.svc.cluster.local/application/o/token/",
		"BRIDGE_PASSWORD":  "pw",
	}
	with := func(k, v string) func(string) string {
		return func(x string) string {
			if x == k {
				return v
			}
			return good[x]
		}
	}
	c, err := load(with("", ""))
	if err != nil || c.Username != "bridge-kwatch" || c.ClientID != "ukubi-bridge-api" || c.Settle != 30*time.Second ||
		c.SettleCap != 5*time.Minute || c.FlapWindow != 15*time.Minute || c.FlapCount != 3 || c.Port != "8080" {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, bad := range [][2]string{{"BRIDGE_PASSWORD", ""}, {"BRIDGE_PASSWORD", "<no value>"}, {"BRIDGE_URL", ""},
		{"BRIDGE_URL", "ukubi-bridge:8080"}, {"BRIDGE_TOKEN_URL", "tcp://x:1"}} {
		if _, err := load(with(bad[0], bad[1])); err == nil {
			t.Errorf("%s=%q is refused", bad[0], bad[1])
		}
	}
	// Unparsable, or out of order (settle past its cap).
	for _, kv := range [][2]string{{"KWATCH_SETTLE", "soon"}, {"KWATCH_SETTLE_CAP", "-1m"}, {"KWATCH_FLAP_COUNT", "1"},
		{"KWATCH_SETTLE", "6m"}, {"KWATCH_FLAP_WINDOW", "0s"}} {
		k, v := kv[0], kv[1]
		if c, err := load(with(k, v)); err != nil || c.Settle != 30*time.Second || c.SettleCap != 5*time.Minute ||
			c.FlapWindow != 15*time.Minute || c.FlapCount != 3 {
			t.Errorf("%s=%q takes its default: %+v %v", k, v, c, err)
		}
	}
	if c, _ := load(with("KWATCH_FLAP_WINDOW", "4m")); c.FlapWindow != 4*time.Minute {
		t.Errorf("a good value is kept: %v", c.FlapWindow)
	}
}
