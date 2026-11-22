package main

import (
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Config is kwatch's whole environment, read once here (plan/15 §5: one Config per binary). README "kwatch".
type Config struct {
	BridgeURL, TokenURL, AuthHost, ClientID, Username, Password string
	Kubeconfig, Port                                            string
	Settle, SettleCap, FlapWindow                               time.Duration
	FlapCount                                                   int
}

func fromProcess() (Config, error) { return load(os.Getenv) }

// load refuses a missing or malformed bridge setting. A tuning value that is set and does not parse is logged at
// WARN and takes its default, as the bridge's optional settings do.
func load(getenv func(string) string) (Config, error) {
	str := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	dur := func(k string, def time.Duration) time.Duration {
		v := getenv(k)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			slog.Warn("setting ignored: not a positive Go duration", "var", k, "value", v, "default", def)
			return def
		}
		return d
	}
	c := Config{
		BridgeURL: getenv("BRIDGE_URL"), TokenURL: getenv("BRIDGE_TOKEN_URL"), AuthHost: getenv("BRIDGE_AUTH_HOST"),
		ClientID: str("BRIDGE_CLIENT_ID", "ukubi-bridge-api"), Username: str("BRIDGE_USERNAME", "bridge-kwatch"),
		Password:   getenv("BRIDGE_PASSWORD"),
		Kubeconfig: getenv("KUBECONFIG"), Port: str("PORT", "8080"),
		Settle: dur("KWATCH_SETTLE", 30*time.Second), SettleCap: dur("KWATCH_SETTLE_CAP", 5*time.Minute),
		FlapWindow: dur("KWATCH_FLAP_WINDOW", 15*time.Minute), FlapCount: 3,
	}
	// A settle at or past its cap closes every run by the cap. The flap window counts raw transitions, apart from both.
	if c.Settle >= c.SettleCap {
		slog.Warn("settings ignored: KWATCH_SETTLE < KWATCH_SETTLE_CAP does not hold", "settle", c.Settle, "cap", c.SettleCap)
		c.Settle, c.SettleCap = 30*time.Second, 5*time.Minute
	}
	if v := getenv("KWATCH_FLAP_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 2 {
			c.FlapCount = n
		} else {
			slog.Warn("setting ignored: not an integer of at least 2", "var", "KWATCH_FLAP_COUNT", "value", v, "default", c.FlapCount)
		}
	}
	// An Infisical key that does not exist renders as the literal "<no value>" (infra-bootstrap ADR-0049).
	if c.BridgeURL == "" || c.TokenURL == "" || c.Password == "" || c.Password == "<no value>" {
		return c, errors.New("BRIDGE_URL, BRIDGE_TOKEN_URL and BRIDGE_PASSWORD are required")
	}
	for _, s := range []string{c.BridgeURL, c.TokenURL} {
		if p, err := url.Parse(s); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return c, errors.New("BRIDGE_URL and BRIDGE_TOKEN_URL must be http(s) URLs")
		}
	}
	return c, nil
}
