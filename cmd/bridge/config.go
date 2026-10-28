package main

import (
	"crypto/rsa"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/github"
)

// envVars is every variable load reads: TestConfigDocumented holds it, load's own reads and README.md's table to the
// same set. The libraries' reads (pgx's PG* defaults, net/http's proxy variables) are theirs.
var envVars = []string{
	"BRIDGE_DATABASE_URL", "BRIDGE_GITHUB_WEBHOOK_SECRET", "BRIDGE_TRUSTED_LOGINS", "BRIDGE_AGENT_LOGINS",
	"BRIDGE_API_CLIENTS", "BRIDGE_OIDC_ISSUER", "BRIDGE_OIDC_CLIENT_ID", "BRIDGE_OIDC_CERT", "BRIDGE_OIDC_JWKS_URL",
	"BRIDGE_GITHUB_APP_ID", "BRIDGE_GITHUB_APP_PRIVATE_KEY", "BRIDGE_RECONCILE_LOOKBACK", "BRIDGE_ALERT_TOKEN",
	"BRIDGE_RETENTION", "PORT", "BRIDGE_CLIENTS", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
}

// Config is the bridge's whole configuration (mountain plan/15 §5): the environment, read once by load and checked
// before anything is built. What only a constructor can check stays with it: the client table (bus.ParseClients),
// the pinned certificate (auth.New) and the database URL (store.Open).
type Config struct {
	WebhookSecret   string
	LegacyClients   bool // BRIDGE_CLIENTS is set: ignored, with a warning (ADR-0066)
	APIClients      string
	OIDC            OIDCConfig
	DatabaseURL     string
	Trusted, Agents map[string]bool
	AlertToken      string // "": both alert endpoints answer 503
	Retention       time.Duration
	Port            string
	Traces          string     // OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, the OTLP/HTTP traces URL in full; "" = no tracing
	App             *AppConfig // nil: the reconcile loop is off (no App id or no key, or a key that does not parse)
	// Warnings are the optional settings that were set and did not satisfy their rule, in the order they were
	// checked: each took its default (a retention or lookback default, no tracing, no reconcile loop), and main logs
	// each at WARN. Only a missing required setting refuses the start (the webhook secret).
	Warnings []*configError
}

// OIDCConfig is how API clients sign in through authentik (ADR-0066).
type OIDCConfig struct{ Issuer, ClientID, Cert, JWKSURL string }

// AppConfig is the GitHub App's credentials, for the reconcile loop.
type AppConfig struct {
	ID       string
	Key      *rsa.PrivateKey
	Lookback time.Duration
}

// configError is a setting's problem, logged as its own line: msg and its attributes, as slog takes them. A refusal
// is logged at ERROR, a warning (Config.Warnings) at WARN.
type configError struct {
	msg  string
	args []any
}

func (e *configError) Error() string { return e.msg }

// log writes the refusal's line.
func (e *configError) log() { slog.Error(e.msg, e.args...) }

// warn writes the warning's line.
func (e *configError) warn() { slog.Warn(e.msg, e.args...) }

// load reads the configuration from getenv. The one refusal is a missing webhook secret: the bridge cannot do its
// job without it. Every other setting is optional, and a value that does not satisfy its rule is a warning
// (Config.Warnings) and its default, in the order the settings are checked: the retention, the traces endpoint, the
// App's key, the lookback.
func load(getenv func(string) string) (Config, *configError) {
	c := Config{
		WebhookSecret: getenv("BRIDGE_GITHUB_WEBHOOK_SECRET"),
		LegacyClients: getenv("BRIDGE_CLIENTS") != "",
		APIClients:    getenv("BRIDGE_API_CLIENTS"),
		OIDC: OIDCConfig{Issuer: getenv("BRIDGE_OIDC_ISSUER"), ClientID: getenv("BRIDGE_OIDC_CLIENT_ID"),
			Cert: getenv("BRIDGE_OIDC_CERT"), JWKSURL: getenv("BRIDGE_OIDC_JWKS_URL")},
		DatabaseURL: getenv("BRIDGE_DATABASE_URL"),
		// Agents are never added to trusted: see github.Policy.
		Trusted:    set(getenv("BRIDGE_TRUSTED_LOGINS")),
		Agents:     set(getenv("BRIDGE_AGENT_LOGINS")),
		AlertToken: getenv("BRIDGE_ALERT_TOKEN"),
		Retention:  30 * 24 * time.Hour,
		Port:       getenv("PORT"),
	}
	if c.WebhookSecret == "" {
		return Config{}, &configError{msg: "BRIDGE_GITHUB_WEBHOOK_SECRET is required"}
	}
	if v := getenv("BRIDGE_RETENTION"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d < 24*time.Hour {
			c.warn("BRIDGE_RETENTION must be a Go duration of at least 24h; using the default", "value", v, "default", c.Retention.String())
		} else {
			c.Retention = d
		}
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	if c.Traces = getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); c.Traces != "" {
		if u, err := url.Parse(c.Traces); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path == "" || u.Path == "/" {
			shown := "(not a URL)"
			if err == nil {
				shown = u.Redacted() // a user:pass in it is never logged
			}
			c.warn("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not an http(s) URL with its traces path (…/v1/traces); tracing is off", "value", shown)
			c.Traces = ""
		}
	}
	appID, pemKey := getenv("BRIDGE_GITHUB_APP_ID"), getenv("BRIDGE_GITHUB_APP_PRIVATE_KEY")
	if appID == "" || pemKey == "" {
		return c, nil // the lookback is read only with the App's credentials
	}
	key, err := github.ParseKey(pemKey)
	if err != nil {
		c.warn("BRIDGE_GITHUB_APP_PRIVATE_KEY does not parse; the reconcile loop is off", "err", err)
		return c, nil
	}
	app := &AppConfig{ID: appID, Key: key, Lookback: 6 * time.Hour}
	if v := getenv("BRIDGE_RECONCILE_LOOKBACK"); v != "" {
		if d, err := time.ParseDuration(v); err != nil {
			c.warn("BRIDGE_RECONCILE_LOOKBACK is not a Go duration; using the default", "err", err, "default", app.Lookback.String())
		} else {
			app.Lookback = d
		}
	}
	c.App = app
	return c, nil
}

// warn records an optional setting's problem; the caller keeps the default.
func (c *Config) warn(msg string, args ...any) {
	c.Warnings = append(c.Warnings, &configError{msg: msg, args: args})
}

// fromProcess is the process's configuration: the one place that reads its environment.
func fromProcess() (Config, *configError) { return load(os.Getenv) }

func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}
