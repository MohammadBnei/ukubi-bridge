package main

import (
	"crypto/rsa"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/github"
)

// envVars is every variable load reads, in README.md's order: TestConfigDocumented holds the two to each other and
// to load's own reads. The libraries' reads (pgx's PG* defaults, net/http's proxy variables) are theirs.
var envVars = []string{
	"BRIDGE_DATABASE_URL", "BRIDGE_GITHUB_WEBHOOK_SECRET", "BRIDGE_TRUSTED_LOGINS", "BRIDGE_AGENT_LOGINS",
	"BRIDGE_API_CLIENTS", "BRIDGE_OIDC_ISSUER", "BRIDGE_OIDC_CLIENT_ID", "BRIDGE_OIDC_CERT", "BRIDGE_OIDC_JWKS_URL",
	"BRIDGE_GITHUB_APP_ID", "BRIDGE_GITHUB_APP_PRIVATE_KEY", "BRIDGE_RECONCILE_LOOKBACK", "BRIDGE_ALERT_TOKEN",
	"BRIDGE_RETENTION", "PORT", "BRIDGE_CLIENTS",
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
	App             *AppConfig // nil: the reconcile loop is off (no App id or no key)
}

// OIDCConfig is how API clients sign in through authentik (ADR-0066).
type OIDCConfig struct{ Issuer, ClientID, Cert, JWKSURL string }

// AppConfig is the GitHub App's credentials, for the reconcile loop.
type AppConfig struct {
	ID       string
	Key      *rsa.PrivateKey
	Lookback time.Duration
}

// configError is a refused setting, logged as its own line: msg and its attributes, as slog.Error takes them.
type configError struct {
	msg  string
	args []any
}

func (e *configError) Error() string { return e.msg }

// log writes the refusal's line.
func (e *configError) log() { slog.Error(e.msg, e.args...) }

// load reads the configuration from getenv. A refusal is the first problem, in the order the settings were checked
// before the Config existed: the webhook secret, the retention, the App's key, the lookback.
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
		var err error
		if c.Retention, err = time.ParseDuration(v); err != nil || c.Retention < 24*time.Hour {
			return Config{}, &configError{msg: "BRIDGE_RETENTION must be a Go duration of at least 24h", args: []any{"value", v}}
		}
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	appID, pemKey := getenv("BRIDGE_GITHUB_APP_ID"), getenv("BRIDGE_GITHUB_APP_PRIVATE_KEY")
	if appID == "" || pemKey == "" {
		return c, nil // the lookback is read only with the App's credentials
	}
	key, err := github.ParseKey(pemKey)
	if err != nil {
		return Config{}, &configError{msg: "BRIDGE_GITHUB_APP_PRIVATE_KEY", args: []any{"err", err}}
	}
	app := &AppConfig{ID: appID, Key: key, Lookback: 6 * time.Hour}
	if v := getenv("BRIDGE_RECONCILE_LOOKBACK"); v != "" {
		if app.Lookback, err = time.ParseDuration(v); err != nil {
			return Config{}, &configError{msg: "BRIDGE_RECONCILE_LOOKBACK", args: []any{"err", err}}
		}
	}
	c.App = app
	return c, nil
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
