package main

import (
	"crypto/rsa"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
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
	"BRIDGE_RETENTION", "PORT", "BRIDGE_CLIENTS", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "BRIDGE_FORGEJO_WEBHOOK_SECRET",
	"BRIDGE_FORGEJO_TRUSTED_LOGINS", "BRIDGE_FORGEJO_AGENT_LOGINS", "BRIDGE_FORGEJO_RELIST_REPOS",
	"BRIDGE_FORGEJO_READER_TOKEN", "BRIDGE_FORGEJO_TOKEN_FILE", "BRIDGE_FORGEJO_URL", "BRIDGE_TAG_GRACE", "BRIDGE_CONTRACT_FILE",
	"BRIDGE_METRICS_ADDR", "BRIDGE_K8S_SA_KEY", "BRIDGE_K8S_JWKS_URL", "BRIDGE_INGEST_LAPTOP_SECRET",
	"BRIDGE_INGEST_LAPTOP_REPOS",
}

// Config is the bridge's whole configuration (mountain plan/15 §5): the environment, read once by load and checked
// before anything is built. What only a constructor can check stays with it: the client table (bus.ParseClients),
// the pinned certificate (auth.New), the pinned cluster key (auth.NewSA) and the database URL (store.Open).
type Config struct {
	WebhookSecret   string
	ForgejoSecret   string          // "": no /webhook/forgejo route
	LaptopSecret    string          // not a key (ingest.Key): no /ingest/laptop route
	LaptopRepos     map[string]bool // the repos a post may be about, as Forgejo names them; empty: none
	LegacyClients   bool            // BRIDGE_CLIENTS is set: ignored, with a warning (ADR-0066)
	APIClients      string
	OIDC            OIDCConfig
	K8s             K8sConfig
	DatabaseURL     string
	Trusted, Agents map[string]bool
	AlertToken      string // "": both alert endpoints answer 503
	Retention       time.Duration
	TagGrace        time.Duration // how long a System-filtered stream waits for an event's tag (bus.TagGrace)
	ContractFile    string        // "": no event contract, nothing is flagged
	Port            string
	MetricsAddr     string     // BRIDGE_METRICS_ADDR: where /metrics is served, apart from the public port
	Traces          string     // OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, the OTLP/HTTP traces URL in full; "" = no tracing
	App             *AppConfig // nil: the reconcile loop is off (no App id or no key, or a key that does not parse)

	// The Forgejo logins, apart from the GitHub ones: a name free on one forge
	// is anyone's to claim there (ADR-0082 §12).
	ForgejoTrusted, ForgejoAgents map[string]bool
	Relist                        *RelistConfig // nil: the Forgejo relist loop is off (no repos, or no token: env or file)

	// Warnings are the optional settings that were set and did not satisfy their rule, in the order they were
	// checked: each took its default (a retention or lookback default, no tracing, no reconcile loop), and main logs
	// each at WARN. load refuses a missing webhook secret and a metrics port equal to PORT; the settings only a constructor can check (the
	// client table, the pinned certificate, the database URL) still refuse in main, closed.
	Warnings []*configError
}

// OIDCConfig is how API clients sign in through authentik (ADR-0066).
type OIDCConfig struct{ Issuer, ClientID, Cert, JWKSURL string }

// K8sConfig is how pods sign in with projected service account tokens (plan M3): the pinned cluster key (PEM, ""
// turns it off) and the optional JWKS to compare it with.
type K8sConfig struct{ SAKey, JWKSURL string }

// RelistConfig is what the Forgejo relist loop reads.
type RelistConfig struct {
	URL       string   // Forgejo's base URL, default https://git.bnei.dev
	Token     string   // the read-only token from BRIDGE_FORGEJO_READER_TOKEN; wins over TokenFile
	TokenFile string   // a mounted file holding a read-only token (fallback)
	Repos     []string // owner/repo, sorted
}

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

// load reads the configuration from getenv. Its refusals are a missing webhook secret and a metrics port equal to PORT: the bridge cannot do its
// job without it (main still refuses what only a constructor can check: see Config). Every other setting is optional, and a value that does not satisfy its rule is a warning
// (Config.Warnings) and its default, in the order the settings are checked: the retention, the traces endpoint, the
// App's key, the lookback.
func load(getenv func(string) string) (Config, *configError) {
	c := Config{
		WebhookSecret: getenv("BRIDGE_GITHUB_WEBHOOK_SECRET"),
		ForgejoSecret: getenv("BRIDGE_FORGEJO_WEBHOOK_SECRET"),
		LaptopSecret:  getenv("BRIDGE_INGEST_LAPTOP_SECRET"),
		LegacyClients: getenv("BRIDGE_CLIENTS") != "",
		APIClients:    getenv("BRIDGE_API_CLIENTS"),
		OIDC: OIDCConfig{Issuer: getenv("BRIDGE_OIDC_ISSUER"), ClientID: getenv("BRIDGE_OIDC_CLIENT_ID"),
			Cert: getenv("BRIDGE_OIDC_CERT"), JWKSURL: getenv("BRIDGE_OIDC_JWKS_URL")},
		K8s:         K8sConfig{SAKey: getenv("BRIDGE_K8S_SA_KEY"), JWKSURL: getenv("BRIDGE_K8S_JWKS_URL")},
		DatabaseURL: getenv("BRIDGE_DATABASE_URL"),
		// Agents are never added to trusted: see github.Policy.
		Trusted:    set(getenv("BRIDGE_TRUSTED_LOGINS")),
		Agents:     set(getenv("BRIDGE_AGENT_LOGINS")),
		AlertToken: getenv("BRIDGE_ALERT_TOKEN"),
		Retention:  30 * 24 * time.Hour,
		TagGrace:   time.Minute,
		Port:       getenv("PORT"),

		ContractFile: getenv("BRIDGE_CONTRACT_FILE"),

		ForgejoTrusted: set(getenv("BRIDGE_FORGEJO_TRUSTED_LOGINS")),
		ForgejoAgents:  set(getenv("BRIDGE_FORGEJO_AGENT_LOGINS")),
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
	if v := getenv("BRIDGE_TAG_GRACE"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d <= 0 {
			c.warn("BRIDGE_TAG_GRACE must be a Go duration above 0; using the default", "value", v, "default", c.TagGrace.String())
		} else {
			c.TagGrace = d
		}
	}
	if c.Port == "" {
		c.Port = "8080"
	}
	if c.MetricsAddr = getenv("BRIDGE_METRICS_ADDR"); c.MetricsAddr == "" {
		c.MetricsAddr = ":9090"
	}
	if _, p, err := net.SplitHostPort(c.MetricsAddr); err != nil || p == "" {
		c.warn("BRIDGE_METRICS_ADDR is not host:port; using the default", "value", c.MetricsAddr)
		c.MetricsAddr = ":9090"
	}
	// Two listeners on one port: the second fails to bind, and no default can fix it.
	if _, p, _ := net.SplitHostPort(c.MetricsAddr); p == c.Port {
		return Config{}, &configError{msg: "BRIDGE_METRICS_ADDR uses the same port as PORT: /metrics must not be on the public port", args: []any{"port", p}}
	}
	if c.Traces = getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); c.Traces != "" {
		if u, err := url.Parse(c.Traces); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path == "" || u.Path == "/" {
			shown := "(not a URL)"
			switch {
			case strings.Contains(c.Traces, "@"): // any user:password form, parsed or not, scheme or not, is never logged
				shown = "<redacted: contains @>"
			case err == nil:
				shown = u.String()
			}
			c.warn("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not an http(s) URL with its traces path (…/v1/traces); tracing is off", "value", shown)
			c.Traces = ""
		}
	}
	// The check sends the pod's own API token: never in clear.
	if v := c.K8s.JWKSURL; v != "" {
		if u, err := url.Parse(v); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			c.warn("BRIDGE_K8S_JWKS_URL is not an https URL: it would send the pod's token in clear; the cluster key check is off")
			c.K8s.JWKSURL = ""
		}
	}
	c.LaptopRepos = map[string]bool{}
	for r := range set(getenv("BRIDGE_INGEST_LAPTOP_REPOS")) {
		if !repoName.MatchString(r) {
			c.warn("BRIDGE_INGEST_LAPTOP_REPOS: not owner/repo; skipped", "value", r)
			continue
		}
		c.LaptopRepos[r] = true
	}
	repos, token, tokenFile, forgejoURL := getenv("BRIDGE_FORGEJO_RELIST_REPOS"), strings.TrimSpace(getenv("BRIDGE_FORGEJO_READER_TOKEN")), getenv("BRIDGE_FORGEJO_TOKEN_FILE"), getenv("BRIDGE_FORGEJO_URL")
	if forgejoURL == "" {
		forgejoURL = "https://git.bnei.dev"
	}
	var watched []string
	for r := range set(repos) {
		if repoName.MatchString(r) {
			watched = append(watched, r)
		} else {
			c.warn("BRIDGE_FORGEJO_RELIST_REPOS: not owner/repo; skipped", "value", r)
		}
	}
	switch {
	case len(watched) == 0:
	case token == "" && tokenFile == "":
		c.warn("BRIDGE_FORGEJO_RELIST_REPOS is set without BRIDGE_FORGEJO_READER_TOKEN or BRIDGE_FORGEJO_TOKEN_FILE; the Forgejo relist loop is off")
	default:
		if !strings.HasPrefix(forgejoURL, "https://") {
			c.warn("BRIDGE_FORGEJO_URL is not https: the relist loop sends its token in clear", "value", forgejoURL)
		}
		slices.Sort(watched)
		c.Relist = &RelistConfig{URL: strings.TrimSuffix(forgejoURL, "/"), Token: token, TokenFile: tokenFile, Repos: watched}
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
		} else if d <= 0 {
			c.warn("BRIDGE_RECONCILE_LOOKBACK must be above 0; using the default", "value", v, "default", app.Lookback.String())
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

var repoName = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)

func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}
