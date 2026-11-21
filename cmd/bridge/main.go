// Command bridge ingests webhooks into the ukubi event bus and serves its
// BridgeService API (infra-bootstrap ADR-0060).
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/MohammadBnei/ukubi-go/telemetry"

	"github.com/MohammadBnei/ukubi-bridge/internal/alert"
	"github.com/MohammadBnei/ukubi-bridge/internal/auth"
	"github.com/MohammadBnei/ukubi-bridge/internal/bus"
	"github.com/MohammadBnei/ukubi-bridge/internal/forgejo"
	"github.com/MohammadBnei/ukubi-bridge/internal/github"
	"github.com/MohammadBnei/ukubi-bridge/internal/store"
)

func main() {
	// JSON on stdout (mountain plan/15 §7): Loki's detected_level reads the level field; the chart's two alerts match
	// the words, which JSON leaves as they are (TestAlertLines).
	slog.SetDefault(newLogger(os.Stdout))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	cfg, cerr := fromProcess()
	if cerr != nil {
		cerr.log()
		os.Exit(1)
	}
	for _, w := range cfg.Warnings {
		w.warn()
	}
	// API clients are authentik service accounts (infra-bootstrap ADR-0066):
	// the table holds permissions, the pinned certificate is the trust anchor.
	if cfg.LegacyClients {
		slog.Warn("BRIDGE_CLIENTS is ignored: clients sign in through authentik (BRIDGE_API_CLIENTS)")
	}
	clients, err := bus.ParseClients(cfg.APIClients)
	if err != nil {
		slog.Error("clients", "err", err)
		os.Exit(1)
	}
	tokens, err := auth.New(cfg.OIDC.Issuer, cfg.OIDC.ClientID, cfg.OIDC.Cert)
	if err != nil {
		slog.Error("oidc", "err", err)
		os.Exit(1)
	}
	if !tokens.Pinned() {
		slog.Warn("no signing certificate pinned: the API refuses every call; webhooks still work")
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	policy := github.Policy{Trusted: cfg.Trusted, Agents: cfg.Agents}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	tel, err := telemetry.New(cfg.Traces, "ukubi-bridge")
	if err != nil {
		slog.Error("traces", "err", err)
		os.Exit(1)
	}
	route := func(pattern string, h http.Handler) { mux.Handle(pattern, tel.Handler(pattern, h)) }
	route("POST /webhook/github", githubHandler(st, policy, []byte(cfg.WebhookSecret)))
	forgejoRoute(route, st, cfg)
	api := bus.New(st, clients, tokens)
	mux.Handle(api.Handler(tel.Interceptors()...))

	// Unset token: both answer 503 rather than serve open.
	route("POST /webhook/alertmanager", alert.Handler("alertmanager", cfg.AlertToken, st.Insert))
	route("POST /webhook/grafana", alert.Handler("grafana", cfg.AlertToken, st.Insert))

	if cfg.OIDC.JWKSURL != "" {
		go tokens.Watch(ctx, cfg.OIDC.JWKSURL, &http.Client{Timeout: 10 * time.Second}, time.Hour)
	}
	go retain(ctx, api, st, cfg.Retention, time.Hour)

	if r := reconciler(st, cfg.App); r != nil {
		go r.Loop(ctx, 10*time.Minute)
	}

	port := cfg.Port
	// No WriteTimeout: Subscribe streams are long-lived. h2c so gRPC clients work
	// alongside Connect and gRPC-Web.
	inflight := &handlers{h: mux}
	srv := &http.Server{Addr: ":" + port, Handler: inflight, ReadHeaderTimeout: 10 * time.Second, Protocols: new(http.Protocols),
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelError)} // net/http's own lines (a panic, an Accept error): ERROR
	srv.Protocols.SetHTTP1(true)
	srv.Protocols.SetUnencryptedHTTP2(true)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Subscribe streams never go idle, so Shutdown times out on them; Close
		// cancels their contexts, or st.Close would wait on their connections.
		if srv.Shutdown(shutdown) != nil {
			_ = srv.Close()
		}
	}()
	slog.Info("listening", "port", port)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
	// ListenAndServe returns as soon as Shutdown starts; wait for in-flight
	// handlers before the deferred st.Close, and before tel.Shutdown: Close does
	// not wait for them, and a span that ends after Shutdown is dropped.
	<-shutdownDone
	if !inflight.wait(5 * time.Second) {
		slog.Warn("handlers still running at exit")
	}
	if err := tel.Shutdown(); err != nil {
		slog.Warn("traces", "err", err)
	}
}

// handlers counts the requests in flight, so main can wait for them after srv.Close, which does not.
type handlers struct {
	h http.Handler
	n atomic.Int64
}

func (h *handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.n.Add(1)
	defer h.n.Add(-1)
	h.h.ServeHTTP(w, r)
}

// wait waits until no request is in flight, at most d: false if some still were.
func (h *handlers) wait(d time.Duration) bool {
	for end := time.Now().Add(d); h.n.Load() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			return false
		}
	}
	return true
}

// maxBody caps a webhook body (see readBody).
const maxBody = 2 << 20

// readBody reads a webhook body under maxBody, or answers 413 or 400 and
// returns false. The body is read before the HMAC can be checked, so a webhook
// path lets anyone make the pod allocate: keep the cap far under the 128Mi
// limit. ponytail: 2 MB fits GitHub's subscribed events (PR, issue comment,
// review: bodies cap at 65536 chars, ~800 KB worst case JSON-escaped). It is
// not measured for Forgejo, whose body limit is not known here: an action_run
// delivery embeds the triggering event twice (run and last_run event_payload,
// each a JSON string escaped again), so a huge or escape-heavy PR body can
// push a run past the cap. That is a logged 413, and the event is lost, since
// Forgejo never retries. Raise the cap with the memory limit if the log shows it.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	tooLarge := func() ([]byte, bool) {
		slog.Warn("webhook body over the cap: refused, 413", "path", r.URL.Path, "max", maxBody)
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	if r.ContentLength > maxBody {
		return tooLarge()
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return tooLarge()
		}
		http.Error(w, "read body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func githubHandler(st *store.Store, policy github.Policy, secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		if !github.Verify(secret, body, r.Header.Get("X-Hub-Signature-256")) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		kind, delivery := r.Header.Get("X-GitHub-Event"), r.Header.Get("X-GitHub-Delivery")
		e, err := github.Normalize(policy, kind, delivery, body, time.Now())
		if errors.Is(err, github.ErrIgnored) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			slog.Warn("github: unusable delivery", "event", kind, "delivery", delivery, "err", err)
			http.Error(w, "unusable payload", http.StatusBadRequest)
			return
		}
		inserted, err := st.Insert(r.Context(), e)
		if store.Invalid(err) {
			slog.Warn("github: store refused delivery", "event", kind, "delivery", delivery, "err", err)
			http.Error(w, "unusable payload", http.StatusBadRequest)
			return
		}
		if err != nil {
			// 503 so the delivery shows as failed in the App's delivery log.
			// GitHub never retries on its own: the reconcile loop redelivers it
			// within BRIDGE_RECONCILE_LOOKBACK. With reconcile off (no App
			// credentials) or past that window, a manual redelivery from that log
			// is the only recovery, and GitHub keeps deliveries for 3 days only:
			// past that, nothing redelivers it.
			slog.Error("github: store", "delivery", delivery, "err", err)
			http.Error(w, "store unavailable", http.StatusServiceUnavailable)
			return
		}
		slog.Info("github: event", "type", e.Type, "subject", e.Subject, "actorTrusted", e.ActorTrusted, "threadOwned", e.ThreadOwned, "new", inserted)
		w.WriteHeader(http.StatusAccepted)
	})
}

// forgejoRoute adds POST /webhook/forgejo when its secret is set. Unset: no
// route (404), so an unsigned Forgejo delivery is never read. Its policy holds
// the Forgejo logins only, never the GitHub ones.
func forgejoRoute(route func(string, http.Handler), st *store.Store, cfg Config) {
	if cfg.ForgejoSecret == "" {
		slog.Warn("forgejo webhook off: BRIDGE_FORGEJO_WEBHOOK_SECRET is unset")
		return
	}
	policy := github.Policy{Trusted: cfg.ForgejoTrusted, Agents: cfg.ForgejoAgents}
	route("POST /webhook/forgejo", forgejoHandler(st, policy, []byte(cfg.ForgejoSecret)))
}

// forgejoHandler is githubHandler for Forgejo's webhook (content type
// application/json).
func forgejoHandler(st *store.Store, policy github.Policy, secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		if !forgejo.Verify(secret, body, r.Header.Get("X-Forgejo-Signature")) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		kind, delivery := r.Header.Get("X-Forgejo-Event-Type"), r.Header.Get("X-Forgejo-Delivery")
		e, err := forgejo.Normalize(policy, kind, delivery, body, time.Now())
		if errors.Is(err, forgejo.ErrIgnored) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err != nil {
			slog.Warn("forgejo: unusable delivery", "event", kind, "delivery", delivery, "err", err)
			http.Error(w, "unusable payload", http.StatusBadRequest)
			return
		}
		inserted, err := st.Insert(r.Context(), e)
		if store.Invalid(err) {
			slog.Warn("forgejo: store refused delivery", "event", kind, "delivery", delivery, "err", err)
			http.Error(w, "unusable payload", http.StatusBadRequest)
			return
		}
		if err != nil {
			// 503 marks the delivery failed in the webhook's recent deliveries.
			// Forgejo does not retry on its own and keeps no deliveries API, so
			// nothing redelivers it: a manual redelivery from that list is the
			// only recovery until a reconcile loop exists.
			slog.Error("forgejo: store", "delivery", delivery, "err", err)
			http.Error(w, "store unavailable", http.StatusServiceUnavailable)
			return
		}
		slog.Info("forgejo: event", "type", e.Type, "subject", e.Subject, "actorTrusted", e.ActorTrusted, "threadOwned", e.ThreadOwned, "new", inserted)
		w.WriteHeader(http.StatusAccepted)
	})
}

// retain deletes events older than keep every interval (infra-bootstrap
// ADR-0066 §6), then logs each parked subject left uncleared for 3 days: one
// line per subscription and subject, which the chart's LogQL rule alerts on.
// A run that fails either step logs one "retention failed" line, which has its
// own rule.
func retain(ctx context.Context, api *bus.Server, st *store.Store, keep, every time.Duration) {
	for {
		p, perr := api.Prune(ctx, time.Now().Add(-keep))
		if perr == nil && p.Through > 0 {
			slog.Info("retention", "through", p.Through, "deleted", p.Deleted, "moved", len(p.Moved), "gapped", p.Gapped)
		}
		// Whatever the run did: a failing run must not silence this alert.
		stale, serr := st.StaleDeadLetters(ctx, 72*time.Hour)
		if err := errors.Join(perr, serr); err != nil && ctx.Err() == nil {
			slog.Error("retention failed", "err", err) // one line per run: the failing rule counts runs
		}
		for _, d := range stale {
			slog.Warn("dead letter uncleared", "subscription", d.Subscription, "subject", d.Subject, "count", d.Count, "since", d.Since)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// reconciler is nil, with a warning, when the App credentials are absent or
// unusable (a key that does not parse is warned about by load first): ingest
// still works, lost deliveries just stay lost.
func reconciler(st *store.Store, app *AppConfig) *github.Reconciler {
	if app == nil {
		slog.Warn("github reconcile disabled: no usable GitHub App credentials (BRIDGE_GITHUB_APP_ID and BRIDGE_GITHUB_APP_PRIVATE_KEY)")
		return nil
	}
	return &github.Reconciler{API: "https://api.github.com", AppID: app.ID, Key: app.Key, Lookback: app.Lookback,
		Known: st.Known, Client: &http.Client{Timeout: 30 * time.Second}}
}

// newLogger is the bridge's log: one JSON object per line (time, level, msg, attributes) on w.
func newLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(w, nil)) }
