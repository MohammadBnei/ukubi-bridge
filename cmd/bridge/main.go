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
	"strings"
	"syscall"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/alert"
	"github.com/MohammadBnei/ukubi-bridge/internal/auth"
	"github.com/MohammadBnei/ukubi-bridge/internal/bus"
	"github.com/MohammadBnei/ukubi-bridge/internal/github"
	"github.com/MohammadBnei/ukubi-bridge/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	secret := os.Getenv("BRIDGE_GITHUB_WEBHOOK_SECRET")
	if secret == "" {
		slog.Error("BRIDGE_GITHUB_WEBHOOK_SECRET is required")
		os.Exit(1)
	}
	// API clients are authentik service accounts (infra-bootstrap ADR-0066):
	// the table holds permissions, the pinned certificate is the trust anchor.
	if os.Getenv("BRIDGE_CLIENTS") != "" {
		slog.Warn("BRIDGE_CLIENTS is ignored: clients sign in through authentik (BRIDGE_API_CLIENTS)")
	}
	clients, err := bus.ParseClients(os.Getenv("BRIDGE_API_CLIENTS"))
	if err != nil {
		slog.Error("clients", "err", err)
		os.Exit(1)
	}
	tokens, err := auth.New(os.Getenv("BRIDGE_OIDC_ISSUER"), os.Getenv("BRIDGE_OIDC_CLIENT_ID"), os.Getenv("BRIDGE_OIDC_CERT"))
	if err != nil {
		slog.Error("oidc", "err", err)
		os.Exit(1)
	}
	if _, _, err := tokens.Verify(""); errors.Is(err, auth.ErrNoKey) {
		slog.Warn("no signing certificate pinned: the API refuses every call; webhooks still work")
	}
	st, err := store.Open(ctx, os.Getenv("BRIDGE_DATABASE_URL"))
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Agents are never added to trusted: see github.Policy.
	policy := github.Policy{Trusted: set(os.Getenv("BRIDGE_TRUSTED_LOGINS")), Agents: set(os.Getenv("BRIDGE_AGENT_LOGINS"))}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("POST /webhook/github", githubHandler(st, policy, []byte(secret)))
	mux.Handle(bus.New(st, clients, tokens).Handler())

	// Unset token: both answer 503 rather than serve open.
	alertToken := os.Getenv("BRIDGE_ALERT_TOKEN")
	mux.Handle("POST /webhook/alertmanager", alert.Handler("alertmanager", alertToken, st.Insert))
	mux.Handle("POST /webhook/grafana", alert.Handler("grafana", alertToken, st.Insert))

	if u := os.Getenv("BRIDGE_OIDC_JWKS_URL"); u != "" {
		go tokens.Watch(ctx, u, &http.Client{Timeout: 10 * time.Second}, time.Hour)
	}
	if r := reconciler(st); r != nil {
		go r.Loop(ctx, 10*time.Minute)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	// No WriteTimeout: Subscribe streams are long-lived. h2c so gRPC clients work
	// alongside Connect and gRPC-Web.
	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 10 * time.Second, Protocols: new(http.Protocols)}
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
			srv.Close()
		}
	}()
	slog.Info("listening", "port", port)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
	// ListenAndServe returns as soon as Shutdown starts; wait for in-flight
	// handlers before the deferred st.Close.
	<-shutdownDone
}

// maxBody caps a /webhook/github body (see githubHandler).
const maxBody = 2 << 20

func githubHandler(st *store.Store, policy github.Policy, secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The body is read before the HMAC can be checked, so this path lets
		// anyone make the pod allocate: keep the cap far under the 128Mi limit.
		// ponytail: 2 MB fits the subscribed events (PR, issue comment, review:
		// bodies cap at 65536 chars, ~800 KB worst case JSON-escaped); raise it
		// with the memory limit if a subscribed event ever outgrows it.
		if r.ContentLength > maxBody {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read body", http.StatusBadRequest)
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
			// GitHub never retries on its own: until the reconcile loop exists,
			// a manual redelivery from that log is the only recovery.
			slog.Error("github: store", "delivery", delivery, "err", err)
			http.Error(w, "store unavailable", http.StatusServiceUnavailable)
			return
		}
		slog.Info("github: event", "type", e.Type, "subject", e.Subject, "trusted", e.Trusted, "new", inserted)
		w.WriteHeader(http.StatusAccepted)
	})
}

// reconciler is nil, with a warning, when the App credentials are absent:
// ingest still works, lost deliveries just stay lost.
func reconciler(st *store.Store) *github.Reconciler {
	appID, pemKey := os.Getenv("BRIDGE_GITHUB_APP_ID"), os.Getenv("BRIDGE_GITHUB_APP_PRIVATE_KEY")
	if appID == "" || pemKey == "" {
		slog.Warn("github reconcile disabled: BRIDGE_GITHUB_APP_ID or BRIDGE_GITHUB_APP_PRIVATE_KEY unset")
		return nil
	}
	key, err := github.ParseKey(pemKey)
	if err != nil {
		slog.Error("BRIDGE_GITHUB_APP_PRIVATE_KEY", "err", err)
		os.Exit(1)
	}
	lookback := 6 * time.Hour
	if v := os.Getenv("BRIDGE_RECONCILE_LOOKBACK"); v != "" {
		if lookback, err = time.ParseDuration(v); err != nil {
			slog.Error("BRIDGE_RECONCILE_LOOKBACK", "err", err)
			os.Exit(1)
		}
	}
	return &github.Reconciler{API: "https://api.github.com", AppID: appID, Key: key, Lookback: lookback,
		Known: st.Known, Client: &http.Client{Timeout: 30 * time.Second}}
}

func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}
