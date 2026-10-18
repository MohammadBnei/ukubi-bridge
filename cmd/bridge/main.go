// Command bridge ingests webhooks into the ukubi event bus (infra-bootstrap ADR-0059).
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
	st, err := store.Open(ctx, os.Getenv("BRIDGE_DATABASE_URL"))
	if err != nil {
		slog.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	agents := set(os.Getenv("BRIDGE_AGENT_LOGINS"))
	trusted := set(os.Getenv("BRIDGE_TRUSTED_LOGINS"))
	for a := range agents {
		trusted[a] = true
	}
	policy := github.Policy{Trusted: trusted, Agents: agents}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("POST /webhook/github", githubHandler(st, policy, []byte(secret)))
	// Unset token: both answer 503 rather than serve open.
	alertToken := os.Getenv("BRIDGE_ALERT_TOKEN")
	mux.Handle("POST /webhook/alertmanager", alert.Handler("alertmanager", alertToken, st.Insert))
	mux.Handle("POST /webhook/grafana", alert.Handler("grafana", alertToken, st.Insert))

	if r := reconciler(st); r != nil {
		go r.Loop(ctx, 10*time.Minute)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	slog.Info("listening", "port", port)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

func githubHandler(st *store.Store, policy github.Policy, secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GitHub caps payloads at 25 MB.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 25<<20))
		if err != nil {
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
		if err != nil {
			// 503 so the delivery shows as failed; the reconcile loop redelivers it.
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
