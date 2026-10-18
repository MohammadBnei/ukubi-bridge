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

func set(csv string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}
