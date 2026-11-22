// Command kwatch is the bridge's k8s watch adapter (conception §6, spike S4): it watches the ArgoCD Applications
// and the cluster's Warning events, and publishes deploy.health, deploy.synced, deploy.flapping and k8s.warning to
// the bridge as its API client bridge-kwatch. It holds no state worth keeping: after a restart every app's first
// sight is a baseline again, and atlas's own polls carry the levels.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

// argocdNamespace holds every Application (60 of 60) and is the only one watched: apps-in-any-namespace is off, so
// an Application elsewhere is reconciled by nothing, its status is whatever its creator wrote, and the contract has
// no subject or System tag for it (argocd/<app>, app:<app>). Turning apps-in-any-namespace on widens this, the
// grant and the contract together.
const argocdNamespace = "argocd"

const (
	warnEvery = 10 * time.Minute // how often one repeating Warning event is sent again
	warnGrace = 2 * time.Minute  // a Warning this much older than kwatch's start is still sent (the restart's gap)
	drainFor  = 10 * time.Second // what a SIGTERM leaves the queue to reach the bridge, within the pod's 30 s grace
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	cfg, err := fromProcess()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	b := newBridge(cfg)
	w := NewWatcher(cfg.Settle, cfg.SettleCap, cfg.FlapWindow, cfg.FlapCount)

	// KUBECONFIG for a run from a laptop; unset, the pod's own account.
	kc, err := clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	if err != nil {
		slog.Error("kube config", "err", err)
		os.Exit(1)
	}
	dyn, err := dynamic.NewForConfig(kc)
	if err != nil {
		slog.Error("kube client", "err", err)
		os.Exit(1)
	}
	cs, err := kubernetes.NewForConfig(kc)
	if err != nil {
		slog.Error("kube client", "err", err)
		os.Exit(1)
	}

	in := make(chan any, 256)
	apps := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dyn, 0, argocdNamespace, nil).
		ForResource(schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}).Informer()
	events := informers.NewSharedInformerFactoryWithOptions(cs, 0, informers.WithTweakListOptions(func(o *metav1.ListOptions) {
		o.FieldSelector = "type=Warning"
	})).Core().V1().Events().Informer()
	for _, inf := range []cache.SharedIndexInformer{apps, events} {
		if _, err := inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(o any) { in <- o },
			UpdateFunc: func(_, o any) { in <- o },
			DeleteFunc: func(o any) { in <- gone{o} },
		}); err != nil {
			slog.Error("informer", "err", err)
			os.Exit(1)
		}
		go inf.Run(ctx.Done())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) {
		if !apps.HasSynced() || !events.HasSynced() {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		rw.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Addr: ":" + cfg.Port, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("healthz", "err", err)
			stop()
		}
	}()

	// The publisher outlives the signal by drainFor: on SIGTERM, loop closes every run and sends every held Warning,
	// and the queue drains until it is empty or drainFor has passed (README "kwatch").
	q := make(chan Out, 1024)
	drain, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(drain, q); close(done) }()
	loop(ctx, w, &warnings{every: warnEvery, grace: warnGrace, since: time.Now(), sent: map[string]sent{}}, in, q)
	close(q)
	t := time.AfterFunc(drainFor, cancel)
	<-done
	t.Stop()
	cancel()
	if n := len(q); n > 0 {
		slog.Warn("shutdown: events not published", "dropped", n)
	}
	_ = srv.Shutdown(context.Background())
}

// gone wraps a deleted object.
type gone struct{ obj any }

// loop owns the watcher: every observation and every tick goes through it, so it needs no lock.
func loop(ctx context.Context, w *Watcher, ws *warnings, in <-chan any, q chan<- Out) {
	emit := func(outs ...Out) {
		for _, o := range outs {
			select {
			case q <- o:
			default:
				// ponytail: a bridge down long enough to fill 1024 events drops the newest; atlas polls the levels.
				slog.Warn("publish queue full: event dropped", "type", o.Type, "subject", o.Subject, "id", o.ID)
			}
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// A window (an every) ahead, every open run is settled (every held repeat due): the next start baselines
			// on what they ended at, so a run left open would be an edge never sent. A run that goes on changing
			// after the restart is a new one; its id is a resourceVersion, so an overlap dedups.
			now := time.Now()
			emit(w.Tick(now.Add(w.Window))...)
			emit(ws.tick(now.Add(ws.every))...)
			return
		case now := <-tick.C:
			emit(w.Tick(now)...)
			emit(ws.tick(now)...)
		case o := <-in:
			now := time.Now()
			switch o := o.(type) {
			case gone:
				d := o.obj
				if u, ok := d.(cache.DeletedFinalStateUnknown); ok {
					d = u.Obj
				}
				switch d := d.(type) {
				case *unstructured.Unstructured:
					w.Forget(d.GetName())
				case *corev1.Event:
					delete(ws.sent, string(d.UID))
				}
			case *unstructured.Unstructured:
				raw, err := o.MarshalJSON()
				var a App
				if err == nil {
					err = json.Unmarshal(raw, &a)
				}
				if err != nil {
					slog.Warn("application unreadable: skipped", "name", o.GetName(), "err", err)
					continue
				}
				if !valid(a) {
					slog.Warn("application status is not ArgoCD's shape: skipped", "name", a.Metadata.Name,
						"resourceVersion", a.Metadata.ResourceVersion)
					continue
				}
				h, s := States(a)
				emit(w.Observe(a.Metadata.Name, sigHealth, h, now)...)
				emit(w.Observe(a.Metadata.Name, sigSync, s, now)...)
			case *corev1.Event:
				if out, ok := ws.observe(o, now); ok {
					emit(out)
				}
			}
		}
	}
}

// bridge publishes as bridge-kwatch, an authentik service account, with a client_credentials grant (infra-bootstrap
// ADR-0066), as agent-fleet core's bridgeclient does.
type bridge struct {
	api    bridgev1connect.BridgeServiceClient
	src    oauth2.TokenSource
	signIn func() oauth2.TokenSource
}

func newBridge(cfg Config) *bridge {
	cc := clientcredentials.Config{
		ClientID:       cfg.ClientID,
		TokenURL:       cfg.TokenURL,
		EndpointParams: url.Values{"username": {cfg.Username}, "password": {cfg.Password}},
		AuthStyle:      oauth2.AuthStyleInParams,
	}
	tokenHTTP := &http.Client{Timeout: 15 * time.Second, Transport: hostRewrite{cfg.AuthHost, http.DefaultTransport}}
	b := &bridge{
		api: bridgev1connect.NewBridgeServiceClient(&http.Client{Timeout: 30 * time.Second}, cfg.BridgeURL),
		signIn: func() oauth2.TokenSource {
			return cc.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, tokenHTTP))
		},
	}
	b.src = b.signIn()
	return b
}

// hostRewrite sends the token request to authentik's in-cluster Service as its public host, so the token's issuer is
// the one the bridge pins.
type hostRewrite struct {
	host string
	base http.RoundTripper
}

func (h hostRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.host != "" {
		r = r.Clone(r.Context())
		r.Host = h.host
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	return h.base.RoundTrip(r)
}

func (b *bridge) publish(ctx context.Context, o Out) error {
	tok, err := b.src.Token()
	if err != nil {
		return err
	}
	data, err := json.Marshal(o.Data)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	e := &bridgev1.CloudEvent{Id: o.ID, Type: o.Type, Subject: o.Subject, Data: data}
	if !o.Time.IsZero() {
		e.Time = timestamppb.New(o.Time) // unset only when the object gave no time: the bridge stamps its own
	}
	req := connect.NewRequest(&bridgev1.PublishRequest{Event: e})
	req.Header().Set("Authorization", "Bearer "+tok.AccessToken)
	_, err = b.api.Publish(ctx, req)
	if connect.CodeOf(err) == connect.CodeUnauthenticated {
		b.src = b.signIn() // a rotated certificate or a revoked token: sign in afresh on the retry
	}
	return err
}

// run publishes the queue in order until it is closed and empty, or ctx ends. A refusal that a retry cannot change (a
// bad event, a type or subject the client table does not grant) is logged and dropped; anything else is retried,
// backing off to a minute. Retries are safe: the bridge dedups on (source, id) and every id is derived from the object.
func (b *bridge) run(ctx context.Context, q <-chan Out) {
	for o := range q {
		if ctx.Err() != nil {
			return
		}
		for delay := time.Second; ; delay = min(2*delay, time.Minute) {
			err := b.publish(ctx, o)
			if err == nil {
				break
			}
			if c := connect.CodeOf(err); c == connect.CodeInvalidArgument || c == connect.CodePermissionDenied {
				slog.Error("publish refused: event dropped", "type", o.Type, "subject", o.Subject, "id", o.ID, "err", err)
				break
			}
			slog.Warn("publish failed: retrying", "type", o.Type, "subject", o.Subject, "in", delay, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}
