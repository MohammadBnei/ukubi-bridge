package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// App is the part of an argoproj.io/v1alpha1 Application the watcher reads.
type App struct {
	Metadata struct {
		Namespace       string `json:"namespace"`
		Name            string `json:"name"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Status struct {
		Health struct {
			Status             string    `json:"status"`
			LastTransitionTime time.Time `json:"lastTransitionTime"`
		} `json:"health"`
		Sync struct {
			Status    string   `json:"status"`
			Revisions []string `json:"revisions"` // multi-source
			Revision  string   `json:"revision"`  // single source
		} `json:"sync"`
		ReconciledAt   time.Time `json:"reconciledAt"`
		OperationState struct {
			Phase      string    `json:"phase"`
			FinishedAt time.Time `json:"finishedAt"`
			SyncResult struct {
				Revisions []string `json:"revisions"`
				Revision  string   `json:"revision"`
			} `json:"syncResult"`
		} `json:"operationState"`
	} `json:"status"`
}

func revisions(multi []string, single string) []string {
	if len(multi) == 0 && single != "" {
		return []string{single}
	}
	return multi
}

// ArgoCD's controller writes an Application's status, but so can whoever may write the Application, and every field
// here reaches agents' context: one outside ArgoCD's own vocabulary drops the app (valid) or the field (phase).
var (
	healthStatuses = []string{"Healthy", "Progressing", "Degraded", "Suspended", "Missing", "Unknown"}
	syncStatuses   = []string{"Synced", "OutOfSync", "Unknown"}
	opPhases       = []string{"Running", "Terminating", "Failed", "Error", "Succeeded"}
	revRe          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`) // a git sha, a tag or a chart version
)

// valid says whether the app's status is ArgoCD's shape. A new app before its first reconcile is not, yet.
func valid(a App) bool {
	st := a.Status
	if !slices.Contains(healthStatuses, st.Health.Status) || !slices.Contains(syncStatuses, st.Sync.Status) {
		return false
	}
	for _, r := range revisions(st.Sync.Revisions, st.Sync.Revision) {
		if !revRe.MatchString(r) {
			return false
		}
	}
	return true
}

// States reads the app's two signals with the time the object gives each. Health carries its own
// lastTransitionTime. Sync has none: a sync operation's finishedAt when that operation synced these very revisions,
// otherwise reconciledAt, the reconcile that saw the state (an app often turns Synced at a new revision with no
// operation at all, when the new commit renders nothing different).
func States(a App) (health, sync State) {
	st := a.Status
	health = State{Status: st.Health.Status, At: st.Health.LastTransitionTime, RV: a.Metadata.ResourceVersion}
	if health.At.IsZero() {
		health.At = st.ReconciledAt
	}
	sync = State{Status: st.Sync.Status, At: st.ReconciledAt, RV: a.Metadata.ResourceVersion}
	if sync.Status == "Synced" {
		sync.Revisions = revisions(st.Sync.Revisions, st.Sync.Revision)
		op := st.OperationState
		if !op.FinishedAt.IsZero() && slices.Equal(revisions(op.SyncResult.Revisions, op.SyncResult.Revision), sync.Revisions) {
			sync.At = op.FinishedAt
			if slices.Contains(opPhases, op.Phase) {
				sync.Phase = op.Phase
			}
		}
	}
	return health, sync
}

// warnings publishes Kubernetes Warning events. Each Event object is an edge already: its id (uid and count) dedups a
// relist after a restart. An Event last observed more than Grace before Since (kwatch's start) is a baseline,
// recorded and not sent, so a restart does not replay the cluster's last hour; Grace covers the restart's own gap,
// whose Events the bridge dedups if they were sent before it. A repeating Event (its count climbing,
// CrashLoopBackOff say) is sent again at most once per every: a repeat within it is held back, and tick sends the
// latest one held once every has passed, so the last count always goes out.
type warnings struct {
	every, grace time.Duration
	since        time.Time
	sent         map[string]sent // by Event uid
}

type sent struct {
	at   time.Time // the watcher's clock; zero for a baseline
	id   string
	held *Out // the latest repeat within every, not sent yet
}

// Every field of a Warning but its message is free text too (core/v1 validates none of kind, reason or component),
// and the subject and the refs reach agents' context: a field that is not the shape Kubernetes itself writes drops
// the event (the subject's parts and the reason) or the field (the rest).
var (
	kindRe   = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	reasonRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	tokenRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:{}\[\]-]{0,252}$`) // fieldPath, component, apiVersion, uid
)

func token(v string) string {
	if tokenRe.MatchString(v) {
		return v
	}
	return ""
}

func (ws *warnings) observe(e *corev1.Event, now time.Time) (Out, bool) {
	count, when := e.Count, e.LastTimestamp.Time
	if e.Series != nil {
		count, when = max(count, e.Series.Count), e.Series.LastObservedTime.Time
	}
	for _, t := range []time.Time{e.EventTime.Time, e.FirstTimestamp.Time, e.CreationTimestamp.Time} {
		if when.IsZero() {
			when = t
		}
	}
	uid := string(e.UID)
	id := "k8s.warning/" + uid + "/" + strconv.Itoa(int(count))
	p, ok := ws.sent[uid]
	if ok && (p.id == id || (p.held != nil && p.held.ID == id)) {
		return Out{}, false
	}
	if !ok && !ws.since.IsZero() && when.Before(ws.since.Add(-ws.grace)) {
		ws.sent[uid] = sent{id: id}
		return Out{}, false
	}
	o := e.InvolvedObject
	ns := o.Namespace
	if ns == "" {
		ns = "_" // cluster-scoped (a Node): never a namespace name
	} else if len(validation.IsDNS1123Label(ns)) > 0 {
		return ws.refuse(e, id, "namespace")
	}
	if !kindRe.MatchString(o.Kind) {
		return ws.refuse(e, id, "kind")
	}
	if len(validation.IsDNS1123Subdomain(o.Name)) > 0 {
		return ws.refuse(e, id, "name")
	}
	if !reasonRe.MatchString(e.Reason) {
		return ws.refuse(e, id, "reason")
	}
	component := e.ReportingController
	if component == "" {
		component = e.Source.Component
	}
	// The message is free text a workload or a controller wrote: only its hash rides the bus (contract v0), so the
	// reason and the object are what a reader branches on.
	sum := sha256.Sum256([]byte(e.Message))
	out := Out{ID: id, Type: "dev.bnei.k8s.warning", Subject: "k8s/" + ns + "/" + o.Kind + "/" + o.Name, Time: when,
		Data: map[string]any{
			"refs": map[string]any{"ns": o.Namespace, "kind": o.Kind, "name": o.Name, "uid": token(string(o.UID)),
				"api_version": token(o.APIVersion), "field_path": token(o.FieldPath), "reason": e.Reason},
			"message_hash": hex.EncodeToString(sum[:]), "count": count, "component": token(component),
		}}
	if ok && now.Sub(p.at) < ws.every {
		p.held = &out
		ws.sent[uid] = p
		return Out{}, false
	}
	ws.sent[uid] = sent{at: now, id: id}
	return out, true
}

// refuse drops an Event whose subject or reason is not a shape Kubernetes writes, logged once per uid and count.
func (ws *warnings) refuse(e *corev1.Event, id, field string) (Out, bool) {
	slog.Warn("warning event refused: a field is not the shape Kubernetes writes", "uid", e.UID, "field", field)
	ws.sent[string(e.UID)] = sent{id: id}
	return Out{}, false
}

// tick sends every repeat held back for its every.
func (ws *warnings) tick(now time.Time) []Out {
	var out []Out
	for _, uid := range slices.Sorted(maps.Keys(ws.sent)) {
		if p := ws.sent[uid]; p.held != nil && now.Sub(p.at) >= ws.every {
			out = append(out, *p.held)
			ws.sent[uid] = sent{at: now, id: p.held.ID}
		}
	}
	return out
}
