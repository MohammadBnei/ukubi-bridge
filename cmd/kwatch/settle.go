package main

import (
	"slices"
	"sort"
	"time"
)

// State is one signal of one Application as the object shows it: its health, or its sync.
type State struct {
	Status    string
	Revisions []string  // sync only, and only while Synced: an OutOfSync app's target revisions are not an edge
	At        time.Time // when the object says it changed (never the watcher's clock); zero if it does not say
	RV        string    // the resourceVersion that showed it: the published id, so a retry or a restart dedups
	Phase     string    // sync only: the phase of the operation that synced these revisions; empty when none did
}

func (s State) same(o State) bool {
	return s.Status == o.Status && slices.Equal(s.Revisions, o.Revisions)
}

// Out is one event for the bridge, before the envelope.
type Out struct {
	ID, Type, Subject string
	Time              time.Time
	Data              map[string]any
}

const (
	sigHealth = "health"
	sigSync   = "sync"
)

type key struct{ app, signal string }

// run is a settle window still open: every transition since from, the last one showing to.
type run struct {
	from, to     State
	synced       *State    // sync only: the last Synced state the run showed, to among them
	deployed     bool      // sync only: a Synced in it came from a non-Synced one, or an operation synced it
	opened, last time.Time // the watcher's clock
}

// unhealthy is a health that counts toward flapping: a deploy's Progressing and its return to Healthy never do.
func unhealthy(status string) bool { return status == "Degraded" || status == "Missing" }

// Watcher turns observed Application states into settled edges (conception §6, spike S4, doubt cycle 3 M2).
//   - The first sight of an app's signal is its baseline, not an edge.
//   - Transitions per app and signal closer together than Window are one run; it emits once, from the first previous
//     to the last value, and a run that ends where it began (A -> B -> A) emits nothing.
//   - A run is closed after Cap even while it keeps changing, so an app flapping forever still emits.
//   - Flapping is independent of settling: it counts every health transition into Degraded or Missing as observed,
//     before any run absorbs it, per app in a sliding FlapWindow. The FlapN-th emits one deploy.flapping at once; the
//     next only after a whole FlapWindow with none (the episode over). Sync and Progressing/Healthy moves never
//     count, so an ordinary deploy (Healthy -> Progressing -> Healthy, Synced -> OutOfSync -> Synced) is no flap
//     however often it ships.
//   - Sync: a run emits deploy.synced when it arrives at Synced, or when it showed a Synced at revisions other than
//     the last ones known, even if it ends OutOfSync (the next commit or a drift landing within the window), and
//     only if that Synced was deployed: reached from OutOfSync, or synced by an operation. A revision-only move
//     with no operation (a shared source's commit that renders nothing new for this app) updates the revisions
//     known and emits nothing. previous_revisions are the last Synced revisions known, kept across runs.
//
// Not safe for concurrent use: one loop owns it. The clock is passed in, so the tests drive it.
type Watcher struct {
	Window, Cap, FlapWindow time.Duration
	FlapN                   int

	seen     map[key]State
	runs     map[key]*run
	flips    map[key][]time.Time
	flapping map[key]bool
	revs     map[key][]string // sync only: the last Synced revisions known (a baseline's, or the last edge's)
}

func NewWatcher(window, settleCap, flapWindow time.Duration, flapN int) *Watcher {
	return &Watcher{Window: window, Cap: settleCap, FlapWindow: flapWindow, FlapN: flapN,
		seen: map[key]State{}, runs: map[key]*run{}, flips: map[key][]time.Time{}, flapping: map[key]bool{},
		revs: map[key][]string{}}
}

// Observe records one signal's state as seen at now, and returns what it closed: a run that was already due, and a
// flapping event.
func (w *Watcher) Observe(app, signal string, s State, now time.Time) []Out {
	k := key{app, signal}
	out := w.flushIfDue(k, now)
	prev, ok := w.seen[k]
	w.seen[k] = s
	if !ok && s.Status == "Synced" {
		w.revs[k] = s.Revisions
	}
	if !ok || prev.same(s) {
		return out
	}
	r := w.runs[k]
	if r == nil {
		r = &run{from: prev, opened: now}
		w.runs[k] = r
	}
	r.to, r.last = s, now
	switch {
	case signal == sigHealth && unhealthy(s.Status):
		w.trim(k, now)
		w.flips[k] = append(w.flips[k], now)
		if n := len(w.flips[k]); n >= w.FlapN && !w.flapping[k] {
			w.flapping[k] = true
			out = append(out, Out{ID: "deploy.flapping/" + app + "/" + signal + "/" + s.RV, Type: "dev.bnei.deploy.flapping",
				Subject: "argocd/" + app, Time: s.At, Data: appData(app, map[string]any{
					"signal": signal, "transitions": n, "window": w.FlapWindow.String(), "current": s.Status})})
		}
	case signal == sigSync && s.Status == "Synced":
		r.synced = &s
		r.deployed = r.deployed || prev.Status != "Synced" || s.Phase != ""
	}
	return out
}

// Tick closes every run that is due and slides every flap window to now.
func (w *Watcher) Tick(now time.Time) []Out {
	var out []Out
	for _, k := range sortedKeys(w.runs) {
		out = append(out, w.flushIfDue(k, now)...)
	}
	for k := range w.flips {
		w.trim(k, now)
	}
	return out
}

// trim drops k's entries a FlapWindow or more before now, and its flapping mark once none is left. Re-arming at
// fewer than FlapN would not end an episode: an app entering Degraded every 6 minutes holds 2 or 3 in a 15-minute
// window, dips to 2 between entries, and would flap again at nearly every one.
func (w *Watcher) trim(k key, now time.Time) {
	if fs := recent(w.flips[k], now, w.FlapWindow); len(fs) > 0 {
		w.flips[k] = fs
		return
	}
	delete(w.flips, k)
	delete(w.flapping, k)
}

// Forget drops a deleted app: if it comes back, its first sight is a baseline again.
func (w *Watcher) Forget(app string) {
	for _, m := range []string{sigHealth, sigSync} {
		k := key{app, m}
		delete(w.seen, k)
		delete(w.runs, k)
		delete(w.flips, k)
		delete(w.flapping, k)
		delete(w.revs, k)
	}
}

// recent is fs without the times a window or more before now.
func recent(fs []time.Time, now time.Time, window time.Duration) []time.Time {
	i := 0
	for i < len(fs) && now.Sub(fs[i]) >= window {
		i++
	}
	return fs[i:]
}

func (w *Watcher) flushIfDue(k key, now time.Time) []Out {
	r := w.runs[k]
	settled := r != nil && now.Sub(r.last) >= w.Window
	if r == nil || (!settled && now.Sub(r.opened) < w.Cap) {
		return nil
	}
	delete(w.runs, k)
	return w.edge(k, r)
}

// edge is what a closed run emits, if anything.
func (w *Watcher) edge(k key, r *run) []Out {
	base := Out{Subject: "argocd/" + k.app}
	switch k.signal {
	case sigHealth:
		if r.from.same(r.to) {
			return nil // A -> B -> A: nothing happened
		}
		base.ID, base.Type, base.Time = "deploy.health/"+k.app+"/"+r.to.RV, "dev.bnei.deploy.health", r.to.At
		base.Data = appData(k.app, map[string]any{"health": r.to.Status, "previous": r.from.Status})
	case sigSync:
		if r.synced == nil {
			return nil // never Synced
		}
		s := *r.synced // r.to when the run ends Synced
		prev, known := w.revs[k]
		w.revs[k] = s.Revisions
		arrived := r.to.Status == "Synced" && r.from.Status != "Synced"
		if !r.deployed || (!arrived && known && slices.Equal(s.Revisions, prev)) {
			return nil // a revision-only move nothing deployed, or Synced only where it already was (A -> B -> A)
		}
		base.ID, base.Type, base.Time = "deploy.synced/"+k.app+"/"+s.RV, "dev.bnei.deploy.synced", s.At
		base.Data = appData(k.app, map[string]any{"sync": s.Status, "previous": r.from.Status,
			"previous_revisions": nonNil(prev), "phase": s.Phase})
		base.Data["refs"].(map[string]any)["revisions"] = nonNil(s.Revisions)
	}
	return []Out{base}
}

// appData is an Application event's data: its refs, the System hint atlas turns into the tag (decision 6: the bridge
// never resolves), and the event's own fields.
func appData(app string, fields map[string]any) map[string]any {
	fields["refs"] = map[string]any{"app": app}
	fields["hints"] = map[string]any{"system": "app:" + app}
	return fields
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sortedKeys[V any](m map[key]V) []key {
	ks := make([]key, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].app != ks[j].app {
			return ks[i].app < ks[j].app
		}
		return ks[i].signal < ks[j].signal
	})
	return ks
}
