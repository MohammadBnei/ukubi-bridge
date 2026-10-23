// Package bus serves the BridgeService API (infra-bootstrap ADR-0060 §2, §4):
// Publish, head-of-line Subscribe with Ack/Nack, and Replay.
package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
	"github.com/MohammadBnei/ukubi-bridge/internal/store"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

// Tunables; tests shrink them.
var (
	MaxAttempts = 5                // Nacks before an event is dead-lettered
	RetryBase   = time.Second      // backoff after Nack n is RetryBase << (n-1)
	PollEvery   = 30 * time.Second // fallback when a NOTIFY is missed
)

// Client is one BRIDGE_API_CLIENTS entry, keyed by its authentik username
// (infra-bootstrap ADR-0066 §1). It holds permissions only, no secret.
type Client struct {
	Name         string   `json:"-"`
	Kind         string   `json:"kind"`          // actor stamped on its events; default machine
	PublishTypes []string `json:"publish_types"` // type prefixes it may publish
	// Subject prefixes it may publish on; "" allows any. Keeps an app off
	// threads it does not own, e.g. github/... PRs (parking is per subject).
	PublishSubjects []string `json:"publish_subjects"`
	// What it may read: one subscription's whole filter must fit one rule
	// (ADR-0066 §2). privileged never widens it.
	Subscribe  []Rule `json:"subscribe"`
	Privileged bool   `json:"privileged"` // may set actor, trusted, hops, causation_id
}

// Rule pairs type prefixes with subject prefixes; subject "" allows any.
type Rule struct {
	Types    []string `json:"types"`
	Subjects []string `json:"subjects"`
}

// PrivilegedClient is the only client that may be privileged: agent-fleet core.
const PrivilegedClient = "bridge-core"

// ParseClients reads BRIDGE_API_CLIENTS: {"<username>": {kind, publish_types, publish_subjects, subscribe, privileged}}.
func ParseClients(js string) (map[string]Client, error) {
	clients := map[string]Client{}
	if js == "" {
		return clients, nil
	}
	// Unknown fields are refused: a leftover token_sha256 or a typo in
	// "subscribe" would otherwise be dropped silently.
	dec := json.NewDecoder(strings.NewReader(js))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&clients); err != nil {
		return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("BRIDGE_API_CLIENTS: data after the client table")
	}
	for name, c := range clients {
		if name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("BRIDGE_API_CLIENTS: bad client name %q", name)
		}
		if c.Privileged && name != PrivilegedClient {
			return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: only %s may be privileged", name, PrivilegedClient)
		}
		if c.Kind == "" {
			c.Kind = event.ActorMachine
		}
		if !validActor(c.Kind) {
			return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: unknown kind %q", name, c.Kind)
		}
		if err := typePrefixes(c.PublishTypes); err != nil {
			return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: publish_types: %w", name, err)
		}
		if err := subjectPrefixes(c.PublishSubjects); err != nil {
			return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: publish_subjects: %w", name, err)
		}
		for i, r := range c.Subscribe {
			if len(r.Types) == 0 || len(r.Subjects) == 0 {
				return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: subscribe rule %d needs types and subjects", name, i)
			}
			if err := typePrefixes(r.Types); err != nil {
				return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: subscribe rule %d: %w", name, i, err)
			}
			if err := subjectPrefixes(r.Subjects); err != nil {
				return nil, fmt.Errorf("BRIDGE_API_CLIENTS: %s: subscribe rule %d: %w", name, i, err)
			}
		}
		c.Name = name
		clients[name] = c
	}
	return clients, nil
}

// typePrefixes: written with their final dot, so a name never matches a
// longer one by accident (dev.bnei.game. is not dev.bnei.gamex).
func typePrefixes(ps []string) error {
	for _, p := range ps {
		if !strings.HasSuffix(p, ".") {
			return fmt.Errorf("type prefix %q must end with a dot", p)
		}
	}
	return nil
}

// subjectPrefixes: "" (any subject) or ending with a slash, for the same
// reason (fleet/client/game/ is not fleet/client/gameother/).
func subjectPrefixes(ps []string) error {
	for _, p := range ps {
		if p != "" && !strings.HasSuffix(p, "/") {
			return fmt.Errorf("subject prefix %q must end with a slash", p)
		}
	}
	return nil
}

// covers: rule r admits a subscription asking for types and subjects. Every
// requested type starts with one of r's type prefixes; every subject glob's
// literal head (up to its first * or ?) starts with one of r's subject
// prefixes. An empty request list matches everything, so it is admitted only
// where r allows everything: never for types, for subjects only with "".
func covers(r Rule, types, subjects []string) bool {
	if len(types) == 0 {
		return false
	}
	for _, t := range types {
		if !slices.ContainsFunc(r.Types, func(p string) bool { return strings.HasPrefix(t, p) }) {
			return false
		}
	}
	if slices.Contains(r.Subjects, "") {
		return true
	}
	if len(subjects) == 0 {
		return false
	}
	for _, g := range subjects {
		head := g
		if i := strings.IndexAny(g, "*?"); i >= 0 {
			head = g[:i]
		}
		if !slices.ContainsFunc(r.Subjects, func(p string) bool { return strings.HasPrefix(head, p) }) {
			return false
		}
	}
	return true
}

func (c Client) mayRead(types, subjects []string) bool {
	return slices.ContainsFunc(c.Subscribe, func(r Rule) bool { return covers(r, types, subjects) })
}

func validActor(a string) bool {
	return slices.Contains([]string{event.ActorHuman, event.ActorBot, event.ActorAgent, event.ActorMachine}, a)
}

// Verifier checks a bearer token and returns its subject and expiry
// (auth.Verifier in production).
type Verifier interface {
	Verify(raw string) (sub string, exp time.Time, err error)
}

type Server struct {
	st      *store.Store
	clients map[string]Client
	tokens  Verifier

	mu   sync.Mutex
	live map[string]*stream // subscription name -> its one active Subscribe
}

// stream is one Subscribe call. inflight is the event awaiting Ack/Nack, Seq 0 if none.
type stream struct {
	cancel   context.CancelCauseFunc
	inflight event.Event
	done     chan outcome // buffered 1: written once per claimed delivery
}

type outcome struct {
	advanced bool          // the cursor moved past the in-flight event
	delay    time.Duration // wait before the next delivery
}

func New(st *store.Store, clients map[string]Client, tokens Verifier) *Server {
	return &Server{st: st, clients: clients, tokens: tokens, live: map[string]*stream{}}
}

// Handler mounts the service on a mux.
func (s *Server) Handler() (string, http.Handler) { return bridgev1connect.NewBridgeServiceHandler(s) }

// errMoved ends a stream whose cursor a deletion run moved; errReplaced one a
// reconnect on the same name took over.
var (
	errMoved    = errors.New("retention moved the cursor: reconnect")
	errReplaced = errors.New("replaced by a newer stream on this subscription")
)

// errExpired ends a stream at its token's exp, so the client reconnects with
// a fresh one (ADR-0066 §1: deactivating an account takes effect within one
// token lifetime).
var errExpired = errors.New("token expired")

func (s *Server) auth(h http.Header) (Client, time.Time, error) {
	tok, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return Client{}, time.Time{}, connect.NewError(connect.CodeUnauthenticated, errors.New("bearer token required"))
	}
	sub, exp, err := s.tokens.Verify(tok)
	if err != nil {
		return Client{}, time.Time{}, connect.NewError(connect.CodeUnauthenticated, err)
	}
	c, ok := s.clients[sub]
	if !ok {
		return Client{}, time.Time{}, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("%s is not a bridge client", sub))
	}
	return c, exp, nil
}

// owns: a client subscribes as itself or under "<name>/...".
func (s *Server) owns(h http.Header, sub string) (Client, time.Time, error) {
	c, exp, err := s.auth(h)
	if err != nil {
		return c, exp, err
	}
	if len(c.Subscribe) == 0 || (sub != c.Name && !strings.HasPrefix(sub, c.Name+"/")) {
		return c, exp, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s may not use subscription %q", c.Name, sub))
	}
	return c, exp, nil
}

// MinStreamLife: a token with less left cannot open a stream, which would
// end at once and loop the client. Under golang.org/x/oauth2's 10 s refresh
// delta, so a client reconnecting with its cached token is not refused.
var MinStreamLife = 5 * time.Second

// untilExpiry bounds a stream by its token: it ends at exp. An event in
// flight then is redelivered on the next stream, as after any disconnect.
func untilExpiry(ctx context.Context, exp time.Time) (context.Context, context.CancelFunc, error) {
	if exp.Before(time.Now().Add(MinStreamLife)) {
		return nil, nil, connect.NewError(connect.CodeUnauthenticated, errors.New("token too close to expiry to open a stream"))
	}
	ctx, cancel := context.WithDeadlineCause(ctx, exp, errExpired)
	return ctx, cancel, nil
}

// ended: why the bridge stopped the stream, as a status the client acts on
// (nil when the client went away).
func ended(ctx context.Context) error {
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errExpired):
		return connect.NewError(connect.CodeUnauthenticated, errExpired)
	case errors.Is(cause, errMoved), errors.Is(cause, errReplaced):
		return connect.NewError(connect.CodeAborted, cause)
	}
	return nil
}

// unavailable is a store error on a bounded stream: Unauthenticated when the
// token's deadline caused it, so the client refreshes instead of retrying.
func unavailable(ctx context.Context, err error) error {
	if e := ended(ctx); e != nil {
		return e
	}
	return connect.NewError(connect.CodeUnavailable, err)
}

func (s *Server) Publish(ctx context.Context, req *connect.Request[bridgev1.PublishRequest]) (*connect.Response[bridgev1.PublishResponse], error) {
	c, _, err := s.auth(req.Header())
	if err != nil {
		return nil, err
	}
	p := req.Msg.GetEvent()
	if p.GetId() == "" || p.GetType() == "" || p.GetSubject() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("id, type and subject are required"))
	}
	if !slices.ContainsFunc(c.PublishTypes, func(pre string) bool { return strings.HasPrefix(p.GetType(), pre) }) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s may not publish %s", c.Name, p.GetType()))
	}
	if !slices.ContainsFunc(c.PublishSubjects, func(pre string) bool { return strings.HasPrefix(p.GetSubject(), pre) }) {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s may not publish on subject %s", c.Name, p.GetSubject()))
	}
	// Negative hops would undercut the +1 stamp below; MaxInt32 would overflow it.
	// ponytail: an unprivileged client's hops is still its own claim (it can
	// send 0); derive it from the causation_id event's stored hops if an app
	// ever drives a loop.
	if p.GetHops() < 0 || p.GetHops() == math.MaxInt32 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("hops out of range"))
	}
	data := p.GetData()
	if len(data) == 0 {
		data = []byte("null")
	}
	if !json.Valid(data) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("data must be JSON"))
	}
	e := event.Event{
		ID: p.GetId(), Source: "client/" + c.Name, Type: p.GetType(), Subject: p.GetSubject(),
		Time: time.Now(), Data: data,
		Actor: p.GetActor(), ActorLogin: p.GetActorLogin(), Trusted: p.GetTrusted(), Owner: p.GetOwner(),
		Hops: int(p.GetHops()), CausationID: p.GetCausationId(),
	}
	if p.GetTime() != nil {
		e.Time = p.GetTime().AsTime()
	}
	if c.Privileged {
		if !validActor(e.Actor) {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown actor %q", e.Actor))
		}
	} else {
		// The client vouches only for itself: its own kind, never trusted,
		// one hop further than whatever it claims caused this.
		e.Actor, e.ActorLogin, e.Trusted, e.Owner = c.Kind, c.Name, false, ""
		e.Hops++
	}
	inserted, err := s.st.Insert(ctx, e)
	if store.Invalid(err) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err) // retrying cannot help
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&bridgev1.PublishResponse{Duplicate: !inserted}), nil
}

func (s *Server) Subscribe(ctx context.Context, req *connect.Request[bridgev1.SubscribeRequest], out *connect.ServerStream[bridgev1.SubscribeResponse]) error {
	name := req.Msg.GetName()
	c, exp, err := s.owns(req.Header(), name)
	if err != nil {
		return err
	}
	if !c.mayRead(req.Msg.GetTypes(), req.Msg.GetSubjects()) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s may not read that filter", c.Name))
	}
	ctx, cancel, err := untilExpiry(ctx, exp)
	if err != nil {
		return err
	}
	defer cancel()
	cursor, gap, err := s.st.Subscribe(ctx, name, req.Msg.GetTypes(), req.Msg.GetSubjects())
	if err != nil {
		return unavailable(ctx, err)
	}
	// Send headers now: the client's call returns once the subscription is
	// registered, so a Publish made after it is never missed.
	if err := out.Send(nil); err != nil {
		return err
	}
	if gap != nil {
		if err := out.Send(&bridgev1.SubscribeResponse{Gap: &bridgev1.Gap{FromSeq: gap.From, ToSeq: gap.To}}); err != nil {
			return err
		}
	}

	ctx, stop := context.WithCancelCause(ctx)
	me := &stream{cancel: stop, done: make(chan outcome, 1)}
	s.mu.Lock()
	if old := s.live[name]; old != nil {
		old.cancel(errReplaced) // a reconnect replaces a stream that may be half-dead
	}
	s.live[name] = me
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.live[name] == me {
			delete(s.live, name)
		}
		s.mu.Unlock()
		stop(nil)
	}()

	for {
		wake := s.st.Wake()
		ds, err := s.st.Match(ctx, name, cursor, 1)
		if ctx.Err() != nil {
			return ended(ctx)
		}
		if err != nil {
			return unavailable(ctx, err)
		}
		if len(ds) == 0 {
			select {
			case <-ctx.Done():
				return ended(ctx)
			case <-wake:
			case <-time.After(PollEvery):
			}
			continue
		}
		d := ds[0]
		if d.Parked {
			if err := s.st.DeadLetter(ctx, name, d.Event, "subject parked"); err != nil {
				return unavailable(ctx, err)
			}
			cursor = d.Seq
			continue
		}
		s.mu.Lock()
		me.inflight = d.Event
		s.mu.Unlock()
		if err := out.Send(&bridgev1.SubscribeResponse{Event: toProto(d.Event, false)}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ended(ctx)
		case o := <-me.done:
			if o.advanced {
				cursor = d.Seq
			}
			select {
			case <-ctx.Done():
				return ended(ctx)
			case <-time.After(o.delay):
			}
		}
	}
}

// Drop ends the live streams of subscriptions whose cursor moved under them
// (a deletion run): they reconnect, reload the cursor and get any gap first.
func (s *Server) Drop(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range names {
		if st := s.live[n]; st != nil {
			st.cancel(errMoved)
		}
	}
}

// Prune runs one deletion of what was ingested before cutoff, then ends the
// streams it moved.
func (s *Server) Prune(ctx context.Context, cutoff time.Time) (store.Pruned, error) {
	p, err := s.st.Prune(ctx, cutoff)
	if err == nil {
		s.Drop(p.Moved)
	}
	return p, err
}

// claim takes the in-flight event off subscription sub's live stream, so
// exactly one Ack or Nack settles it.
func (s *Server) claim(sub string, seq int64) (*stream, event.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.live[sub]
	if st == nil || seq == 0 || st.inflight.Seq != seq {
		return nil, event.Event{}, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("event %d is not in flight on %q", seq, sub))
	}
	e := st.inflight
	st.inflight = event.Event{}
	return st, e, nil
}

func (s *Server) Ack(ctx context.Context, req *connect.Request[bridgev1.AckRequest]) (*connect.Response[bridgev1.AckResponse], error) {
	sub, seq := req.Msg.GetSubscription(), req.Msg.GetSeq()
	if _, _, err := s.owns(req.Header(), sub); err != nil {
		return nil, err
	}
	st, _, err := s.claim(sub, seq)
	if err != nil {
		return nil, err
	}
	if err := s.st.Ack(ctx, sub, seq); err != nil {
		st.done <- outcome{} // redeliver; subscribers are idempotent on (source, id)
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	st.done <- outcome{advanced: true}
	return connect.NewResponse(&bridgev1.AckResponse{}), nil
}

// ponytail: only Nacks count as failures. A subscriber that crashes on an
// event without Nacking gets it redelivered forever; count stream drops with
// an event in flight if that shows up.
func (s *Server) Nack(ctx context.Context, req *connect.Request[bridgev1.NackRequest]) (*connect.Response[bridgev1.NackResponse], error) {
	sub, seq := req.Msg.GetSubscription(), req.Msg.GetSeq()
	if _, _, err := s.owns(req.Header(), sub); err != nil {
		return nil, err
	}
	st, e, err := s.claim(sub, seq)
	if err != nil {
		return nil, err
	}
	n, err := s.st.Fail(ctx, sub)
	if err != nil {
		st.done <- outcome{delay: RetryBase}
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if n < MaxAttempts {
		st.done <- outcome{delay: RetryBase << (n - 1)}
		return connect.NewResponse(&bridgev1.NackResponse{}), nil
	}
	// The reason is client text bound for a Postgres text column: a NUL would
	// fail DeadLetter on every retry and wedge the subscription head-of-line.
	reason := strings.ReplaceAll(req.Msg.GetReason(), "\x00", "")
	if len(reason) > 1024 {
		reason = strings.ToValidUTF8(reason[:1024], "") // drop a rune cut in half
	}
	if reason == "" {
		reason = "nacked"
	}
	if err := s.st.DeadLetter(ctx, sub, e, fmt.Sprintf("%d attempts: %s", n, reason)); err != nil {
		st.done <- outcome{delay: RetryBase}
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	st.done <- outcome{advanced: true}
	return connect.NewResponse(&bridgev1.NackResponse{}), nil
}

func (s *Server) Replay(ctx context.Context, req *connect.Request[bridgev1.ReplayRequest], out *connect.ServerStream[bridgev1.ReplayResponse]) error {
	sub := req.Msg.GetSubscription()
	c, exp, err := s.owns(req.Header(), sub)
	if err != nil {
		return err
	}
	ctx, cancel, err := untilExpiry(ctx, exp)
	if err != nil {
		return err
	}
	defer cancel()
	// Replay reads with the filter stored by Subscribe: re-check it, so a
	// client that lost a right cannot read history with it.
	types, subjects, found, err := s.st.Filter(ctx, sub)
	if err != nil {
		return unavailable(ctx, err)
	}
	if !found {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("no subscription %q", sub))
	}
	if !c.mayRead(types, subjects) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s may no longer read %q's filter", c.Name, sub))
	}
	head, err := s.st.Head(ctx)
	if err != nil {
		return unavailable(ctx, err)
	}
	through, err := s.st.DeletedThrough(ctx)
	if err != nil {
		return unavailable(ctx, err)
	}
	if from := max(req.Msg.GetFromSeq(), 1); from <= through {
		if err := out.Send(&bridgev1.ReplayResponse{Gap: &bridgev1.Gap{FromSeq: from, ToSeq: through}}); err != nil {
			return err
		}
	}
	for after := max(req.Msg.GetFromSeq()-1, 0); after < head; {
		ds, err := s.st.Match(ctx, sub, after, 100)
		if err != nil {
			return unavailable(ctx, err)
		}
		if len(ds) == 0 {
			return nil
		}
		for _, d := range ds {
			if d.Seq > head {
				return nil
			}
			if err := out.Send(&bridgev1.ReplayResponse{Event: toProto(d.Event, true)}); err != nil {
				return err
			}
			after = d.Seq
		}
	}
	return nil
}

func toProto(e event.Event, replayed bool) *bridgev1.CloudEvent {
	return &bridgev1.CloudEvent{
		Seq: e.Seq, Id: e.ID, Source: e.Source, Type: e.Type, Subject: e.Subject,
		Time: timestamppb.New(e.Time), Data: e.Data, Actor: e.Actor, ActorLogin: e.ActorLogin,
		Trusted: e.Trusted, Owner: e.Owner, Hops: int32(e.Hops), CausationId: e.CausationID,
		Replayed: replayed,
	}
}
