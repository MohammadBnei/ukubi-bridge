// Package bus serves the BridgeService API (infra-bootstrap ADR-0059 §2, §4):
// Publish, head-of-line Subscribe with Ack/Nack, and Replay.
package bus

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// Client is one BRIDGE_CLIENTS entry.
// ponytail: static clients from env; ADR-0059 §8's TokenReview + namespace
// allowlist replaces this when apps subscribe.
type Client struct {
	Name         string   `json:"-"`
	TokenSHA256  string   `json:"token_sha256"`  // hex sha256 of the bearer token
	Kind         string   `json:"kind"`          // actor stamped on its events; default machine
	PublishTypes []string `json:"publish_types"` // type prefixes it may publish
	// Subject prefixes it may publish on; "" allows any. Keeps an app off
	// threads it does not own, e.g. github/... PRs (parking is per subject).
	PublishSubjects []string `json:"publish_subjects"`
	Subscribe       bool     `json:"subscribe"`
	Privileged      bool     `json:"privileged"` // may set actor, trusted, hops, causation_id (agent-fleet core only)
}

// ParseClients reads BRIDGE_CLIENTS: {"name": {token_sha256, kind, publish_types, publish_subjects, subscribe, privileged}}.
func ParseClients(js string) (map[string]Client, error) {
	clients := map[string]Client{}
	if js == "" {
		return clients, nil
	}
	if err := json.Unmarshal([]byte(js), &clients); err != nil {
		return nil, fmt.Errorf("BRIDGE_CLIENTS: %w", err)
	}
	for name, c := range clients {
		if name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("BRIDGE_CLIENTS: bad client name %q", name)
		}
		if b, err := hex.DecodeString(c.TokenSHA256); err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("BRIDGE_CLIENTS: %s: token_sha256 is not a hex sha256", name)
		}
		if c.Kind == "" {
			c.Kind = event.ActorMachine
		}
		if !validActor(c.Kind) {
			return nil, fmt.Errorf("BRIDGE_CLIENTS: %s: unknown kind %q", name, c.Kind)
		}
		c.Name, c.TokenSHA256 = name, strings.ToLower(c.TokenSHA256)
		clients[name] = c
	}
	return clients, nil
}

func validActor(a string) bool {
	return slices.Contains([]string{event.ActorHuman, event.ActorBot, event.ActorAgent, event.ActorMachine}, a)
}

type Server struct {
	st      *store.Store
	clients map[string]Client

	mu   sync.Mutex
	live map[string]*stream // subscription name -> its one active Subscribe
}

// stream is one Subscribe call. inflight is the event awaiting Ack/Nack, Seq 0 if none.
type stream struct {
	cancel   context.CancelFunc
	inflight event.Event
	done     chan outcome // buffered 1: written once per claimed delivery
}

type outcome struct {
	advanced bool          // the cursor moved past the in-flight event
	delay    time.Duration // wait before the next delivery
}

func New(st *store.Store, clients map[string]Client) *Server {
	return &Server{st: st, clients: clients, live: map[string]*stream{}}
}

// Handler mounts the service on a mux.
func (s *Server) Handler() (string, http.Handler) { return bridgev1connect.NewBridgeServiceHandler(s) }

func (s *Server) auth(h http.Header) (Client, error) {
	tok, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return Client{}, connect.NewError(connect.CodeUnauthenticated, errors.New("bearer token required"))
	}
	sum := sha256.Sum256([]byte(tok))
	got := []byte(hex.EncodeToString(sum[:]))
	for _, c := range s.clients {
		if subtle.ConstantTimeCompare(got, []byte(c.TokenSHA256)) == 1 {
			return c, nil
		}
	}
	return Client{}, connect.NewError(connect.CodeUnauthenticated, errors.New("unknown token"))
}

// owns: a client subscribes as itself or under "<name>/...".
func (s *Server) owns(h http.Header, sub string) (Client, error) {
	c, err := s.auth(h)
	if err != nil {
		return c, err
	}
	if !c.Subscribe || (sub != c.Name && !strings.HasPrefix(sub, c.Name+"/")) {
		return c, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("%s may not use subscription %q", c.Name, sub))
	}
	return c, nil
}

func (s *Server) Publish(ctx context.Context, req *connect.Request[bridgev1.PublishRequest]) (*connect.Response[bridgev1.PublishResponse], error) {
	c, err := s.auth(req.Header())
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
	if _, err := s.owns(req.Header(), name); err != nil {
		return err
	}
	cursor, err := s.st.Subscribe(ctx, name, req.Msg.GetTypes(), req.Msg.GetSubjects())
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	// Send headers now: the client's call returns once the subscription is
	// registered, so a Publish made after it is never missed.
	if err := out.Send(nil); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	me := &stream{cancel: cancel, done: make(chan outcome, 1)}
	s.mu.Lock()
	if old := s.live[name]; old != nil {
		old.cancel() // a reconnect replaces a stream that may be half-dead
	}
	s.live[name] = me
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.live[name] == me {
			delete(s.live, name)
		}
		s.mu.Unlock()
		cancel()
	}()

	for {
		wake := s.st.Wake()
		ds, err := s.st.Match(ctx, name, cursor, 1)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return connect.NewError(connect.CodeUnavailable, err)
		}
		if len(ds) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-wake:
			case <-time.After(PollEvery):
			}
			continue
		}
		d := ds[0]
		if d.Parked {
			if err := s.st.DeadLetter(ctx, name, d.Event, "subject parked"); err != nil {
				return connect.NewError(connect.CodeUnavailable, err)
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
			return nil
		case o := <-me.done:
			if o.advanced {
				cursor = d.Seq
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(o.delay):
			}
		}
	}
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
	if _, err := s.owns(req.Header(), sub); err != nil {
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
	if _, err := s.owns(req.Header(), sub); err != nil {
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
	reason := req.Msg.GetReason()
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
	if _, err := s.owns(req.Header(), sub); err != nil {
		return err
	}
	head, err := s.st.Head(ctx)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	for after := max(req.Msg.GetFromSeq()-1, 0); after < head; {
		ds, err := s.st.Match(ctx, sub, after, 100)
		if err != nil {
			return connect.NewError(connect.CodeUnavailable, err)
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
