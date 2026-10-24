package bus

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/MohammadBnei/ukubi-bridge/internal/store"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

type fixture struct {
	db  *pgx.Conn
	api bridgev1connect.BridgeServiceClient
	srv *Server
}

// fakeTokens maps a bearer to its subject; every token is valid for exp.
type fakeTokens map[string]string

func (f fakeTokens) Verify(raw string) (string, time.Time, error) {
	sub, ok := f[raw]
	if !ok {
		return "", time.Time{}, errors.New("unknown token")
	}
	if raw == "short-token" {
		return sub, time.Now().Add(MinStreamLife + 300*time.Millisecond), nil
	}
	return sub, time.Now().Add(time.Hour), nil
}

// nobody is a valid authentik token for an account the table does not list.
var tokens = fakeTokens{"core-token": "bridge-core", "app-token": "app", "nobody-token": "nobody", "short-token": "bridge-core"}

// setup runs the API against its own fresh database, so it never races the
// store package's TRUNCATE when `go test ./...` runs packages in parallel.
func setup(t *testing.T) fixture {
	base := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP DATABASE IF EXISTS bridge_bus_test WITH (FORCE)`, `CREATE DATABASE bridge_bus_test`} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	admin.Close(ctx)
	u, _ := url.Parse(base)
	u.Path = "/bridge_bus_test"

	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(ctx) })

	clients, err := ParseClients(`{
		"bridge-core": {"kind": "agent", "publish_types": ["dev."], "publish_subjects": [""], "privileged": true,
		                "subscribe": [{"types": ["dev."], "subjects": [""]}]},
		"app":         {"kind": "bot", "publish_types": ["dev.app."], "publish_subjects": ["app/"],
		                "subscribe": [{"types": ["dev.app."], "subjects": ["app/"]}]}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	bus := New(st, clients, tokens)
	mux.Handle(bus.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// PollEvery an hour: deliveries in these tests must come from the NOTIFY nudge.
	MaxAttempts, RetryBase, PollEvery, MinStreamLife = 5, time.Millisecond, time.Hour, 100*time.Millisecond
	return fixture{db: db, api: bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL), srv: bus}
}

func as[T any](tok string, msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer "+tok)
	return r
}

func (f fixture) publish(t *testing.T, tok string, e *bridgev1.CloudEvent) bool {
	t.Helper()
	res, err := f.api.Publish(context.Background(), as(tok, &bridgev1.PublishRequest{Event: e}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.Duplicate
}

// subscribe returns once the subscription is registered: anything published
// after it is delivered.
func (f fixture) subscribe(t *testing.T, name string, subjects ...string) <-chan *bridgev1.CloudEvent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := f.api.Subscribe(ctx, as("core-token", &bridgev1.SubscribeRequest{Name: name, Types: []string{"dev."}, Subjects: subjects}))
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan *bridgev1.CloudEvent, 16)
	go func() {
		for stream.Receive() {
			ch <- stream.Msg().Event
		}
	}()
	return ch
}

func recv(t *testing.T, ch <-chan *bridgev1.CloudEvent) *bridgev1.CloudEvent {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery")
		return nil
	}
}

func quiet(t *testing.T, ch <-chan *bridgev1.CloudEvent) {
	t.Helper()
	select {
	case e := <-ch:
		t.Fatalf("unexpected delivery %s (%s)", e.Id, e.Subject)
	case <-time.After(300 * time.Millisecond):
	}
}

func ev(id, subject string) *bridgev1.CloudEvent {
	return &bridgev1.CloudEvent{Id: id, Type: "dev.app.test", Subject: subject, Actor: "agent", Data: []byte(`{}`)}
}

func TestPublishDedup(t *testing.T) {
	f := setup(t)
	if f.publish(t, "app-token", ev("d1", "app/x")) {
		t.Fatal("first publish reported duplicate")
	}
	if !f.publish(t, "app-token", ev("d1", "app/x")) {
		t.Fatal("second publish of the same id was appended")
	}
	if f.publish(t, "core-token", ev("d1", "app/x")) {
		t.Fatal("same id from another client is a different source, not a duplicate")
	}
}

func TestHeadOfLine(t *testing.T) {
	f := setup(t)
	ch := f.subscribe(t, "bridge-core/hol", "hol/*")
	f.publish(t, "core-token", ev("h1", "hol/a"))
	f.publish(t, "core-token", ev("h2", "hol/b"))
	f.publish(t, "core-token", ev("h3", "other/c")) // filtered out

	first := recv(t, ch)
	if first.Id != "h1" {
		t.Fatalf("got %s first, want h1", first.Id)
	}
	quiet(t, ch) // h2 waits for h1's ack
	_, err := f.api.Ack(context.Background(), as("core-token", &bridgev1.AckRequest{Subscription: "bridge-core/hol", Seq: first.Seq + 1}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("ack of an event not in flight: %v, want FailedPrecondition", err)
	}
	f.ack(t, "bridge-core/hol", first.Seq)
	if second := recv(t, ch); second.Id != "h2" {
		t.Fatalf("got %s second, want h2", second.Id)
	}
}

func (f fixture) ack(t *testing.T, sub string, seq int64) {
	t.Helper()
	if _, err := f.api.Ack(context.Background(), as("core-token", &bridgev1.AckRequest{Subscription: sub, Seq: seq})); err != nil {
		t.Fatal(err)
	}
}

// A poison event is retried MaxAttempts times, then dead-lettered, and later
// events on its subject are parked behind it while other subjects flow.
func TestNackDeadLetterParksSubject(t *testing.T) {
	f := setup(t)
	ch := f.subscribe(t, "bridge-core/dlq", "dlq/*")
	f.publish(t, "core-token", ev("p1", "dlq/poison"))
	f.publish(t, "core-token", ev("p2", "dlq/poison"))
	f.publish(t, "core-token", ev("p3", "dlq/fine"))

	for i := range MaxAttempts {
		e := recv(t, ch)
		if e.Id != "p1" {
			t.Fatalf("attempt %d delivered %s, want p1 redelivered", i+1, e.Id)
		}
		if _, err := f.api.Nack(context.Background(), as("core-token", &bridgev1.NackRequest{Subscription: "bridge-core/dlq", Seq: e.Seq, Reason: "boom"})); err != nil {
			t.Fatal(err)
		}
	}
	if e := recv(t, ch); e.Id != "p3" {
		t.Fatalf("after dead-lettering p1 got %s, want p3 (p2 parked)", e.Id)
	}
	rows, _ := f.db.Query(context.Background(), `
		SELECT e.ce_id FROM dead_letters d JOIN events e ON e.id = d.event_id
		WHERE d.subscription = 'bridge-core/dlq' ORDER BY d.event_id`)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[p1 p2]" {
		t.Fatalf("dead letters %v, want [p1 p2]", got)
	}
}

// A Nack reason Postgres cannot store must not block dead-lettering.
func TestNackReasonSanitized(t *testing.T) {
	f := setup(t)
	ch := f.subscribe(t, "bridge-core/nul", "nul/*")
	f.publish(t, "core-token", ev("n1", "nul/a"))
	f.publish(t, "core-token", ev("n2", "nul/b"))

	for range MaxAttempts {
		e := recv(t, ch)
		if _, err := f.api.Nack(context.Background(), as("core-token", &bridgev1.NackRequest{Subscription: "bridge-core/nul", Seq: e.Seq, Reason: "bad\x00" + strings.Repeat("é", 1000)})); err != nil {
			t.Fatal(err)
		}
	}
	if e := recv(t, ch); e.Id != "n2" {
		t.Fatalf("after dead-lettering n1 got %s, want n2", e.Id)
	}
	var reason string
	if err := f.db.QueryRow(context.Background(), `SELECT reason FROM dead_letters WHERE subscription = 'bridge-core/nul'`).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(reason, "5 attempts: bad") || len(reason) > 1100 || !utf8.ValidString(reason) {
		t.Fatalf("stored reason %q (%d bytes)", reason, len(reason))
	}
}

func TestReplay(t *testing.T) {
	f := setup(t)
	ch := f.subscribe(t, "bridge-core/replay", "rep/*")
	f.publish(t, "core-token", ev("r1", "rep/a"))
	f.publish(t, "core-token", ev("r2", "rep/a"))
	first := recv(t, ch)
	f.ack(t, "bridge-core/replay", first.Seq)
	second := recv(t, ch)

	stream, err := f.api.Replay(context.Background(), as("core-token", &bridgev1.ReplayRequest{Subscription: "bridge-core/replay", FromSeq: first.Seq}))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for stream.Receive() {
		e := stream.Msg().Event
		if !e.Replayed {
			t.Fatalf("replayed %s without replayed=true", e.Id)
		}
		ids = append(ids, e.Id)
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(ids) != "[r1 r2]" {
		t.Fatalf("replay sent %v, want [r1 r2]", ids)
	}

	// The log and the cursor are untouched, and r2 is still the one in flight.
	var replayedRows int
	var cursor int64
	f.db.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE replayed`).Scan(&replayedRows)
	f.db.QueryRow(context.Background(), `SELECT last_acked_id FROM subscriptions WHERE name = 'bridge-core/replay'`).Scan(&cursor)
	if replayedRows != 0 || cursor != first.Seq {
		t.Fatalf("replay mutated state: %d replayed rows, cursor %d (want 0, %d)", replayedRows, cursor, first.Seq)
	}
	f.ack(t, "bridge-core/replay", second.Seq)
}

func TestAuthz(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	claim := &bridgev1.CloudEvent{Id: "z1", Type: "dev.app.x", Subject: "app/z", Actor: "human", ActorLogin: "operator",
		Trusted: true, Owner: "zot", Hops: 2, CausationId: "c1", Replayed: true}
	f.publish(t, "app-token", claim)
	claim.Id = "z2"
	f.publish(t, "core-token", claim)

	type row struct {
		actor, login, owner, causation string
		trusted, replayed              bool
		hops                           int
	}
	get := func(id string) (r row) {
		if err := f.db.QueryRow(ctx, `SELECT actor, actor_login, owner, causation_id, trusted, replayed, hops FROM events WHERE ce_id = $1`, id).
			Scan(&r.actor, &r.login, &r.owner, &r.causation, &r.trusted, &r.replayed, &r.hops); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if got, want := get("z1"), (row{"bot", "app", "", "c1", false, false, 3}); got != want {
		t.Fatalf("unprivileged publish stored %+v, want %+v", got, want)
	}
	if got, want := get("z2"), (row{"human", "operator", "zot", "c1", true, false, 2}); got != want {
		t.Fatalf("privileged publish stored %+v, want %+v", got, want)
	}

	cases := []struct {
		name string
		err  error
		code connect.Code
	}{
		{"no token", func() error {
			_, err := f.api.Publish(ctx, connect.NewRequest(&bridgev1.PublishRequest{Event: ev("z3", "z")}))
			return err
		}(), connect.CodeUnauthenticated},
		{"wrong token", func() error {
			_, err := f.api.Publish(ctx, as("nope", &bridgev1.PublishRequest{Event: ev("z3", "z")}))
			return err
		}(), connect.CodeUnauthenticated},
		{"type outside publish_types", func() error {
			_, err := f.api.Publish(ctx, as("app-token", &bridgev1.PublishRequest{Event: &bridgev1.CloudEvent{Id: "z4", Type: "dev.github.x", Subject: "z"}}))
			return err
		}(), connect.CodePermissionDenied},
		{"subject outside publish_subjects", func() error {
			_, err := f.api.Publish(ctx, as("app-token", &bridgev1.PublishRequest{Event: &bridgev1.CloudEvent{Id: "z5", Type: "dev.app.x", Subject: "github/MohammadBnei/editable-blog/pr/42"}}))
			return err
		}(), connect.CodePermissionDenied},
		{"another client's subscription", func() error {
			_, err := f.api.Ack(ctx, as("app-token", &bridgev1.AckRequest{Subscription: "bridge-core", Seq: 1}))
			return err
		}(), connect.CodePermissionDenied},
	}
	for _, c := range cases {
		var ce *connect.Error
		if !errors.As(c.err, &ce) || ce.Code() != c.code {
			t.Errorf("%s: %v, want %v", c.name, c.err, c.code)
		}
	}
}

// Events Postgres can never store are the client's fault, not an outage:
// InvalidArgument, so a publisher that retries on Unavailable does not loop.
func TestPublishInvalid(t *testing.T) {
	f := setup(t)
	cases := map[string]*bridgev1.CloudEvent{
		"NUL in subject":     {Id: "i1", Type: "dev.app.x", Subject: "app/x\x00y"},
		"negative hops":      {Id: "i3", Type: "dev.app.x", Subject: "app/x", Hops: -50},
		"hops overflows int": {Id: "i4", Type: "dev.app.x", Subject: "app/x", Hops: math.MaxInt32},
	}
	for name, e := range cases {
		_, err := f.api.Publish(context.Background(), as("app-token", &bridgev1.PublishRequest{Event: e}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	// store.Insert rewrites \u0000 in data, so that one is stored, not refused.
	e := &bridgev1.CloudEvent{Id: "i2", Type: "dev.app.x", Subject: "app/x", Data: []byte(`{"a":"\u0000"}`)}
	if _, err := f.api.Publish(context.Background(), as("app-token", &bridgev1.PublishRequest{Event: e})); err != nil {
		t.Errorf("\\u0000 in data: %v, want stored", err)
	}
}

func TestReadRules(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	sub := func(tok, name string, types, subjects []string) error {
		stream, err := f.api.Subscribe(ctx, as(tok, &bridgev1.SubscribeRequest{Name: name, Types: types, Subjects: subjects}))
		if err != nil {
			return err
		}
		defer stream.Close()
		stream.Receive() // the first read surfaces a refusal sent before any message
		return stream.Err()
	}
	refused := map[string]error{
		"unlisted account":  sub("nobody-token", "nobody", []string{"dev.app."}, []string{"app/*"}),
		"no types":          sub("app-token", "app", nil, []string{"app/*"}),
		"type outside rule": sub("app-token", "app", []string{"dev."}, []string{"app/*"}),
		"no subjects":       sub("app-token", "app", []string{"dev.app."}, nil),
		"subject outside":   sub("app-token", "app", []string{"dev.app."}, []string{"github/*"}),
		"another's name":    sub("app-token", "bridge-core/x", []string{"dev.app."}, []string{"app/*"}),
	}
	for name, err := range refused {
		if c := connect.CodeOf(err); c != connect.CodePermissionDenied && c != connect.CodeUnauthenticated {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}

	// Replay re-checks the stored filter: one widened behind the bridge's back is refused.
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		stream, err := f.api.Subscribe(cctx, as("app-token", &bridgev1.SubscribeRequest{Name: "app/r", Types: []string{"dev.app."}, Subjects: []string{"app/*"}}))
		if err == nil {
			for stream.Receive() {
			}
		}
	}()
	<-ch
	if _, err := f.db.Exec(ctx, `UPDATE subscriptions SET types = '{dev.}', subjects = '{}' WHERE name = 'app/r'`); err != nil {
		t.Fatal(err)
	}
	rs, err := f.api.Replay(ctx, as("app-token", &bridgev1.ReplayRequest{Subscription: "app/r", FromSeq: 1}))
	if err == nil {
		for rs.Receive() {
		}
		err = rs.Err()
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("replay of a widened filter: %v, want PermissionDenied", err)
	}
}

// A stream ends at its token's exp with Unauthenticated, so the client
// reconnects with a fresh token instead of reading on a lapsed one.
func TestStreamEndsAtExpiry(t *testing.T) {
	f := setup(t)
	stream, err := f.api.Subscribe(context.Background(), as("short-token", &bridgev1.SubscribeRequest{Name: "bridge-core/exp", Types: []string{"dev."}}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for stream.Receive() {
		}
		done <- stream.Err()
	}()
	select {
	case err := <-done:
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("stream ended with %v, want Unauthenticated", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream outlived its token")
	}
}

// Retention seen from a subscriber: a gapped stream ends Aborted, the next
// Subscribe sends the gap first until the subscriber confirms it, and Replay
// from below the watermark starts with one too.
func TestRetentionGap(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	stream, err := f.api.Subscribe(ctx, as("core-token", &bridgev1.SubscribeRequest{Name: "bridge-core/ret", Types: []string{"dev."}, Subjects: []string{"ret/*"}}))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *bridgev1.SubscribeResponse, 8)
	done := make(chan error, 1)
	go func() {
		for stream.Receive() {
			got <- stream.Msg()
		}
		done <- stream.Err()
	}()
	f.publish(t, "core-token", ev("g1", "ret/a"))
	f.publish(t, "core-token", ev("g2", "ret/a"))
	first := (<-got).Event // in flight, never acked
	if _, err := f.db.Exec(ctx, `UPDATE events SET ingested_at = now() - interval '40 days'`); err != nil {
		t.Fatal(err)
	}
	p, err := f.srv.Prune(ctx, time.Now().Add(-30*24*time.Hour))
	if err != nil || p.Through != first.Seq+1 {
		t.Fatalf("prune %+v %v", p, err)
	}
	select {
	case err := <-done:
		if connect.CodeOf(err) != connect.CodeAborted {
			t.Fatalf("moved stream ended with %v, want Aborted", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("moved stream kept running on its old cursor")
	}

	again, err := f.api.Subscribe(ctx, as("core-token", &bridgev1.SubscribeRequest{Name: "bridge-core/ret", Types: []string{"dev."}, Subjects: []string{"ret/*"}}))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !again.Receive() {
		t.Fatal(again.Err())
	}
	if g := again.Msg().Gap; g == nil || g.FromSeq != first.Seq || g.ToSeq != p.Through || again.Msg().Event != nil {
		t.Fatalf("first message %+v, want the gap %d..%d", again.Msg(), first.Seq, p.Through)
	}
	g := again.Msg().Gap
	confirm := func(v int64) error {
		_, err := f.api.ConfirmGap(ctx, as("core-token", &bridgev1.ConfirmGapRequest{Subscription: "bridge-core/ret", Version: v}))
		return err
	}
	// Confirmed right after receipt: the server recorded the version before sending.
	if err := confirm(g.Version); err != nil {
		t.Fatalf("confirming the gap: %v", err)
	}
	if err := confirm(g.Version + 1); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("confirming a version never sent: %v, want FailedPrecondition", err)
	}
	var gapTo *int64
	if err := f.db.QueryRow(ctx, `SELECT gap_to FROM subscriptions WHERE name = 'bridge-core/ret'`).Scan(&gapTo); err != nil {
		t.Fatal(err)
	}
	if gapTo != nil {
		t.Fatal("a confirmed gap was not cleared")
	}
	if err := confirm(g.Version); err != nil {
		t.Fatalf("confirming twice: %v, want OK (a retried confirmation)", err)
	}
	if err := confirm(0); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("version 0: %v, want InvalidArgument", err)
	}

	rs, err := f.api.Replay(ctx, as("core-token", &bridgev1.ReplayRequest{Subscription: "bridge-core/ret", FromSeq: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if !rs.Receive() || rs.Msg().Gap == nil || rs.Msg().Gap.ToSeq != p.Through {
		t.Fatalf("replay from below the watermark: %+v %v", rs.Msg(), rs.Err())
	}
	for rs.Receive() {
		t.Fatalf("replay sent a deleted event %+v", rs.Msg())
	}
}

// A stream retention only moved (it lost nothing) keeps running; a stream
// replaced by a reconnect on its name ends cleanly, so its client does not
// come back and flap with the new one.
func TestMovedAndReplacedStreams(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // runs before setup's server Close, which waits for open streams
	open := func(name string) chan error {
		stream, err := f.api.Subscribe(ctx, as("core-token", &bridgev1.SubscribeRequest{Name: name, Types: []string{"dev.q."}}))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			for stream.Receive() {
			}
			done <- stream.Err()
		}()
		return done
	}
	quietDone := open("bridge-core/quiet")
	f.publish(t, "core-token", ev("m1", "app/x")) // dev.app.test: the quiet subscription does not match it
	f.db.Exec(ctx, `UPDATE events SET ingested_at = now() - interval '40 days'`)
	p, err := f.srv.Prune(ctx, time.Now().Add(-30*24*time.Hour))
	if err != nil || len(p.Moved) != 1 || len(p.Gapped) != 0 {
		t.Fatalf("prune %+v %v", p, err)
	}
	select {
	case err := <-quietDone:
		t.Fatalf("a moved-only stream ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	open("bridge-core/quiet") // replaces it
	select {
	case err := <-quietDone:
		if err != nil {
			t.Fatalf("replaced stream ended with %v, want a clean end", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced stream kept running")
	}
}
