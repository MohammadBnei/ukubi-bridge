package bus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	"github.com/MohammadBnei/ukubi-bridge/internal/store"
	bridgev1 "github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1"
	"github.com/MohammadBnei/ukubi-bridge/proto/gen/go/bridge/v1/bridgev1connect"
)

type fixture struct {
	db  *pgx.Conn
	api bridgev1connect.BridgeServiceClient
}

func hash(tok string) string { s := sha256.Sum256([]byte(tok)); return hex.EncodeToString(s[:]) }

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

	clients, err := ParseClients(fmt.Sprintf(`{
		"core": {"token_sha256": %q, "kind": "agent", "publish_types": ["dev."], "publish_subjects": [""], "subscribe": true, "privileged": true},
		"app":  {"token_sha256": %q, "kind": "bot", "publish_types": ["dev.app."], "publish_subjects": ["app/"], "subscribe": true}
	}`, hash("core-token"), hash("app-token")))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(New(st, clients).Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// PollEvery an hour: deliveries in these tests must come from the NOTIFY nudge.
	MaxAttempts, RetryBase, PollEvery = 5, time.Millisecond, time.Hour
	return fixture{db: db, api: bridgev1connect.NewBridgeServiceClient(srv.Client(), srv.URL)}
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
	stream, err := f.api.Subscribe(ctx, as("core-token", &bridgev1.SubscribeRequest{Name: name, Subjects: subjects}))
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
	ch := f.subscribe(t, "core/hol", "hol/*")
	f.publish(t, "core-token", ev("h1", "hol/a"))
	f.publish(t, "core-token", ev("h2", "hol/b"))
	f.publish(t, "core-token", ev("h3", "other/c")) // filtered out

	first := recv(t, ch)
	if first.Id != "h1" {
		t.Fatalf("got %s first, want h1", first.Id)
	}
	quiet(t, ch) // h2 waits for h1's ack
	_, err := f.api.Ack(context.Background(), as("core-token", &bridgev1.AckRequest{Subscription: "core/hol", Seq: first.Seq + 1}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("ack of an event not in flight: %v, want FailedPrecondition", err)
	}
	f.ack(t, "core/hol", first.Seq)
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
	ch := f.subscribe(t, "core/dlq", "dlq/*")
	f.publish(t, "core-token", ev("p1", "dlq/poison"))
	f.publish(t, "core-token", ev("p2", "dlq/poison"))
	f.publish(t, "core-token", ev("p3", "dlq/fine"))

	for i := range MaxAttempts {
		e := recv(t, ch)
		if e.Id != "p1" {
			t.Fatalf("attempt %d delivered %s, want p1 redelivered", i+1, e.Id)
		}
		if _, err := f.api.Nack(context.Background(), as("core-token", &bridgev1.NackRequest{Subscription: "core/dlq", Seq: e.Seq, Reason: "boom"})); err != nil {
			t.Fatal(err)
		}
	}
	if e := recv(t, ch); e.Id != "p3" {
		t.Fatalf("after dead-lettering p1 got %s, want p3 (p2 parked)", e.Id)
	}
	rows, _ := f.db.Query(context.Background(), `
		SELECT e.ce_id FROM dead_letters d JOIN events e ON e.id = d.event_id
		WHERE d.subscription = 'core/dlq' ORDER BY d.event_id`)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[p1 p2]" {
		t.Fatalf("dead letters %v, want [p1 p2]", got)
	}
}

func TestReplay(t *testing.T) {
	f := setup(t)
	ch := f.subscribe(t, "core/replay", "rep/*")
	f.publish(t, "core-token", ev("r1", "rep/a"))
	f.publish(t, "core-token", ev("r2", "rep/a"))
	first := recv(t, ch)
	f.ack(t, "core/replay", first.Seq)
	second := recv(t, ch)

	stream, err := f.api.Replay(context.Background(), as("core-token", &bridgev1.ReplayRequest{Subscription: "core/replay", FromSeq: first.Seq}))
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
	f.db.QueryRow(context.Background(), `SELECT last_acked_id FROM subscriptions WHERE name = 'core/replay'`).Scan(&cursor)
	if replayedRows != 0 || cursor != first.Seq {
		t.Fatalf("replay mutated state: %d replayed rows, cursor %d (want 0, %d)", replayedRows, cursor, first.Seq)
	}
	f.ack(t, "core/replay", second.Seq)
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
			_, err := f.api.Ack(ctx, as("app-token", &bridgev1.AckRequest{Subscription: "core", Seq: 1}))
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
		"\\u0000 in data":    {Id: "i2", Type: "dev.app.x", Subject: "app/x", Data: []byte(`{"a":"\u0000"}`)},
		"negative hops":      {Id: "i3", Type: "dev.app.x", Subject: "app/x", Hops: -50},
		"hops overflows int": {Id: "i4", Type: "dev.app.x", Subject: "app/x", Hops: math.MaxInt32},
	}
	for name, e := range cases {
		_, err := f.api.Publish(context.Background(), as("app-token", &bridgev1.PublishRequest{Event: e}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
}
