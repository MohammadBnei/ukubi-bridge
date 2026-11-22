package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

// Needs a throwaway Postgres: BRIDGE_TEST_DATABASE_URL=postgres://... go test ./...
func open(t *testing.T) *Store {
	url := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	s, err := Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.db.Exec(context.Background(), `TRUNCATE events, event_tags, subscriptions, dead_letters RESTART IDENTITY;
		UPDATE retention SET deleted_through = 0`); err != nil {
		t.Fatal(err)
	}
	return s
}

func ev(id string) event.Event {
	return event.Event{ID: id, Source: "test", Type: "t", Subject: "s", Actor: event.ActorMachine,
		Data: []byte(`{}`), Time: time.Unix(0, 0)}
}

func TestInsertDedup(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if ok, err := s.Insert(ctx, ev("a")); !ok || err != nil {
		t.Fatalf("first insert: %v %v", ok, err)
	}
	if ok, err := s.Insert(ctx, ev("a")); ok || err != nil {
		t.Fatalf("redelivery: inserted=%v err=%v, want false nil", ok, err)
	}
}

// The raw producer is written by Insert (nothing reads it back yet; atlas's read path is open).
func TestInsertProducer(t *testing.T) {
	s := open(t)
	e := ev("p")
	e.Producer = event.Producer("route", "x")
	if _, err := s.Insert(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := s.db.QueryRow(context.Background(), `SELECT producer::text FROM events WHERE ce_id = 'p'`).Scan(&got); err != nil || got != `{"kind": "route", "name": "x"}` {
		t.Fatalf("producer %q %v", got, err)
	}
}

// jsonb rejects \u0000; Insert must store the payload, not fail forever.
func TestInsertNullEscape(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	e := ev("nul")
	e.Data = []byte(`{"body":"a\u0000b"}`)
	if ok, err := s.Insert(ctx, e); !ok || err != nil {
		t.Fatalf("insert: %v %v", ok, err)
	}
	var body string
	if err := s.db.QueryRow(ctx, `SELECT data->>'body' FROM events WHERE ce_id = 'nul'`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if body != "a\ufffdb" {
		t.Fatalf("body = %q", body)
	}
}

// Ids must become visible in order: a reader that has seen id N must never
// later find a new id below N. Concurrent inserts plus a polling reader check it.
func TestInsertCommitOrder(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Insert(ctx, ev(fmt.Sprint(i))); err != nil {
				t.Error(err)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var cursor, seen int64
	for finished := false; !finished; {
		select {
		case <-done:
			finished = true // one last read below
		default:
		}
		rows, err := s.db.Query(ctx, `SELECT id FROM events WHERE id > $1 ORDER BY id`, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			if err := rows.Scan(&cursor); err != nil {
				t.Fatal(err)
			}
			seen++
		}
		rows.Close()
	}
	if seen != 200 {
		t.Fatalf("cursor saw %d of 200 rows: some committed below it", seen)
	}
}

func TestKnown(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Insert(ctx, ev("guid-1")); err != nil {
		t.Fatal(err)
	}
	m, err := s.Known(ctx, []string{"guid-1", "guid-2"})
	if err != nil {
		t.Fatal(err)
	}
	if !m["guid-1"] || m["guid-2"] || len(m) != 1 {
		t.Fatalf("known = %v", m)
	}
}

func TestRelistCursor(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.db.Exec(ctx, `TRUNCATE forge_relist`); err != nil {
		t.Fatal(err)
	}
	if c, err := s.RelistCursor(ctx, "a/b"); err != nil || !c.IsZero() {
		t.Fatalf("never ran: %v %v", c, err)
	}
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	for _, ts := range []time.Time{at.Add(-time.Hour), at} {
		if err := s.SetRelistCursor(ctx, "a/b", ts); err != nil {
			t.Fatal(err)
		}
	}
	if c, err := s.RelistCursor(ctx, "a/b"); err != nil || !c.Equal(at) {
		t.Fatalf("cursor %v %v, want %v", c, err, at)
	}
}

// Tag is all or none: a missing event refuses the batch, the schema refuses
// a value, and the same (event, System, version) is replaced, not added.
func TestTag(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Insert(ctx, ev("a")); err != nil {
		t.Fatal(err)
	}
	ok := Tag{Seq: 1, System: "hq", Resolution: "applied", RegistryVersion: "v1"}
	if err := s.Tag(ctx, "atlas", []Tag{ok, {Seq: 99, System: "hq", Resolution: "applied", RegistryVersion: "v1"}}); !errors.Is(err, ErrNoEvent) {
		t.Errorf("missing event: %v, want ErrNoEvent", err)
	}
	for _, bad := range []Tag{
		{Seq: 1, System: "hq", Resolution: "namespace", RegistryVersion: "v1"}, // no namespace rung
		{Seq: 1, System: "hq", Resolution: "unresolved", RegistryVersion: "v1"},
		{Seq: 1, System: "", Resolution: "applied", RegistryVersion: "v1"},
		{Seq: 1, System: "hq", Resolution: "applied", RegistryVersion: ""},
	} {
		if err := s.Tag(ctx, "atlas", []Tag{bad}); !Invalid(err) {
			t.Errorf("%+v: %v, want a refusal", bad, err)
		}
	}
	for _, res := range []string{"tracked", "applied"} {
		ok.Resolution = res
		if err := s.Tag(ctx, "atlas", []Tag{ok, {Seq: 1, Resolution: "unresolved", RegistryVersion: "v1"}}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	var res string
	if err := s.db.QueryRow(ctx, `SELECT count(*), max(resolution) FILTER (WHERE system = 'hq') FROM event_tags`).Scan(&n, &res); err != nil || n != 2 || res != "applied" {
		t.Errorf("%d tags, hq %s (%v); want 2, applied", n, res, err)
	}
}

// A System filter reads only the event's current registry version, the one
// whose first tag arrived last: hq@v1 applied, then v2 placing it elsewhere or
// v3 ambiguous, no longer matches hq, and a late re-send of v1 does not bring
// it back. Only applied matches unless the subscription opted in.
func TestTaggedLatestVersion(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.Insert(ctx, ev("a")); err != nil {
		t.Fatal(err)
	}
	tagged := func(system string, optIn ...string) (ok bool) {
		t.Helper()
		if err := s.db.QueryRow(ctx, `SELECT bridge_tagged(ARRAY[$1], $2, 1)`, system, nonNil(optIn)).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, c := range []struct {
		tags      []Tag
		hq, other bool
	}{
		{[]Tag{{Seq: 1, System: "hq", Resolution: "applied", RegistryVersion: "v1"}}, true, false},
		{[]Tag{{Seq: 1, System: "other", Resolution: "applied", RegistryVersion: "v2"}}, false, true},
		{[]Tag{{Seq: 1, System: "hq", Resolution: "ambiguous", RegistryVersion: "v3"},
			{Seq: 1, System: "other", Resolution: "ambiguous", RegistryVersion: "v3"}}, false, false},
		// A late retry of v1, a new row of it included: v3 stays current.
		{[]Tag{{Seq: 1, System: "hq", Resolution: "applied", RegistryVersion: "v1"},
			{Seq: 1, System: "other", Resolution: "applied", RegistryVersion: "v1"}}, false, false},
		{[]Tag{{Seq: 1, System: "hq", Resolution: "tracked", RegistryVersion: "v4"}}, false, false},
	} {
		if err := s.Tag(ctx, "atlas", c.tags); err != nil {
			t.Fatal(err)
		}
		if hq, other := tagged("hq"), tagged("other"); hq != c.hq || other != c.other {
			t.Errorf("after %+v: hq %v other %v, want %v %v", c.tags, hq, other, c.hq, c.other)
		}
	}
	if !tagged("hq", "tracked") || tagged("hq", "manager") {
		t.Error("tracked matches only a subscription that opted into it")
	}
}
