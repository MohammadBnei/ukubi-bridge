package store

import (
	"context"
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
	if _, err := s.db.Exec(context.Background(), `TRUNCATE events, subscriptions, dead_letters RESTART IDENTITY`); err != nil {
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
