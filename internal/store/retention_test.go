package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

func evOn(id, typ, subject string) event.Event {
	e := ev(id)
	e.Type, e.Subject = typ, subject
	return e
}

// age makes the events up to id look ingested long ago (their time is the
// publisher's claim and stays 1970, which must not matter).
func age(t *testing.T, s *Store, through int64) {
	t.Helper()
	if _, err := s.db.Exec(context.Background(), `UPDATE events SET ingested_at = now() - interval '40 days' WHERE id <= $1`, through); err != nil {
		t.Fatal(err)
	}
}

func cursorGap(t *testing.T, s *Store, name string) (int64, *int64, *int64) {
	t.Helper()
	var c int64
	var from, to *int64
	if err := s.db.QueryRow(context.Background(), `SELECT last_acked_id, gap_from, gap_to FROM subscriptions WHERE name = $1`, name).Scan(&c, &from, &to); err != nil {
		t.Fatal(err)
	}
	return c, from, to
}

func TestPrune(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	cutoff := time.Now().Add(-30 * 24 * time.Hour)

	// Every event's time is 1970: deleting by it would empty the log.
	if _, err := s.Insert(ctx, evOn("fresh0", "dev.a.x", "a/1")); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Prune(ctx, cutoff); err != nil || p.Through != 0 {
		t.Fatalf("a backdated event was pruned: %+v %v", p, err)
	}

	// Subscriptions start at the head (1).
	for _, sub := range []struct{ name, types, subjects string }{
		{"quiet", "dev.q.", ""}, {"lagging", "dev.a.", ""}, {"parked", "dev.a.", ""}, {"ahead", "dev.a.", ""},
	} {
		if _, _, err := s.Subscribe(ctx, sub.name, []string{sub.types}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 4; i++ {
		subject := "a/1"
		if i == 3 {
			subject = "a/poison"
		}
		if _, err := s.Insert(ctx, evOn(fmt.Sprint("old", i), "dev.a.x", subject)); err != nil {
			t.Fatal(err)
		}
	}
	// ids: 1 fresh0, 2..5 old1..old4 (old3 on a/poison). "parked" dead-lettered
	// old3 and moved past it; "ahead" acked everything.
	if err := s.DeadLetter(ctx, "parked", event.Event{Seq: 4, Subject: "a/poison"}, "boom"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(ctx, "ahead", 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(ctx, evOn("old5", "dev.a.x", "a/poison")); err != nil { // id 6, parked behind old3
		t.Fatal(err)
	}
	if _, err := s.Insert(ctx, evOn("new", "dev.a.x", "a/1")); err != nil { // id 7, stays
		t.Fatal(err)
	}
	age(t, s, 6)

	p, err := s.Prune(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if p.Through != 6 {
		t.Fatalf("through %d, want 6", p.Through)
	}
	slices.Sort(p.Moved)
	slices.Sort(p.Gapped)
	// ahead acked through old4; old5 (6) is kept for parked's sake, so ahead's
	// cursor stays before it and it is still delivered: no gap, not moved.
	// parked lost old4 (5); lagging lost old1, old2, old4 and stops before old3.
	if fmt.Sprint(p.Moved) != "[lagging parked quiet]" || fmt.Sprint(p.Gapped) != "[lagging parked]" {
		t.Fatalf("moved %v gapped %v", p.Moved, p.Gapped)
	}
	// Kept: old3 and old5 (at or past the uncleared dead letter on a/poison) and new.
	rows, _ := s.db.Query(ctx, `SELECT ce_id FROM events ORDER BY id`)
	var kept []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		kept = append(kept, id)
	}
	if fmt.Sprint(kept) != "[old3 old5 new]" || p.Deleted != 4 {
		t.Fatalf("kept %v, deleted %d", kept, p.Deleted)
	}
	if c, from, to := cursorGap(t, s, "lagging"); c != 3 || from == nil || *from != 2 || *to != 6 {
		t.Fatalf("lagging: cursor %d gap %v..%v, want 3 (before kept old3), 2..6", c, from, to)
	}
	if c, from, _ := cursorGap(t, s, "quiet"); c != 6 || from != nil {
		t.Fatalf("quiet: cursor %d gap %v, want 6 and none", c, from)
	}
	var parkedDL int
	s.db.QueryRow(ctx, `SELECT count(*) FROM dead_letters WHERE subscription = 'parked' AND event_id = 6`).Scan(&parkedDL)
	if parkedDL != 1 {
		t.Fatal("old5, on parked's poisoned subject, did not join its dead letters")
	}
	if c, from, _ := cursorGap(t, s, "ahead"); c != 5 || from != nil {
		t.Fatalf("ahead cursor %d gap %v, want 5 and none", c, from)
	}

	// A second run with the same cutoff changes nothing.
	if p2, err := s.Prune(ctx, cutoff); err != nil || p2.Deleted != 0 || len(p2.Moved) != 0 {
		t.Fatalf("second run: %+v %v", p2, err)
	}
	if x, _ := s.DeletedThrough(ctx); x != 6 {
		t.Fatalf("deleted_through %d", x)
	}

	// Subscribe reports the gap; an Ack inside it neither clears it nor moves
	// the cursor back; an Ack past it clears it.
	if _, gap, err := s.Subscribe(ctx, "lagging", []string{"dev.a."}, nil); err != nil || gap == nil || gap.From != 2 || gap.To != 6 {
		t.Fatalf("subscribe gap %+v %v", gap, err)
	}
	if err := s.Ack(ctx, "lagging", 3); err != nil {
		t.Fatal(err)
	}
	if c, from, _ := cursorGap(t, s, "lagging"); c != 3 || from == nil {
		t.Fatalf("ack inside the gap: cursor %d gap %v", c, from)
	}
	if err := s.Ack(ctx, "lagging", 7); err != nil {
		t.Fatal(err)
	}
	if c, from, _ := cursorGap(t, s, "lagging"); c != 7 || from != nil {
		t.Fatalf("ack past the gap: cursor %d gap %v", c, from)
	}

	// Once the operator clears the dead letters, the kept events go on the
	// next run, and ahead, which never received old5, gets a gap for it.
	if _, err := s.db.Exec(ctx, `UPDATE dead_letters SET cleared_at = now() WHERE subscription = 'parked'`); err != nil {
		t.Fatal(err)
	}
	p3, err := s.Prune(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if p3.Deleted != 2 || fmt.Sprint(p3.Gapped) != "[ahead]" {
		t.Fatalf("after clearing: %+v", p3)
	}
	if c, from, to := cursorGap(t, s, "ahead"); c != 6 || from == nil || *from != 6 || *to != 6 {
		t.Fatalf("ahead: cursor %d gap %v..%v, want 6, 6..6", c, from, to)
	}
}

// Two runs before a reconnect widen one gap instead of replacing it.
func TestPruneWidensGap(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	if _, _, err := s.Subscribe(ctx, "w", []string{"dev."}, nil); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		s.Insert(ctx, evOn(fmt.Sprint("e", i), "dev.x", "x/1"))
	}
	age(t, s, 2)
	if _, err := s.Prune(ctx, cutoff); err != nil {
		t.Fatal(err)
	}
	age(t, s, 4)
	if _, err := s.Prune(ctx, cutoff); err != nil {
		t.Fatal(err)
	}
	if _, from, to := cursorGap(t, s, "w"); from == nil || *from != 1 || *to != 4 {
		t.Fatalf("gap %v..%v, want 1..4", from, to)
	}
}

func TestStaleDeadLetters(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	s.Subscribe(ctx, "d", []string{"dev."}, nil)
	for i, subj := range []string{"x/1", "x/1", "x/2"} {
		s.DeadLetter(ctx, "d", event.Event{Seq: int64(i + 1), Subject: subj}, "boom")
	}
	s.db.Exec(ctx, `UPDATE dead_letters SET at = now() - interval '4 days' WHERE subject = 'x/1'`)
	got, err := s.StaleDeadLetters(ctx, 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject != "x/1" || got[0].Count != 2 {
		t.Fatalf("stale %+v, want one line for x/1 with 2", got)
	}
}
