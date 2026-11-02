package store

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The trust split (agent-fleet ADR-0082 §12) upgrades a log written with one
// `trusted` bit: a trusted event gets both facts, an untrusted one neither, the
// column goes, and a second Open changes nothing. Its own database, so it never
// races the other packages' tests on the shared one.
func TestOpenUpgradesTrusted(t *testing.T) {
	base := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP DATABASE IF EXISTS bridge_upgrade_test WITH (FORCE)`, `CREATE DATABASE bridge_upgrade_test`} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	u, _ := url.Parse(base)
	u.Path = "/bridge_upgrade_test"

	db, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(ctx) })
	// The events table as it was before the split.
	if _, err := db.Exec(ctx, `
		CREATE TABLE events (
		    id bigserial PRIMARY KEY, source text NOT NULL, ce_id text NOT NULL, type text NOT NULL,
		    subject text NOT NULL, actor text NOT NULL, actor_login text NOT NULL DEFAULT '',
		    trusted boolean NOT NULL, owner text NOT NULL DEFAULT '', hops integer NOT NULL DEFAULT 0,
		    causation_id text NOT NULL DEFAULT '', replayed boolean NOT NULL DEFAULT false,
		    data jsonb NOT NULL, time timestamptz NOT NULL, ingested_at timestamptz NOT NULL DEFAULT now(),
		    UNIQUE (source, ce_id));
		INSERT INTO events (source, ce_id, type, subject, actor, trusted, data, time) VALUES
		    ('s', 'yes', 't', 'x', 'human', true, '{}', now()),
		    ('s', 'no', 't', 'x', 'human', false, '{}', now())`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		s, err := Open(ctx, u.String())
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		s.Close()
	}
	for id, want := range map[string]bool{"yes": true, "no": false} {
		var actor, thread bool
		if err := db.QueryRow(ctx, `SELECT actor_trusted, thread_owned FROM events WHERE ce_id = $1`, id).Scan(&actor, &thread); err != nil {
			t.Fatal(err)
		}
		if actor != want || thread != want {
			t.Errorf("%s: actor_trusted=%v thread_owned=%v, want both %v", id, actor, thread, want)
		}
	}
	var left bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'trusted')`).Scan(&left); err != nil || left {
		t.Errorf("trusted still there: %v %v", left, err)
	}
}
