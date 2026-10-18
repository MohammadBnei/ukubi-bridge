// Package store is the bus's only door to Postgres (ADR-0059 §2).
package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

//go:embed schema.sql
var schema string

// insertLock serialises inserts so event ids commit in id order and a
// subscriber cursor can never skip a row that commits late.
// ponytail: one global lock; move to an xmin-horizon cursor if throughput matters.
const insertLock = 0x6272696467650001 // "bridge" + 1

// notifyChannel is nudged inside every insert transaction, so it fires on commit.
const notifyChannel = "bridge_events"

type Store struct {
	db   *pgxpool.Pool
	stop context.CancelFunc

	mu   sync.Mutex
	wake chan struct{} // closed and replaced on every NOTIFY
}

// Open connects and applies the schema. url must reach the primary directly,
// not pgbouncer: LISTEN needs a session-mode connection.
func Open(ctx context.Context, url string) (*Store, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	// ponytail: idempotent DDL at boot, a migration tool when the schema first changes.
	if _, err := db.Exec(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	lctx, stop := context.WithCancel(context.Background())
	s := &Store{db: db, stop: stop, wake: make(chan struct{})}
	go s.listen(lctx)
	return s, nil
}

func (s *Store) Close() { s.stop(); s.db.Close() }

// Wake returns a channel closed by the next insert. Take it before reading,
// so an insert landing between the read and the wait is not missed.
func (s *Store) Wake() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wake
}

func (s *Store) broadcast() {
	s.mu.Lock()
	close(s.wake)
	s.wake = make(chan struct{})
	s.mu.Unlock()
}

// listen holds one pooled connection on LISTEN. Readers also poll, so a lost
// connection costs latency, not events.
func (s *Store) listen(ctx context.Context) {
	for ctx.Err() == nil {
		conn, err := s.db.Acquire(ctx)
		if err == nil {
			if _, err = conn.Exec(ctx, "LISTEN "+notifyChannel); err == nil {
				s.broadcast() // anything inserted while we were not listening
				for err == nil {
					if _, err = conn.Conn().WaitForNotification(ctx); err == nil {
						s.broadcast()
					}
				}
			}
			conn.Release()
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// Insert appends e to the log. It returns false, nil when (source, ce_id) is
// already there: a redelivery is not an error.
func (s *Store) Insert(ctx context.Context, e event.Event) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(insertLock)); err != nil {
		return false, err
	}
	var id int64
	err = tx.QueryRow(ctx, `
		INSERT INTO events (source, ce_id, type, subject, actor, actor_login, trusted,
		                    owner, hops, causation_id, replayed, data, time)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (source, ce_id) DO NOTHING
		RETURNING id`,
		e.Source, e.ID, e.Type, e.Subject, e.Actor, e.ActorLogin, e.Trusted,
		e.Owner, e.Hops, e.CausationID, e.Replayed, e.Data, e.Time).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, notifyChannel); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// Invalid reports whether Postgres refused err's values themselves (class 22
// data exception, e.g. NUL in text, \u0000 in jsonb, integer out of range;
// class 23 integrity): retrying the same event can never succeed.
func Invalid(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (strings.HasPrefix(pg.Code, "22") || strings.HasPrefix(pg.Code, "23"))
}

// Subscribe creates or refilters subscription name and returns its cursor.
// A new subscription starts at the head of the log: history is Replay's job.
func (s *Store) Subscribe(ctx context.Context, name string, types, subjects []string) (int64, error) {
	var cursor int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO subscriptions (name, types, subjects, last_acked_id)
		VALUES ($1, $2, $3, (SELECT coalesce(max(id), 0) FROM events))
		ON CONFLICT (name) DO UPDATE
		SET types = excluded.types, subjects = excluded.subjects, last_seen = now()
		RETURNING last_acked_id`, name, nonNil(types), nonNil(subjects)).Scan(&cursor)
	return cursor, err
}

// Delivery is an event as one subscription sees it.
type Delivery struct {
	event.Event
	Parked bool // its subject has an uncleared dead letter for this subscription
}

// Match returns up to limit events after cursor that match subscription
// name's filters, in log order.
func (s *Store) Match(ctx context.Context, name string, after int64, limit int) ([]Delivery, error) {
	rows, err := s.db.Query(ctx, `
		SELECT e.id, e.source, e.ce_id, e.type, e.subject, e.time, e.data, e.actor, e.actor_login,
		       e.trusted, e.owner, e.hops, e.causation_id,
		       EXISTS (SELECT 1 FROM dead_letters d
		               WHERE d.subscription = s.name AND d.subject = e.subject AND d.cleared_at IS NULL)
		FROM subscriptions s JOIN events e ON e.id > $2
		WHERE s.name = $1
		  AND (cardinality(s.types) = 0 OR EXISTS (SELECT 1 FROM unnest(s.types) p WHERE starts_with(e.type, p)))
		  -- subjects are globs: escape LIKE's own wildcards, then * -> %, ? -> _
		  AND (cardinality(s.subjects) = 0 OR EXISTS (SELECT 1 FROM unnest(s.subjects) g WHERE e.subject LIKE
		       replace(replace(replace(replace(replace(g, '\', '\\'), '%', '\%'), '_', '\_'), '*', '%'), '?', '_')))
		ORDER BY e.id
		LIMIT $3`, name, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delivery, error) {
		var d Delivery
		err := r.Scan(&d.Seq, &d.Source, &d.ID, &d.Type, &d.Subject, &d.Time, &d.Data, &d.Actor, &d.ActorLogin,
			&d.Trusted, &d.Owner, &d.Hops, &d.CausationID, &d.Parked)
		return d, err
	})
}

// Head is the newest log position.
func (s *Store) Head(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM events`).Scan(&id)
	return id, err
}

// Ack moves the cursor to seq and resets the retry count.
func (s *Store) Ack(ctx context.Context, name string, seq int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE subscriptions SET last_acked_id = $2, attempts = 0, last_seen = now() WHERE name = $1`, name, seq)
	return err
}

// Fail counts one more failure of the head event and returns the total.
func (s *Store) Fail(ctx context.Context, name string) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `
		UPDATE subscriptions SET attempts = attempts + 1, last_seen = now() WHERE name = $1
		RETURNING attempts`, name).Scan(&n)
	return n, err
}

// DeadLetter records e as undeliverable to name, which parks its subject,
// and moves the cursor past it.
func (s *Store) DeadLetter(ctx context.Context, name string, e event.Event, reason string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO dead_letters (subscription, event_id, subject, reason) VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`, name, e.Seq, e.Subject, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE subscriptions SET last_acked_id = $2, attempts = 0, last_seen = now() WHERE name = $1`, name, e.Seq); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
