// Package store is the bus's only door to Postgres (ADR-0060 §2).
package store

import (
	"bytes"
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
	// jsonb rejects \u0000, which would turn a permanent payload problem into
	// an endless 503/redelivery loop.
	// ponytail: also rewrites an escaped backslash followed by "u0000"; accepted.
	e.Data = bytes.ReplaceAll(e.Data, []byte(`\u0000`), []byte(`\ufffd`))
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

// Gap is a range of log positions deleted before a subscription acked the
// matching events in it (infra-bootstrap ADR-0066 §6).
type Gap struct{ From, To, Version int64 }

// Subscribe creates or refilters subscription name and returns its cursor,
// any gap it has not confirmed, and its gap version (stored even once confirmed). A new subscription starts at the head of
// the log: history is Replay's job.
func (s *Store) Subscribe(ctx context.Context, name string, types, subjects []string) (int64, *Gap, int64, error) {
	var cursor, ver int64
	var from, to *int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO subscriptions (name, types, subjects, last_acked_id)
		VALUES ($1, $2, $3, GREATEST((SELECT coalesce(max(id), 0) FROM events), (SELECT deleted_through FROM retention)))
		ON CONFLICT (name) DO UPDATE
		SET types = excluded.types, subjects = excluded.subjects, last_seen = now()
		RETURNING last_acked_id, gap_from, gap_to, gap_ver`, name, nonNil(types), nonNil(subjects)).Scan(&cursor, &from, &to, &ver)
	if err != nil || from == nil || to == nil {
		return cursor, nil, ver, err
	}
	return cursor, &Gap{*from, *to, ver}, ver, nil
}

// Filter returns subscription name's stored filter; found is false when it does not exist.
func (s *Store) Filter(ctx context.Context, name string) (types, subjects []string, found bool, err error) {
	err = s.db.QueryRow(ctx, `SELECT types, subjects FROM subscriptions WHERE name = $1`, name).Scan(&types, &subjects)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, false, nil
	}
	return types, subjects, err == nil, err
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
		WHERE s.name = $1 AND bridge_matches(s.types, s.subjects, e.type, e.subject)
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

// Ack moves the cursor to seq (never back: a deletion run may have moved it
// past) and resets the retry count.
func (s *Store) Ack(ctx context.Context, name string, seq int64) error {
	_, err := s.db.Exec(ctx, `
		UPDATE subscriptions SET last_acked_id = GREATEST(last_acked_id, $2), attempts = 0, last_seen = now()
		WHERE name = $1`, name, seq)
	return err
}

// ClearGap clears subscription name's gap when version is still current: the
// subscriber confirmed it resynced. current is false when a later run widened
// it (version is no longer the stored one); confirming twice is current.
func (s *Store) ClearGap(ctx context.Context, name string, version int64) (current bool, err error) {
	err = s.db.QueryRow(ctx, `
		UPDATE subscriptions SET
			gap_from = CASE WHEN gap_ver = $2 THEN NULL ELSE gap_from END,
			gap_to   = CASE WHEN gap_ver = $2 THEN NULL ELSE gap_to END
		WHERE name = $1 RETURNING gap_ver = $2`, name, version).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return current, err
}

// GapVersion is subscription name's current gap version.
func (s *Store) GapVersion(ctx context.Context, name string) (int64, error) {
	var v int64
	err := s.db.QueryRow(ctx, `SELECT gap_ver FROM subscriptions WHERE name = $1`, name).Scan(&v)
	return v, err
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
	// Only while the event still exists: a deletion run that removed it first
	// already counted it in this subscription's gap, and a dead letter for a
	// deleted event would park its subject for nothing.
	if _, err := tx.Exec(ctx, `
		INSERT INTO dead_letters (subscription, event_id, subject, reason)
		SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM events WHERE id = $2)
		ON CONFLICT DO NOTHING`, name, e.Seq, e.Subject, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE subscriptions SET last_acked_id = GREATEST(last_acked_id, $2), attempts = 0, last_seen = now()
		WHERE name = $1`, name, e.Seq); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeletedThrough is the log position retention has deleted through.
func (s *Store) DeletedThrough(ctx context.Context) (int64, error) {
	var x int64
	err := s.db.QueryRow(ctx, `SELECT deleted_through FROM retention`).Scan(&x)
	return x, err
}

// Pruned is what one deletion run did.
type Pruned struct {
	Through int64    // deleted through this position (0: nothing older than the cutoff)
	Deleted int64    // rows removed
	Moved   []string // subscriptions whose cursor moved up to Through
	Gapped  []string // of those, the ones that lost events they never acked
}

// Prune deletes the events ingested before cutoff (infra-bootstrap ADR-0066
// §6), in one transaction:
//   - X is the last such id, by ingested_at, the bridge's own clock: a
//     publisher's time could otherwise push X to the head of the log;
//   - every subscription behind X: a matching event on one of its parked
//     subjects joins its dead letters, as delivery would have done; any other
//     matching event it never acked widens its gap; its cursor moves to X;
//   - events at or past an uncleared dead letter on their subject are kept,
//     so an operator can still clear it and Replay them.
//
// The caller ends the moved subscriptions' live streams: they hold the old
// cursor in memory.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) (Pruned, error) {
	var p Pruned
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	// Lock order: dead_letters, retention, then every subscription by name
	// (DeadLetter takes dead_letters then its subscription; Ack only its
	// subscription), so nothing deadlocks. The table lock makes every
	// statement below see the same dead letters: an operator's clear or a
	// live DeadLetter waits for the run instead of landing between its steps.
	if _, err := tx.Exec(ctx, `LOCK TABLE dead_letters IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return p, err
	}
	var done int64 // the watermark only grows
	if err := tx.QueryRow(ctx, `SELECT deleted_through FROM retention FOR UPDATE`).Scan(&done); err != nil {
		return p, err
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM subscriptions ORDER BY name FOR UPDATE`); err != nil {
		return p, err
	}
	// Every run reconsiders everything older than cutoff, not only what is new
	// since the last: events kept behind a dead letter go once it is cleared.
	var x *int64
	if err := tx.QueryRow(ctx, `SELECT max(id) FROM events WHERE ingested_at < $1`, cutoff).Scan(&x); err != nil {
		return p, err
	}
	if x == nil {
		return p, tx.Commit(ctx)
	}
	p.Through = max(*x, done)
	if _, err := tx.Exec(ctx, `
		INSERT INTO dead_letters (subscription, event_id, subject, reason)
		SELECT s.name, e.id, e.subject, 'parked (retention)'
		FROM subscriptions s JOIN events e ON e.id > s.last_acked_id AND e.id <= $1
		WHERE bridge_matches(s.types, s.subjects, e.type, e.subject)
		  AND EXISTS (SELECT 1 FROM dead_letters d
		              WHERE d.subscription = s.name AND d.subject = e.subject AND d.cleared_at IS NULL)
		ON CONFLICT DO NOTHING`, p.Through); err != nil {
		return p, err
	}
	// kept: an event retention leaves in place (at or past an uncleared dead
	// letter on its subject, on any subscription). Per subscription behind X:
	// lost if a matching event it never acked or dead-lettered is deleted; its
	// cursor stops just before the first kept event it still has to receive
	// (another subscription's parked subject must not hide it), else moves to X.
	rows, err := tx.Query(ctx, `
		WITH due AS (
			SELECT s.name, s.last_acked_id AS cursor, e.id,
			       EXISTS (SELECT 1 FROM dead_letters k
			               WHERE k.subject = e.subject AND k.cleared_at IS NULL AND k.event_id <= e.id) AS kept
			FROM subscriptions s JOIN events e ON e.id > s.last_acked_id AND e.id <= $1
			WHERE bridge_matches(s.types, s.subjects, e.type, e.subject)
			  AND NOT EXISTS (SELECT 1 FROM dead_letters d WHERE d.subscription = s.name AND d.event_id = e.id)),
		behind AS (
			SELECT s.name, s.last_acked_id AS cursor,
			       coalesce((SELECT bool_or(NOT kept) FROM due WHERE due.name = s.name), false) AS lost,
			       LEAST($1, coalesce((SELECT min(id) - 1 FROM due WHERE due.name = s.name AND kept), $1)) AS next
			FROM subscriptions s WHERE s.last_acked_id < $1)
		UPDATE subscriptions s SET last_acked_id = b.next, attempts = 0,
			gap_from = CASE WHEN b.lost THEN LEAST(coalesce(s.gap_from, b.cursor + 1), b.cursor + 1) ELSE s.gap_from END,
			gap_to   = CASE WHEN b.lost THEN GREATEST(coalesce(s.gap_to, $1), $1) ELSE s.gap_to END,
			gap_ver  = CASE WHEN b.lost THEN s.gap_ver + 1 ELSE s.gap_ver END
		FROM behind b WHERE s.name = b.name AND (b.next > b.cursor OR b.lost)
		RETURNING s.name, b.lost`, p.Through)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var name string
		var lost bool
		if err := rows.Scan(&name, &lost); err != nil {
			rows.Close()
			return p, err
		}
		p.Moved = append(p.Moved, name)
		if lost {
			p.Gapped = append(p.Gapped, name)
		}
	}
	if err := rows.Err(); err != nil {
		return p, err
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM events e WHERE e.id <= $1
		  AND NOT EXISTS (SELECT 1 FROM dead_letters d
		                  WHERE d.subject = e.subject AND d.cleared_at IS NULL AND d.event_id <= e.id)`, p.Through)
	if err != nil {
		return p, err
	}
	p.Deleted = tag.RowsAffected()
	if _, err := tx.Exec(ctx, `UPDATE retention SET deleted_through = $1`, p.Through); err != nil {
		return p, err
	}
	return p, tx.Commit(ctx)
}

// Stale is one parked subject left uncleared.
type Stale struct {
	Subscription, Subject string
	Count                 int
	Since                 time.Time
}

// StaleDeadLetters lists, per subscription and subject, the uncleared dead
// letters older than age.
func (s *Store) StaleDeadLetters(ctx context.Context, age time.Duration) ([]Stale, error) {
	rows, err := s.db.Query(ctx, `
		SELECT subscription, subject, count(*), min(at) FROM dead_letters
		WHERE cleared_at IS NULL
		GROUP BY subscription, subject HAVING min(at) < now() - $1::interval
		ORDER BY subscription, subject`, fmt.Sprintf("%d seconds", int(age.Seconds())))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Stale, error) {
		var st Stale
		err := r.Scan(&st.Subscription, &st.Subject, &st.Count, &st.Since)
		return st, err
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Known reports which of ids are already in the log under any source. The
// GitHub reconcile loop uses it: delivery GUIDs are globally unique, and the
// deliveries API names the repository by id, not by the full_name in source.
func (s *Store) Known(ctx context.Context, ids []string) (map[string]bool, error) {
	rows, err := s.db.Query(ctx, `SELECT ce_id FROM events WHERE ce_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	known, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(known))
	for _, id := range known {
		m[id] = true
	}
	return m, nil
}
