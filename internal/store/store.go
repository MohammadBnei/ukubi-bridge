// Package store is the bus's only door to Postgres (ADR-0060 §2).
package store

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MohammadBnei/ukubi-bridge/internal/contract"
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
	// ponytail: idempotent DDL at boot, upgrades included (schema.sql); a
	// migration tool once an upgrade cannot be written idempotently.
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
	return s.insert(ctx, e, nil)
}

// InsertAlert stores an alert event whose ID is the base fingerprint:status:startsAt
// and appends its episode (ADR-0092): the number of resolved events already stored
// for that fingerprint and startsAt. A firing that returns after a resolve is a new
// episode, so UNIQUE(source, ce_id) keeps it; retries and repeat notifications of
// the same state compute the same id and dedup. A resolved closes the latest stored
// firing episode, so its retry computes the same number. Ids stored before episodes
// existed (no suffix) count as episode 0: their retries dedup.
// Race-free: the episode is read inside insert's transaction, after the global advisory lock.
// ponytail: a late retry of a firing after its resolve reads as a re-fire and is stored once more;
// the payloads are identical, so the two cannot be told apart.
func (s *Store) InsertAlert(ctx context.Context, e event.Event) (bool, error) {
	return s.insert(ctx, e, func(tx pgx.Tx, e *event.Event) (bool, error) {
		var d struct {
			StartsAt string `json:"startsAt"`
		}
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return false, err
		}
		fp := strings.TrimPrefix(e.Subject, "alert/")
		exists := func(id string) (ok bool, err error) {
			err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE source = $1 AND ce_id = $2)`,
				e.Source, id).Scan(&ok)
			return
		}
		var resolved int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE source = $1 AND subject = $2
			AND type = 'dev.bnei.alert.resolved' AND data->>'startsAt' = $3`,
			e.Source, e.Subject, d.StartsAt).Scan(&resolved); err != nil {
			return false, err
		}
		ep := resolved
		if e.Type == "dev.bnei.alert.resolved" && ep > 0 {
			open, err := exists(fp + ":firing:" + d.StartsAt + ":" + strconv.Itoa(ep))
			if err != nil {
				return false, err
			}
			if !open {
				ep-- // the last resolve is already stored: this is its retry
			}
		}
		if ep == 0 {
			if old, err := exists(e.ID); err != nil || old {
				return old, err
			}
		}
		e.ID += ":" + strconv.Itoa(ep)
		return false, nil
	})
}

func (s *Store) insert(ctx context.Context, e event.Event, prep func(pgx.Tx, *event.Event) (bool, error)) (bool, error) {
	// jsonb rejects \u0000, which would turn a permanent payload problem into
	// an endless 503/redelivery loop.
	// ponytail: also rewrites an escaped backslash followed by "u0000"; accepted.
	e.Data = bytes.ReplaceAll(e.Data, []byte(`\u0000`), []byte(`\ufffd`))
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(insertLock)); err != nil {
		return false, err
	}
	if prep != nil {
		if dup, err := prep(tx, &e); err != nil || dup {
			return false, err
		}
	}
	var id int64
	err = tx.QueryRow(ctx, `
		INSERT INTO events (source, ce_id, type, subject, actor, actor_login, actor_trusted, thread_owned,
		                    owner, hops, causation_id, replayed, data, time, producer)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (source, ce_id) DO NOTHING
		RETURNING id`,
		e.Source, e.ID, e.Type, e.Subject, e.Actor, e.ActorLogin, e.ActorTrusted, e.ThreadOwned,
		e.Owner, e.Hops, e.CausationID, e.Replayed, e.Data, e.Time, e.Producer).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, notifyChannel); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	// The one ingest choke point: logged once per stored event (the chart's Loki rule alerts on this line).
	if contract.Flags(e.Type) != nil {
		slog.Warn("event type uncontracted", "type", e.Type, "source", e.Source, "producer", string(e.Producer))
	}
	return true, nil
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

// Filter is what a subscription sees: types are prefixes, subjects globs,
// systems and resolutions the System filter (schema.sql, bridge_tagged).
type Filter struct{ Types, Subjects, Systems, Resolutions []string }

// Subscribe creates or refilters subscription name and returns its cursor,
// any gap it has not confirmed, and its gap version (stored even once confirmed). A new subscription starts at the head of
// the log: history is Replay's job.
func (s *Store) Subscribe(ctx context.Context, name string, f Filter) (int64, *Gap, int64, error) {
	var cursor, ver int64
	var from, to *int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO subscriptions (name, types, subjects, systems, resolutions, last_acked_id)
		VALUES ($1, $2, $3, $4, $5, GREATEST((SELECT coalesce(max(id), 0) FROM events), (SELECT deleted_through FROM retention)))
		ON CONFLICT (name) DO UPDATE
		SET types = excluded.types, subjects = excluded.subjects, systems = excluded.systems,
		    resolutions = excluded.resolutions, last_seen = now()
		RETURNING last_acked_id, gap_from, gap_to, gap_ver`,
		name, nonNil(f.Types), nonNil(f.Subjects), nonNil(f.Systems), nonNil(f.Resolutions)).Scan(&cursor, &from, &to, &ver)
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
	Parked bool  // its subject has an uncleared dead letter for this subscription
	Tags   []Tag // its current tag set: the rows of its current registry version
	// Untagged: the subscription has a System filter and the event no tag
	// yet, so it can be neither delivered nor passed over (bridge_untagged).
	Untagged   bool
	IngestedAt time.Time
}

// Match returns up to limit events after cursor that match subscription
// name's filters, in log order, and, for a System filter, the untagged events
// among them (Delivery.Untagged).
func (s *Store) Match(ctx context.Context, name string, after int64, limit int) ([]Delivery, error) {
	rows, err := s.db.Query(ctx, `
		SELECT e.id, e.source, e.ce_id, e.type, e.subject, e.time, e.data, e.actor, e.actor_login,
		       e.actor_trusted, e.thread_owned, e.owner, e.hops, e.causation_id,
		       EXISTS (SELECT 1 FROM dead_letters d
		               WHERE d.subscription = s.name AND d.subject = e.subject AND d.cleared_at IS NULL),
		       bridge_untagged(s.systems, e.id), e.ingested_at, coalesce(cur.v, ''),
		       ARRAY(SELECT t.system FROM event_tags t WHERE t.event_id = e.id AND t.registry_version = cur.v ORDER BY t.system),
		       ARRAY(SELECT t.resolution FROM event_tags t WHERE t.event_id = e.id AND t.registry_version = cur.v ORDER BY t.system)
		FROM subscriptions s JOIN events e ON e.id > $2
		CROSS JOIN LATERAL (SELECT bridge_tag_version(e.id) AS v) cur
		WHERE s.name = $1 AND bridge_matches(s.types, s.subjects, e.type, e.subject)
		  AND (bridge_tagged(s.systems, s.resolutions, e.id) OR bridge_untagged(s.systems, e.id))
		ORDER BY e.id
		LIMIT $3`, name, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Delivery, error) {
		var d Delivery
		var version string
		var systems, resolutions []string
		err := r.Scan(&d.Seq, &d.Source, &d.ID, &d.Type, &d.Subject, &d.Time, &d.Data, &d.Actor, &d.ActorLogin,
			&d.ActorTrusted, &d.ThreadOwned, &d.Owner, &d.Hops, &d.CausationID, &d.Parked,
			&d.Untagged, &d.IngestedAt, &version, &systems, &resolutions)
		for i := range systems {
			d.Tags = append(d.Tags, Tag{Seq: d.Seq, System: systems[i], Resolution: resolutions[i], RegistryVersion: version})
		}
		return d, err
	})
}

// GapUntagged moves subscription name past the untagged event at seq once its
// grace window has passed, and past every event after it up to the next one
// it can deliver or still has to wait for (tagged for it, or untagged and
// within grace), and records them as its gap, as retention does: the
// subscriber sees it on its next Subscribe and confirms it. false when seq
// was tagged meanwhile (Match again). An event in the gap may be tagged
// later: Replay finds it then.
func (s *Store) GapUntagged(ctx context.Context, name string, seq int64, grace time.Duration) (bool, error) {
	tag, err := s.db.Exec(ctx, `
		WITH next AS (
			SELECT min(e.id) AS id FROM subscriptions s JOIN events e ON e.id > $2
			WHERE s.name = $1 AND bridge_matches(s.types, s.subjects, e.type, e.subject)
			  AND (bridge_tagged(s.systems, s.resolutions, e.id)
			       OR (bridge_untagged(s.systems, e.id) AND e.ingested_at > now() - $3 * interval '1 second'))),
		through AS (SELECT coalesce((SELECT id - 1 FROM next), (SELECT max(id) FROM events), $2) AS id)
		UPDATE subscriptions u SET last_acked_id = GREATEST(u.last_acked_id, t.id), attempts = 0, last_seen = now(),
			gap_from = LEAST(coalesce(u.gap_from, $2), $2),
			gap_to   = GREATEST(coalesce(u.gap_to, t.id), t.id),
			gap_ver  = u.gap_ver + 1
		FROM through t WHERE u.name = $1 AND bridge_untagged(u.systems, $2)`, name, seq, grace.Seconds())
	return tag.RowsAffected() == 1, err
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
	// Writes only when there is something to clear; a repeat or a stale
	// version is answered by a read, without locking the row.
	tag, err := s.db.Exec(ctx, `
		UPDATE subscriptions SET gap_from = NULL, gap_to = NULL
		WHERE name = $1 AND gap_ver = $2 AND gap_from IS NOT NULL`, name, version)
	if err != nil || tag.RowsAffected() == 1 {
		return err == nil, err
	}
	err = s.db.QueryRow(ctx, `SELECT gap_ver = $2 FROM subscriptions WHERE name = $1`, name, version).Scan(&current)
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
	defer func() { _ = tx.Rollback(ctx) }()
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
	defer func() { _ = tx.Rollback(ctx) }()
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
		WHERE bridge_matches(s.types, s.subjects, e.type, e.subject) AND bridge_tagged(s.systems, s.resolutions, e.id)
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
			  -- an untagged event counts: never tagged is never a silent skip
			  AND (bridge_tagged(s.systems, s.resolutions, e.id) OR bridge_untagged(s.systems, e.id))
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

// RelistCursor is where the Forgejo relist loop's last good run for repo
// started; zero if it never ran.
func (s *Store) RelistCursor(ctx context.Context, repo string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(ctx, `SELECT since FROM forge_relist WHERE repo = $1`, repo).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	return t, err
}

// SetRelistCursor stores repo's cursor.
func (s *Store) SetRelistCursor(ctx context.Context, repo string, t time.Time) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO forge_relist (repo, since) VALUES ($1, $2)
		ON CONFLICT (repo) DO UPDATE SET since = excluded.since`, repo, t)
	return err
}

// Tag is one System tag on a logged event (bridge.v1.EventTag).
type Tag struct {
	Seq                                 int64
	System, Resolution, RegistryVersion string
}

// ErrNoEvent: a tag names a log position that holds no event (never, or no
// longer: retention deleted it).
var ErrNoEvent = errors.New("no event at that position")

// Tag stores tags as tagger's, all or none: one for the same event, System and
// registry version replaces the earlier. The schema checks the values; Invalid
// reports a refusal. It wakes the streams, so a System filter sees the event.
func (s *Store) Tag(ctx context.Context, tagger string, tags []Tag) error {
	seqs := make([]int64, len(tags))
	systems, resolutions, versions := make([]string, len(tags)), make([]string, len(tags)), make([]string, len(tags))
	for i, t := range tags {
		seqs[i], systems[i], resolutions[i], versions[i] = t.Seq, t.System, t.Resolution, t.RegistryVersion
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO event_tags (event_id, system, resolution, registry_version, tagger)
		-- ponytail: a request naming one (event, System, version) twice keeps either.
		SELECT DISTINCT ON (seq, sys, ver) seq, sys, res, ver, $5
		FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) AS t (seq, sys, res, ver)
		-- arrival is kept: a re-sent version does not become current again
		ON CONFLICT (event_id, system, registry_version) DO UPDATE
		SET resolution = excluded.resolution, tagger = excluded.tagger, tagged_at = now()`,
		seqs, systems, resolutions, versions, tagger)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23503" { // foreign_key_violation
		return fmt.Errorf("%w: %s", ErrNoEvent, pg.Detail)
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `SELECT pg_notify($1, '')`, notifyChannel)
	return err
}
