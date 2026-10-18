// Package store is the bus's only door to Postgres (ADR-0059 §2).
package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/MohammadBnei/ukubi-bridge/internal/event"
)

//go:embed schema.sql
var schema string

// insertLock serialises inserts so event ids commit in id order and a
// subscriber cursor can never skip a row that commits late.
// ponytail: one global lock; move to an xmin-horizon cursor if throughput matters.
const insertLock = 0x6272696467650001 // "bridge" + 1

type Store struct{ db *pgxpool.Pool }

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
	return &Store{db: db}, nil
}

func (s *Store) Close() { s.db.Close() }

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
	return true, tx.Commit(ctx)
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
