-- The bus log (ADR-0060 §2). Append-only, not partitioned, deleted by age.
CREATE TABLE IF NOT EXISTS events (
    id           bigserial   PRIMARY KEY,
    source       text        NOT NULL,
    ce_id        text        NOT NULL,
    type         text        NOT NULL,
    subject      text        NOT NULL,
    actor        text        NOT NULL,
    actor_login  text        NOT NULL DEFAULT '',
    trusted      boolean     NOT NULL,
    owner        text        NOT NULL DEFAULT '',
    hops         integer     NOT NULL DEFAULT 0,
    causation_id text        NOT NULL DEFAULT '',
    replayed     boolean     NOT NULL DEFAULT false,
    data         jsonb       NOT NULL,
    time         timestamptz NOT NULL,
    ingested_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source, ce_id)
);

-- One row per named subscriber (ADR-0060 §2). types are prefixes, subjects
-- globs; empty matches everything. attempts counts Nacks of the head event.
CREATE TABLE IF NOT EXISTS subscriptions (
    name          text        PRIMARY KEY,
    types         text[]      NOT NULL DEFAULT '{}',
    subjects      text[]      NOT NULL DEFAULT '{}',
    last_acked_id bigint      NOT NULL DEFAULT 0,
    attempts      integer     NOT NULL DEFAULT 0,
    last_seen     timestamptz NOT NULL DEFAULT now()
);

-- An uncleared row parks its subject for that subscription: later events on
-- the subject land here too, so per-thread order survives a poison event.
-- No FK to events: the log is deleted by age, dead letters are kept.
CREATE TABLE IF NOT EXISTS dead_letters (
    subscription text        NOT NULL REFERENCES subscriptions (name) ON DELETE CASCADE,
    event_id     bigint      NOT NULL,
    subject      text        NOT NULL,
    reason       text        NOT NULL,
    at           timestamptz NOT NULL DEFAULT now(),
    cleared_at   timestamptz,
    PRIMARY KEY (subscription, event_id)
);
CREATE INDEX IF NOT EXISTS dead_letters_parked ON dead_letters (subscription, subject) WHERE cleared_at IS NULL;

-- The GitHub reconcile loop looks deliveries up by GUID alone.
CREATE INDEX IF NOT EXISTS events_ce_id ON events (ce_id);
