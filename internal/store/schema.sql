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

-- Retention (infra-bootstrap ADR-0066 §6). A deletion run records a gap on a
-- subscription that lost matching events it never acked; Subscribe sends it
-- first, and an Ack past gap_to clears it.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gap_from bigint;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gap_to   bigint;

-- One row: the log position deleted through. Replay from at or below it
-- starts with a gap.
CREATE TABLE IF NOT EXISTS retention (
    one             boolean PRIMARY KEY DEFAULT true CHECK (one),
    deleted_through bigint  NOT NULL DEFAULT 0
);
INSERT INTO retention DEFAULT VALUES ON CONFLICT DO NOTHING;

-- Deletion picks its cutoff by ingested_at, the bridge's own clock: an event's
-- time is the publisher's claim.
CREATE INDEX IF NOT EXISTS events_ingested_at ON events (ingested_at);

-- The subscription filter, shared by delivery and retention so both agree on
-- what a subscription sees. types are prefixes, subjects globs (* and ?);
-- empty matches everything.
CREATE OR REPLACE FUNCTION bridge_matches(types text[], subjects text[], t text, s text) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT (cardinality(types) = 0 OR EXISTS (SELECT 1 FROM unnest(types) p WHERE starts_with(t, p)))
       -- escape LIKE's own wildcards, then * -> %, ? -> _
       AND (cardinality(subjects) = 0 OR EXISTS (SELECT 1 FROM unnest(subjects) g WHERE s LIKE
            replace(replace(replace(replace(replace(g, '\', '\\'), '%', '\%'), '_', '\_'), '*', '%'), '?', '_')))
$$;

-- Retention looks dead letters up by subject for every event it considers.
CREATE INDEX IF NOT EXISTS dead_letters_subject ON dead_letters (subject, event_id) WHERE cleared_at IS NULL;
