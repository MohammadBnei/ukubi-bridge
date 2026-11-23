-- The bus log (ADR-0060 §2). Append-only, not partitioned, deleted by age.
CREATE TABLE IF NOT EXISTS events (
    id           bigserial   PRIMARY KEY,
    source       text        NOT NULL,
    ce_id        text        NOT NULL,
    type         text        NOT NULL,
    subject      text        NOT NULL,
    actor        text        NOT NULL,
    actor_login  text        NOT NULL DEFAULT '',
    actor_trusted boolean    NOT NULL DEFAULT false,
    thread_owned  boolean    NOT NULL DEFAULT false,
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
-- InsertAlert counts the resolves of one alert.
CREATE INDEX IF NOT EXISTS events_alert_subject ON events (subject) WHERE type LIKE 'dev.bnei.alert.%';

-- The raw ingest path of an event (event.Producer); null for rows from before it.
ALTER TABLE events ADD COLUMN IF NOT EXISTS producer jsonb;

-- Retention (infra-bootstrap ADR-0066 §6). A deletion run records a gap on a
-- subscription that lost matching events it never acked; Subscribe sends it
-- first, and the subscriber's ConfirmGap (with gap_ver) clears it.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gap_from bigint;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gap_to   bigint;
-- Bumped whenever a run records or widens the gap: only a confirmation of the
-- current version clears it.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS gap_ver  bigint NOT NULL DEFAULT 0;
UPDATE subscriptions SET gap_ver = 1 WHERE gap_from IS NOT NULL AND gap_ver = 0; -- versions start at 1

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

-- agent-fleet ADR-0082 §12 (2026-11-02): one `trusted` bit became two facts.
-- A logged event that was trusted had both; one that was not keeps neither
-- (lossy, never more trust than it had). Idempotent: a no-op once done.
ALTER TABLE events ADD COLUMN IF NOT EXISTS actor_trusted boolean NOT NULL DEFAULT false;
ALTER TABLE events ADD COLUMN IF NOT EXISTS thread_owned boolean NOT NULL DEFAULT false;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
              WHERE table_schema = current_schema() AND table_name = 'events' AND column_name = 'trusted') THEN
    UPDATE events SET actor_trusted = true, thread_owned = true WHERE trusted;
    ALTER TABLE events DROP COLUMN trusted;
  END IF;
END
$$;

-- The Forgejo relist loop's cursor, per watched repo: where its last good run
-- started (internal/forgejo/relist.go).
CREATE TABLE IF NOT EXISTS forge_relist (
    repo  text        PRIMARY KEY,
    since timestamptz NOT NULL
);

-- System tags (conception §5, §6): atlas computes them as a bridge client and
-- attaches them with Tag; the bridge stores them, never computes one, and
-- never writes a System into the event. One row per event, System and
-- registry version: a new version tags the event again. Retention deletes an
-- event's tags with it.
CREATE TABLE IF NOT EXISTS event_tags (
    event_id         bigint      NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    system           text        NOT NULL,
    -- The cascade rung (no namespace rung), or no answer.
    resolution       text        NOT NULL
        CHECK (resolution IN ('applied', 'tracked', 'placement', 'manager', 'ambiguous', 'unresolved')),
    registry_version text        NOT NULL CHECK (registry_version <> ''),
    tagged_at        timestamptz NOT NULL DEFAULT now(),
    tagger           text        NOT NULL, -- the client that tagged
    PRIMARY KEY (event_id, system, registry_version),
    CHECK ((system = '') = (resolution = 'unresolved'))
);
-- Arrival order, assigned at insert and kept when a re-tag replaces the row:
-- an event's current version is the one whose first row arrived last, so a
-- late retry of an older version never makes it current again.
-- ponytail: insert order, not commit order: two concurrent Tag calls for one
-- event with different versions are ordered by when each inserted. Have atlas
-- send an ordered registry generation if that ever matters.
ALTER TABLE event_tags ADD COLUMN IF NOT EXISTS arrival bigserial;

CREATE OR REPLACE FUNCTION bridge_tag_version(event_id bigint) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT registry_version FROM event_tags WHERE event_tags.event_id = $1
    GROUP BY registry_version ORDER BY min(arrival) DESC LIMIT 1
$$;

-- A subscription's System filter: empty matches everything, else an event
-- needs a row of its current version naming one of the systems at resolution
-- applied, or at one of the resolutions the subscription opted into (never
-- ambiguous or unresolved). Delivery and retention both read it, as
-- bridge_matches.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS systems text[] NOT NULL DEFAULT '{}';
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS resolutions text[] NOT NULL DEFAULT '{}';
DROP FUNCTION IF EXISTS bridge_tagged(text[], bigint); -- before resolutions
CREATE OR REPLACE FUNCTION bridge_tagged(systems text[], resolutions text[], event_id bigint) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT cardinality(systems) = 0 OR EXISTS (SELECT 1 FROM event_tags t
        WHERE t.event_id = $3 AND t.system = ANY ($1)
          AND t.resolution = ANY ($2 || 'applied'::text) AND t.resolution NOT IN ('ambiguous', 'unresolved')
          AND t.registry_version = bridge_tag_version($3))
$$;
-- An event a System-filtered subscription cannot judge yet: it has no tag at
-- all. Delivery holds it for the grace window, then gaps it; retention counts
-- it as the subscription's loss. Never skipped in silence.
CREATE OR REPLACE FUNCTION bridge_untagged(systems text[], event_id bigint) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT cardinality(systems) > 0 AND NOT EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = $2)
$$;
