-- The bus log (ADR-0059 §2). Append-only, not partitioned, deleted by age.
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
