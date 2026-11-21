# ukubi-bridge

The event bus of the `ukubi-cluster` homelab: a Postgres-backed CloudEvents log
that feeds agent-fleet's agents and, later, apps. The design is
[infra-bootstrap ADR-0060](https://github.com/MohammadBnei/infra-bootstrap/blob/main/docs/adr/0060-event-bridge.md);
agent-fleet's side is its ADR-0071 (dispatch) and ADR-0072 (approval-gated executor).

## What it does today

- `POST /webhook/github` — GitHub App deliveries. HMAC-verified, filtered to
  `pull_request` (opened/synchronize/closed/reopened/labeled), `issues`
  (opened/labeled), `issue_comment` (created) and `pull_request_review`
  (submitted), normalised to the envelope in `internal/event`, appended to
  `events` once per `X-GitHub-Delivery`. Two trust facts (agent-fleet ADR-0082
  §12): `actor_trusted`, the actor (the opener on `opened`, the sender
  otherwise, the comment or review author) is in `BRIDGE_TRUSTED_LOGINS`; and
  `thread_owned`, the PR's or issue's author is a trusted login or a fleet
  agent, and a PR's head is in the same repo. The head repo is only in
  `pull_request` and `pull_request_review` payloads, so a comment on a fork PR
  can read owned. The webhook must subscribe to Issues and Pull requests.
- `POST /webhook/forgejo` — Forgejo webhook deliveries (type Forgejo, content
  type `application/json`), on only when `BRIDGE_FORGEJO_WEBHOOK_SECRET` is
  set. `X-Forgejo-Signature` (hex HMAC-SHA256 of the body) is checked, then
  `X-Forgejo-Event-Type` picks the event: `pull_request`
  (opened/synchronized/closed/reopened/label_updated), `issues`
  (opened/label_updated), `issue_comment` (created, on an issue or a PR), the
  three review types as `pull_request_review.approved|rejected|comment`, and
  `action_run.success|failure|recover`; anything else is a 204. Type
  `dev.bnei.forge.<event>.<action>`, source `git.bnei.dev/<owner>/<repo>`,
  subject `forge/<owner>/<repo>/pr|issue/<n>`,
  or `forge/<owner>/<repo>/run/<n>` for a run (its number in the repo, as in
  its URL). The trust facts follow the GitHub rules, on their own logins
  (`BRIDGE_FORGEJO_TRUSTED_LOGINS`, `BRIDGE_FORGEJO_AGENT_LOGINS`: a name
  listed for one forge is never trusted or an agent on the other). A run's
  actor and owner are its trigger user, and a fork PR's run is never owned.
  Forgejo puts the PR in a comment's payload, so a comment on a fork PR reads
  not owned here, and a PR comment without that PR reads not owned too.
  `ce_id` is the fact's own key wherever the relist loop below can see the
  fact, so its delivery and its relisted copy are one event (`forgejo.factID`):
  `pr/<n>/opened`, `pr/<n>/closed/<closed_at unix>` (a merge too),
  `issue/<n>/opened`, `comment/<comment id>`, and for an approval or a
  change request
  `pr/<n>/review/<approved|rejected>/<reviewer>/<head sha>/<sha256(text)[:8] hex>`
  (a review delivery has no review id: one submitted on a head that moved
  before it landed is stored twice, and the same verdict with the same text
  by one reviewer on one head is stored once). A COMMENT review is **not**
  content-keyed: Forgejo submits each single inline code comment as its own
  empty COMMENT review, which a content key would drop as the previous one's
  duplicate. Its delivery keeps `X-Forgejo-Delivery`; its relisted copy is
  `pr/<n>/review/comment/<review id>`, so the relist loop stores a COMMENT
  review the webhook already stored a second time (the recovery path may
  duplicate; the live one never drops). Every other event keeps
  `X-Forgejo-Delivery` as its `ce_id`: synchronized, reopened, label_updated
  and runs, none of which the loop recovers. A closed delivery without
  `pull_request.closed_at` keeps its delivery id too, logged at WARN: its
  relisted copy would be stored again. A manual redelivery of one of
  those gets a new `X-Forgejo-Delivery`, so redeliver only a delivery marked
  failed, or it is stored twice. Not reachable yet: Forgejo runs outside
  the cluster and the IngressRoute carries only `/webhook/github` (see Not yet).
- GitHub reconcile: every 10 minutes the App lists its webhook deliveries back
  to the lookback window and redelivers, oldest first, each one not in
  `events` — failed (bridge downtime) or acknowledged with 202 (lost to a
  Pigsty failover). A 204 (ignored type) is never checked. A GUID the bridge
  rejected (4xx) 5 times, or whose original delivery has left the
  `BRIDGE_RECONCILE_LOOKBACK` window (default 6h), is given up on and logged.
  An outage (5xx, timeout) is retried until then, so a longer outage needs a
  manual redelivery from the App's log, which GitHub keeps for 3 days. A 403/429 ends the run; the next tick tries again.
- Forgejo relist: Forgejo neither retries nor lists its deliveries, so every
  10 minutes the bridge lists, per repo in `BRIDGE_FORGEJO_RELIST_REPOS` (off
  when empty), the PRs (newest update first), issues and comments updated
  since the repo's cursor, and each listed PR's reviews, and inserts, oldest
  first, the facts above that happened since: an opened PR or issue, a closed
  or merged PR, a comment, a submitted review. The `(source, ce_id)` dedup
  drops what the webhook already stored. Its data is the webhook's payload
  shape rebuilt from the API objects as they are now, with `"relisted": true`
  and Forgejo's own `repository.full_name` (whatever case the repo is listed
  in); a comment's `issue` is the listed issue, or for a PR's comment the PR
  object (number, user, title, body, html_url, state), not the webhook's
  issue view of it. A relisted fact is **never `actor_trusted`**: its text
  may have been edited since by anyone with write access (a fleet agent too),
  so the author's trust cannot vouch for it; `thread_owned` keeps the
  thread author's rules. An unmerged close names no sender (actor empty).
  Pages after the first go to `BRIDGE_FORGEJO_URL`'s host, whatever host
  Forgejo's `Link` header names (its ROOT_URL). The cursor
  (`forge_relist`, where the repo's last good run started) survives restarts;
  each window starts 5 minutes before it, and never further back than
  `BRIDGE_RETENTION`; a repo's first run looks back 6 hours. A repo that fails
  keeps its cursor and is retried on the next tick. So does a run whose PR
  list shifted while it was paged (a page repeats a PR: one updated mid-run
  jumped to page 1, and the PR it pushed past may have been skipped).
- `POST /webhook/alertmanager` and `POST /webhook/grafana` — bearer token,
  one event per alert: `ce_id` = `fingerprint:status:startsAt`, so a
  `repeat_interval` resend of the same firing coalesces while its resolution
  is a new event. Type `dev.bnei.alert.firing|resolved`, subject
  `alert/<fingerprint>`, `actor=machine`, neither trust fact. 503 when the store is
  down, so the sender retries.
- `GET /healthz`.
- `bridge.v1.BridgeService` (Connect, gRPC and gRPC-Web on the same port,
  `proto/bridge/v1/bridge.proto`). Internal only: the public IngressRoute is
  scoped to the webhook path.
  - Every call carries an authentik access token (`Authorization: Bearer`):
    RS256, signed by the pinned certificate, issuer and client id of the
    `ukubi-bridge-api` provider, not expired. Its `sub` (the
    authentik service account) names the client in `BRIDGE_API_CLIENTS`
    (infra-bootstrap ADR-0066).
  - `Publish` — appends one event, deduplicated on `(source, id)`. The source
    is always `client/<name>`. A client publishes only types under its
    `publish_types` and subjects under its `publish_subjects`, so an app
    cannot post onto another source's thread (a GitHub PR, say). Negative
    `hops` is refused. An event Postgres cannot store (a NUL byte in a
    string field) is `InvalidArgument` (`\u0000` in `data` is stored as `\ufffd`); `Unavailable` always means retry.
    A non-privileged client's event is stamped with its own `kind` as actor and its name as `actor_login`, neither trust fact, no
    `owner`, and `hops` one above what it sent (`causation_id` kept). Only a
    `privileged` client (agent-fleet core) sets actor, `actor_trusted`, owner and hops; nobody publishes `thread_owned`, a GitHub fact.
    Nobody sets `replayed`.
  - `Subscribe(name, types, subjects, systems, resolutions)` — `name` is the client's own name or
    `<name>/<suffix>`. The whole filter must fit one of the client's
    `subscribe` rules, and `types` cannot be empty. `systems` (optional) only
    narrows it: an event matches once a tag of its current registry version
    (the version whose first tag arrived last: a new version supersedes the
    older one's rows, which stay stored) names one of them at `applied`.
    Only `applied` routes a wake by default; `resolutions` opts into
    `tracked`, `placement` or `manager` as well (anything else, or
    `resolutions` without `systems`, is `InvalidArgument`
    `subscribe.resolution_invalid`); `ambiguous` and `unresolved` never
    match. Every event message carries the event's current tag set (`tags`:
    system, resolution, registry version; empty when untagged), filtered
    subscription or not, so check the resolution before acting. A System
    filter never skips an event in silence: when the next event in log order
    (by types and subjects) has no tag yet, the stream holds it, head of line,
    for `BRIDGE_TAG_GRACE` (default 60 s) from its ingestion; then it moves
    past it and every later untagged event whose window has passed too,
    records them as a gap and ends `Aborted` (`stream.gapped`): the reconnect
    gets the gap first, as after retention, and `ConfirmGap` clears it. A tag
    that lands after the stream moved past its event (a late re-tag, or one
    in the gap) is not delivered, though `Replay` sees it. Retention counts a
    gap with the same filter, untagged events included. The stream ends
    `Unauthenticated` at the token's expiry: reconnect with a fresh token (the
    cursor is kept; an event in flight is redelivered, as after any
    disconnect). A token with less than 5 s left cannot open a stream, so
    refresh earlier than that (golang.org/x/oauth2's 10 s default does). A new subscription starts at the head of the log.
    Delivery is head-of-line: the next matching event is sent only once the
    current one is acked. A NOTIFY sent inside each insert wakes the stream;
    it also polls every 30 s. A second `Subscribe` on the same name replaces
    the first.
  - `Ack(subscription, seq)` / `Nack(subscription, seq, reason)` — only the
    event in flight. A Nack retries after 1 s, 2 s, 4 s, 8 s; the fifth
    dead-letters it, which **parks its subject** for that subscription: later
    events on the subject go straight to `dead_letters` too, so a thread is
    never processed out of order.
  - `ConfirmGap(subscription, version)` — clears a gap once resynced (see
    Retention).
  - `Tag(tags)` — attaches System tags to logged events, only for a client
    with `tag` (atlas, which computes them: the bridge stores tags and never
    resolves one, so it never imports mountain). Each tag is `seq`, `system`
    (empty exactly when unresolved), `resolution` (`applied`, `tracked`,
    `placement`, `manager`, `ambiguous` or `unresolved`; there is no namespace
    rung) and `registry_version` (required), stored in `event_tags` with the
    client's name as `tagger` and `tagged_at`, never in the event. All or
    none: a seq that holds no event (retention deleted it) is `NotFound`, a
    value the schema refuses, an empty batch, more than 1000 tags or a
    `system` or `registry_version` over 256 bytes is `InvalidArgument`. A tag
    for the same seq, System and registry version replaces the earlier one's
    resolution and keeps its place; a new registry version adds rows and
    becomes the event's current tag set. Which version is current is decided
    by arrival (`event_tags.arrival`, the order rows were first inserted), so
    a late retry of an older version never makes it current again; two
    concurrent calls with different versions are ordered by insert, not
    commit. Retention deletes an event's tags with it. A tag wakes the
    streams, so a System filter sees its event at once.
  - `Replay(subscription, from_seq)` — streams the subscription's matching
    events from `from_seq` to the current head with `replayed=true`, after
    checking the stored filter still fits the client's rules (`NotFound` for a
    subscription never created by `Subscribe`). Bounded by the token like
    `Subscribe`. No ack,
    no cursor change, nothing written. Subscribers must be idempotent on
    `(source, id)` (or `seq`, which is the same event's log position) — never
    on `id` alone: two clients can both publish id `1`. From at or below the
    retention watermark, the first message is a `gap` (see Retention). Each
    event carries its current `tags`, as on `Subscribe`; a System-filtered
    subscription's replay never waits, and leaves out events still untagged.

### Retention

Every hour the bridge deletes events ingested more than `BRIDGE_RETENTION`
ago (default 30 days), by `ingested_at`, never by the publisher's `time`
(infra-bootstrap ADR-0066 §6). In the same transaction:

- An event at or past an uncleared dead letter on its subject is **kept**, so
  the operator can still unpark it and `Replay` it. A subscription that still
  has to receive a kept event (its subject is parked for someone else) keeps
  its cursor just before it.
- Every other subscription behind the deleted range moves its cursor past it,
  so a quiet subscription never falls behind.
- A subscription that loses a matching event it never acked records a **gap**
  (widened by later runs, never replaced). Its next `Subscribe` sends one
  message carrying `gap {from_seq, to_seq, version}` before any event: resync
  from your own source of truth, then call `ConfirmGap(subscription,
  version)`. Its live stream ends
  `Aborted`, so it reconnects to that gap (also when a run gaps it while it is
  connecting). The gap is sent on every reconnect until confirmed; a run that
  widens it bumps `version`, so confirming an older one is `FailedPrecondition`
  (reconnect for the current one). Confirming twice is fine, also after the
  stream ended (a resync may outlast a token); confirming a version no stream
  was sent is refused. An Ack never moves a
  cursor back. A stream replaced by a newer `Subscribe` on the same name ends
  cleanly: do not reconnect on that.
- A dead letter is never recorded for an event already deleted.
- Each subject left parked for 3 days is logged once per run (`dead letter
  uncleared`), and a failed run logs one `retention failed` line: the chart's
  Loki rules alert on both, matching those words. The bridge logs one JSON
  object per line on stdout (time, level, msg, attributes).

The run locks `dead_letters` for its duration, so an unparking `UPDATE` or a
live dead-lettering waits for it. Clients written before gaps existed must
handle a message whose `event` is unset (there are none yet: nothing calls the
API before agent-fleet's dispatcher).

Dedup on `(source, id)` holds only within retention: an id published again
after its event was deleted is a new event.

Not yet:

- An API for dead letters.
- Forgejo: a route from Forgejo (CT 305, outside the cluster) to
  `/webhook/forgejo`, such as an internal-only IngressRoute locked to the
  Forgejo host; the webhook's registration and Forgejo's `ALLOWED_HOST_LIST`;
  the relist loop's token Secret (`ukubi-bridge-forgejo-token`, key `token`:
  the chart mounts it, optional, at `/var/run/secrets/forgejo`, and its repo
  list is empty) rendered by infra-bootstrap; relisting pushes
  (synchronized), reopens, label changes and runs.
- System tags: the authentik `bridge-atlas` service account (kind machine,
  the only `tag` client in the chart's table) and atlas itself; until then no
  event is tagged and a System-filtered subscription gaps every event it
  sees after the grace window.
- A live API client. No client can call until `BRIDGE_OIDC_CERT` is set and
  the authentik `ukubi-bridge-api` provider exists (infra-bootstrap
  ADR-0066). agent-fleet's consumer is its `core/internal/dispatch` (its
  ADR-0071).

ADR-0071 §6's "drop events caused by the thread's own agent identity" is not
done here: the bridge has no thread ownership. Core's dispatcher never lets
one wake a session (an agent's GitHub login is never a trusted actor), but it is still
delivered as context or filed as a proposal, not dropped. Only `PublishEvent`
hand-offs count toward its per-thread agent-wake cap.

### Unparking a subject

Nothing exposes this yet. Retention keeps parked events only while their dead
letters are uncleared, and new events on the subject keep parking until it is
unparked, so work in rounds. Fix the subscriber, then:

1. Note the subject's uncleared dead letters:
   `SELECT min(event_id), max(event_id) FROM dead_letters WHERE subscription = 'bridge-core' AND subject = 'github/MohammadBnei/editable-blog/pr/42' AND cleared_at IS NULL;`
2. `Replay` from that `min`, and let the subscriber handle the events up to
   that `max` (idempotent on `(source, id)`). If the parked events are older
   than the watermark, Replay's first message is a `gap`: here it only says
   other events in that range may be gone; the parked ones follow.
3. Clear only what was replayed:

   ```sql
   UPDATE dead_letters SET cleared_at = now()
   WHERE subscription = 'bridge-core' AND subject = 'github/MohammadBnei/editable-blog/pr/42'
     AND cleared_at IS NULL AND event_id <= <max from step 1>;
   ```
4. Repeat from 1 until step 1 finds nothing: events that parked during the
   round are still uncleared, so they are neither lost nor deleted.

Once cleared, the next retention run deletes those events if they are old.

## Errors

Every error a BridgeService handler returns carries Connect's code, the same words as before, and an
`ErrorKey {key, source}` detail (mountain plan/15 §4): a client branches on the code and the key, never on the
message. `source` is `store` when the message is the store's words (pgx's or Postgres's), empty for the bridge's.
An unreadable unary request, an unknown procedure or a client's own timeout carries no key: Connect raises it before a
handler runs. A stream's (Subscribe, Replay) unreadable request is keyed `server.internal`, with Connect's code.

The key rides twice, as two details with the same fields and the same value bytes: `bridge.v1.ErrorKey` first, then
`ukubi.errors.v1.ErrorKey` (from ukubi-go, the shared name; standard §6). A client reads either, by its type, not
its position (an error the fallback keys may carry other details between them); each skips a detail it does not know.
In the Connect protocol's error body (JSON, whatever the codec) each is a `{type, value, debug}` entry of `details`; over gRPC and gRPC-Web, an `Any` in `grpc-status-details-bin`. `bridge.v1.ErrorKey` goes only once no client reads it.
The keys and the fallback that keys an unkeyed error `server.internal` are ukubi-go's `errs/connectkeys`, installed
outermost. The registry is closed, in `internal/bus/errkeys.go`:

| Key | Meaning |
|---|---|
| `auth.bearer_required` | no `Authorization: Bearer` header |
| `auth.token_invalid` | the token failed verification (signature, issuer, audience, claims) |
| `auth.no_key_pinned` | the bridge has no `BRIDGE_OIDC_CERT`: every call is refused (its configuration, not the token) |
| `auth.token_expired` | the token is past its exp, or a stream reached it: refresh and reconnect |
| `auth.not_a_client` | a valid token for an account `BRIDGE_API_CLIENTS` does not list |
| `auth.subscription_not_owned` | the subscription is not the client's name or under it |
| `stream.token_near_expiry` | too little token left to open a stream |
| `stream.gapped` | retention deleted events the subscription had not acked, or its System filter moved past untagged events after the grace window: reconnect for the gap, resync, ConfirmGap |
| `store.unavailable` | the store failed (retry); source `store` |
| `publish.fields_required` | id, type and subject are required |
| `publish.type_denied` | the client may not publish that type |
| `publish.subject_denied` | the client may not publish on that subject |
| `publish.hops_out_of_range` | hops is negative or at the int32 maximum |
| `publish.data_not_json` | data is not JSON |
| `publish.actor_unknown` | a privileged publish named an unknown actor |
| `publish.refused` | the store refused the event's values (retrying cannot help); source `store` |
| `subscribe.filter_denied` | the filter is wider than the client's subscribe rules |
| `delivery.not_in_flight` | Ack or Nack of an event not in flight on that subscription |
| `gap.version_invalid` | ConfirmGap's version is not positive |
| `gap.version_unsent` | ConfirmGap of a version no stream sent |
| `gap.version_stale` | ConfirmGap of a version since widened: reconnect for the new one |
| `subscribe.resolution_invalid` | `resolutions` names something other than tracked, placement or manager, or comes without `systems` |
| `replay.no_subscription` | Replay of a subscription that does not exist |
| `replay.filter_revoked` | Replay of a subscription whose filter the client may no longer read |
| `tag.denied` | the client may not tag |
| `tag.invalid` | no tags or over 1000, a system or registry_version over 256 bytes, or the store refused a tag's values (source `store`) |
| `tag.no_event` | a tag's seq holds no event: nothing was stored; source `store` |
| `server.internal` | an error a handler returned without its own key (a failed send): its code and words kept |

The webhook endpoints answer GitHub, Alertmanager and Grafana in plain text, by status only, as before.

## Configuration

The bridge refuses to start (an ERROR line, exit 1) without its webhook secret, on a database URL it cannot open,
and, closed rather than open, on a `BRIDGE_API_CLIENTS` table or an OIDC certificate, issuer or client id that does
not parse. The other settings are optional: one that is set and does not satisfy its rule is logged at WARN, naming
the variable and the rule, and takes its default (the retention or lookback default, no tracing, or no reconcile
loop for a private key that does not parse).

| Env | Meaning |
|---|---|
| `BRIDGE_DATABASE_URL` | Postgres URL. The primary directly, not pgbouncer (LISTEN needs session mode). |
| `BRIDGE_GITHUB_WEBHOOK_SECRET` | The App's webhook secret. Required. |
| `BRIDGE_FORGEJO_WEBHOOK_SECRET` | The Forgejo webhook's secret. Unset: `/webhook/forgejo` is off (404), logged at WARN. |
| `BRIDGE_FORGEJO_TRUSTED_LOGINS`, `BRIDGE_FORGEJO_AGENT_LOGINS` | `BRIDGE_TRUSTED_LOGINS` and `BRIDGE_AGENT_LOGINS` for Forgejo logins, read by `/webhook/forgejo` only. |
| `BRIDGE_FORGEJO_RELIST_REPOS` | Comma-separated `owner/repo` the Forgejo relist loop watches. Unset or empty: the loop is off. An entry that is not `owner/repo` is skipped with a warning. |
| `BRIDGE_FORGEJO_TOKEN_FILE` | Path of a mounted file holding a Forgejo token with `read:repository` and `read:issue` only, read on every run (a rotation needs no restart). Without it the relist loop is off, with a warning. |
| `BRIDGE_TAG_GRACE` | How long a System-filtered stream holds an untagged event for its tag before it gaps it, a Go duration above 0, default `60s`. |
| `BRIDGE_FORGEJO_URL` | Forgejo's base URL for the relist loop, default `https://git.bnei.dev`; every page is fetched from this host. Not `https://`: a warning (the token goes in clear). |
| `BRIDGE_TRUSTED_LOGINS` | Comma-separated GitHub logins whose actions on the operator's threads are trusted (operator, CI). Not `renovate[bot]`: its PR bodies carry third-party release notes. |
| `BRIDGE_AGENT_LOGINS` | Comma-separated fleet agent logins. Tagged `actor=agent`, never trusted; the operator's comments and pushes on their PRs are. |
| `BRIDGE_API_CLIENTS` | API clients, JSON, keyed by authentik username: `{"bridge-core": {"kind": "agent", "privileged": true, "publish_types": ["dev.bnei.agent."], "publish_subjects": [""], "subscribe": [{"types": ["dev.bnei.github."], "subjects": [""]}]}}`. `kind` is `human\|bot\|agent\|machine` (default `machine`). `publish_types` are type prefixes, written with their final dot; `publish_subjects` subject prefixes (`""` allows any). `subscribe` is a list of rules, each pairing type prefixes with subject prefixes (`""` allows any subject): a subscription's whole filter must fit one rule, and an empty type list is refused. Only `bridge-core` may be `privileged`, which changes what it may stamp on `Publish`, never what it may read. `tag` lets a client call `Tag`. Unknown fields are refused. Set in `helm/values.yaml` (no secret in it). |
| `BRIDGE_OIDC_ISSUER`, `BRIDGE_OIDC_CLIENT_ID` | The authentik provider's issuer URL and client id; a token must carry both (`iss`, `aud`, `azp`). |
| `BRIDGE_OIDC_CERT` | The pinned signing certificate(s), PEM: the only trust anchor. Empty: every API call is refused, the webhooks still work. |
| `BRIDGE_OIDC_JWKS_URL` | Optional. The provider's JWKS, fetched hourly and compared with the pinned certificate; a mismatch is logged, never trusted. |
| `BRIDGE_GITHUB_APP_ID` | App id, for the reconcile loop. Unset (or no key): reconcile is off, with a warning. |
| `BRIDGE_GITHUB_APP_PRIVATE_KEY` | The App's private key, PEM (PKCS#1 as GitHub issues it, or PKCS#8). |
| `BRIDGE_RECONCILE_LOOKBACK` | Go duration, default `6h`. Keep event retention longer than this. |
| `BRIDGE_ALERT_TOKEN` | Bearer token Alertmanager and Grafana send. Unset: both alert endpoints answer 503. |
| `BRIDGE_RETENTION` | Go duration, default `720h` (30 days), at least `24h`. Keep it longer than `BRIDGE_RECONCILE_LOOKBACK` and than the longest consumer outage you accept. |
| `PORT` | Default `8080`. |
| `BRIDGE_CLIENTS` | Retired (ADR-0066): ignored, with a warning at start, until the rollout drops it from the Secret. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Optional. The OTLP/HTTP traces URL in full (`…/v1/traces`): a span per API call and webhook route. Unset: no tracing. The SDK still reads its other `OTEL_*` variables (the exporter's headers, timeout, compression and certificates, `OTEL_BSP_*`, span limits, resource attributes); the endpoint and the service name (`ukubi-bridge`) are set in code and win. `OTEL_EXPORTER_OTLP_ENDPOINT` alone turns nothing on. A failed export logs `traces` at WARN. |

## Tests

```sh
go test ./...                                   # store tests skip without a database
docker run -d --rm --name bridge-pg -e POSTGRES_PASSWORD=t -p 55432:5432 postgres:17-alpine
BRIDGE_TEST_DATABASE_URL=postgres://postgres:t@localhost:55432/postgres go test ./...
```

`TestInsertCommitOrder` fails without the insert advisory lock: concurrent
inserts commit out of id order and a cursor skips rows. The `internal/bus`
tests run in their own database (`bridge_bus_test`, recreated each run) with
the poll fallback set to an hour, so they also prove the NOTIFY path.
`TestNackDeadLetterParksSubject` fails if parking is removed: the second event
on the poisoned subject is delivered instead of parked.
`TestTagOutOfOrder` and `TestTagGraceGap` fail if a System filter skips an
untagged event instead of holding it, then gapping it.

## Regenerating the API code

The generated Go is committed. From `proto/`, with `protoc-gen-go` v1.36.12
and `protoc-gen-connect-go` v1.21.0 on `PATH` (the versions agent-fleet uses):

```sh
buf lint && buf generate
```

CI (`.github/workflows/proto.yml`) runs `buf lint`, `buf breaking` against
`main` (a commit saying `BREAKING CHANGE:` opts out) and the same generation
with those two versions pinned, emptying `proto/gen` first. It fails on any
`git status --porcelain` output under `proto/gen`: a changed, a missing or an
untracked generated file. `git diff` alone would not see an untracked one.

## Other checks

- `golangci-lint` v2.14.0 with the default linters, the `lint` job in
  `app.yml`. An ignored error is written `_ = x.Close()`; a deferred one
  `defer func() { _ = x.Close() }()`.
- `.github/workflows/trailers.yml` scans every commit message of a pull request
  and its title and body (`.github/scripts/check-trailers.py`). An agent's commit may
  carry `Co-Authored-By: ukubi-claude-<host> <noreply@bnei.dev>` (or
  `ukubi-agent`) and `Agent-Session: <id>`; a Co-Authored-By naming Claude or
  Anthropic in any other form, a `Claude-Session:` trailer, a generated-with
  footer (a line that starts with it or names Claude; prose such as "files
  generated with protoc-gen-go" passes), a claude.ai or claude.com URL and a
  model name are refused. So is a commit whose author or committer name or
  email names Claude or Anthropic (unless it is `ukubi-claude-<host>` or
  `ukubi-agent` at `noreply@bnei.dev`): GitHub's squash merge turns each commit
  author into a `Co-authored-by:` trailer on `main`, so set
  `git config user.name`/`user.email` before committing. A commit with no
  trailers and a human author passes. The script's own test,
  `python3 .github/scripts/check_trailers_test.py`, builds a scratch repository
  with each allowed and each refused form. `--policy none` is the stricter rule
  mountain uses (no AI trailer at all).
