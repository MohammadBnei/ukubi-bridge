# ukubi-bridge

The event bus of the `ukubi-cluster` homelab: a Postgres-backed CloudEvents log
that feeds agent-fleet's agents and, later, apps. The design is
[infra-bootstrap ADR-0060](https://github.com/MohammadBnei/infra-bootstrap/blob/main/docs/adr/0060-event-bridge.md);
agent-fleet's side is its ADR-0071 (dispatch) and ADR-0072 (approval-gated executor).

## What it does today

- `POST /webhook/github` — GitHub App deliveries. HMAC-verified, filtered to
  `pull_request` (opened/synchronize/closed/reopened), `issue_comment` (created)
  and `pull_request_review` (submitted), normalised to the envelope in
  `internal/event`, appended to `events` once per `X-GitHub-Delivery`.
  Trust follows the PR or comment author, never the webhook sender; a fork PR is
  never trusted.
- GitHub reconcile: every 10 minutes the App lists its webhook deliveries back
  to the lookback window and redelivers, oldest first, each one not in
  `events` — failed (bridge downtime) or acknowledged with 202 (lost to a
  Pigsty failover). A 204 (ignored type) is never checked. A GUID the bridge
  rejected (4xx) 5 times, or whose original delivery has left the
  `BRIDGE_RECONCILE_LOOKBACK` window (default 6h), is given up on and logged.
  An outage (5xx, timeout) is retried until then, so a longer outage needs a
  manual redelivery from the App's log, which GitHub keeps for 3 days. A 403/429 ends the run; the next tick tries again.
- `POST /webhook/alertmanager` and `POST /webhook/grafana` — bearer token,
  one event per alert: `ce_id` = `fingerprint:status:startsAt`, so a
  `repeat_interval` resend of the same firing coalesces while its resolution
  is a new event. Type `dev.bnei.alert.firing|resolved`, subject
  `alert/<fingerprint>`, `actor=machine`, never trusted. 503 when the store is
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
    A non-privileged client's event is stamped with its own `kind` as actor and its name as `actor_login`, `trusted=false`, no
    `owner`, and `hops` one above what it sent (`causation_id` kept). Only a
    `privileged` client (agent-fleet core) sets actor, trust, owner and hops.
    Nobody sets `replayed`.
  - `Subscribe(name, types, subjects)` — `name` is the client's own name or
    `<name>/<suffix>`. The whole filter must fit one of the client's
    `subscribe` rules, and `types` cannot be empty. The stream ends
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
  - `Replay(subscription, from_seq)` — streams the subscription's matching
    events from `from_seq` to the current head with `replayed=true`, after
    checking the stored filter still fits the client's rules (`NotFound` for a
    subscription never created by `Subscribe`). Bounded by the token like
    `Subscribe`. No ack,
    no cursor change, nothing written. Subscribers must be idempotent on
    `(source, id)` (or `seq`, which is the same event's log position) — never
    on `id` alone: two clients can both publish id `1`. From at or below the
    retention watermark, the first message is a `gap` (see Retention).

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
  Loki rules alert on both.

The run locks `dead_letters` for its duration, so an unparking `UPDATE` or a
live dead-lettering waits for it. Clients written before gaps existed must
handle a message whose `event` is unset (there are none yet: nothing calls the
API before agent-fleet's dispatcher).

Dedup on `(source, id)` holds only within retention: an id published again
after its event was deleted is a new event.

Not yet:

- An API for dead letters.
- A live API client. No client can call until `BRIDGE_OIDC_CERT` is set and
  the authentik `ukubi-bridge-api` provider exists (infra-bootstrap
  ADR-0066). agent-fleet's consumer is its `core/internal/dispatch` (its
  ADR-0071).

ADR-0071 §6's "drop events caused by the thread's own agent identity" is not
done here: the bridge has no thread ownership. Core's dispatcher never lets
one wake a session (an agent's GitHub login is never trusted), but it is still
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
Errors Connect raises before a handler runs (an unreadable body, an unknown procedure, a client's own timeout) carry
no key. The registry is closed, in `internal/bus/errkeys.go`:

| Key | Meaning |
|---|---|
| `auth.bearer_required` | no `Authorization: Bearer` header |
| `auth.token_invalid` | the token failed verification (signature, issuer, audience, claims) |
| `auth.no_key_pinned` | the bridge has no `BRIDGE_OIDC_CERT`: every call is refused (its configuration, not the token) |
| `auth.token_expired` | the token is past its exp, or a stream reached it: refresh and reconnect |
| `auth.not_a_client` | a valid token for an account `BRIDGE_API_CLIENTS` does not list |
| `auth.subscription_not_owned` | the subscription is not the client's name or under it |
| `stream.token_near_expiry` | too little token left to open a stream |
| `stream.gapped` | retention deleted events the subscription had not acked: reconnect for the gap, resync, ConfirmGap |
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
| `replay.no_subscription` | Replay of a subscription that does not exist |
| `replay.filter_revoked` | Replay of a subscription whose filter the client may no longer read |
| `server.internal` | an error a handler returned without its own key (a failed send): its code and words kept |

The webhook endpoints answer GitHub, Alertmanager and Grafana in plain text, by status only, as before.

## Configuration

| Env | Meaning |
|---|---|
| `BRIDGE_DATABASE_URL` | Postgres URL. The primary directly, not pgbouncer (LISTEN needs session mode). |
| `BRIDGE_GITHUB_WEBHOOK_SECRET` | The App's webhook secret. Required. |
| `BRIDGE_TRUSTED_LOGINS` | Comma-separated GitHub logins whose actions on the operator's threads are trusted (operator, CI). Not `renovate[bot]`: its PR bodies carry third-party release notes. |
| `BRIDGE_AGENT_LOGINS` | Comma-separated fleet agent logins. Tagged `actor=agent`, never trusted; the operator's comments and pushes on their PRs are. |
| `BRIDGE_API_CLIENTS` | API clients, JSON, keyed by authentik username: `{"bridge-core": {"kind": "agent", "privileged": true, "publish_types": ["dev.bnei.agent."], "publish_subjects": [""], "subscribe": [{"types": ["dev.bnei.github."], "subjects": [""]}]}}`. `kind` is `human\|bot\|agent\|machine` (default `machine`). `publish_types` are type prefixes, written with their final dot; `publish_subjects` subject prefixes (`""` allows any). `subscribe` is a list of rules, each pairing type prefixes with subject prefixes (`""` allows any subject): a subscription's whole filter must fit one rule, and an empty type list is refused. Only `bridge-core` may be `privileged`, which changes what it may stamp on `Publish`, never what it may read. Unknown fields are refused. Set in `helm/values.yaml` (no secret in it). |
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

## Regenerating the API code

The generated Go is committed. From `proto/`, with `protoc-gen-go` v1.36.12
and `protoc-gen-connect-go` v1.21.0 on `PATH` (the versions agent-fleet uses):

```sh
buf lint && buf generate
```
