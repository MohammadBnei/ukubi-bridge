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
  rejected (4xx) 5 times, or whose original delivery has left the 6-hour
  window, is given up on and logged. An outage (5xx, timeout) is retried until
  then, so an outage longer than 6 hours needs a manual redelivery. A 403/429 ends the run; the next tick tries again.
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
    `<name>/<suffix>`. A new subscription starts at the head of the log.
    Delivery is head-of-line: the next matching event is sent only once the
    current one is acked. A NOTIFY sent inside each insert wakes the stream;
    it also polls every 30 s. A second `Subscribe` on the same name replaces
    the first.
  - `Ack(subscription, seq)` / `Nack(subscription, seq, reason)` — only the
    event in flight. A Nack retries after 1 s, 2 s, 4 s, 8 s; the fifth
    dead-letters it, which **parks its subject** for that subscription: later
    events on the subject go straight to `dead_letters` too, so a thread is
    never processed out of order.
  - `Replay(subscription, from_seq)` — streams the subscription's matching
    events from `from_seq` to the current head with `replayed=true`. No ack,
    no cursor change, nothing written. Subscribers must be idempotent on
    `(source, id)` (or `seq`, which is the same event's log position) — never
    on `id` alone: two clients can both publish id `1`.

Not yet: an API for dead letters.
ADR-0071 §6's "drop events caused by the thread's own agent identity" is not
done here: the bridge has no thread ownership, so core's dispatcher drops them
and the per-thread agent-wake cap bounds loops.

### Unparking a subject

Nothing exposes this yet. Fix the subscriber, then:

```sql
UPDATE dead_letters SET cleared_at = now()
WHERE subscription = 'core' AND subject = 'github/MohammadBnei/editable-blog/pr/42' AND cleared_at IS NULL;
```

The dead-lettered events stay behind the cursor; `Replay` from the first one's
`event_id` re-sends them.

## Configuration

| Env | Meaning |
|---|---|
| `BRIDGE_DATABASE_URL` | Postgres URL. The primary directly, not pgbouncer (LISTEN needs session mode). |
| `BRIDGE_GITHUB_WEBHOOK_SECRET` | The App's webhook secret. Required. |
| `BRIDGE_TRUSTED_LOGINS` | Comma-separated GitHub logins that may open threads (operator, `renovate[bot]`, CI). |
| `BRIDGE_AGENT_LOGINS` | Comma-separated fleet agent logins. Trusted, and tagged `actor=agent`. |
| `BRIDGE_CLIENTS` | API clients, JSON: `{"core": {"token_sha256": "<hex sha256 of the bearer token>", "kind": "agent", "publish_types": ["dev.bnei.agent."], "publish_subjects": [""], "subscribe": true, "privileged": true}}`. `kind` is `human\|bot\|agent\|machine` (default `machine`); `publish_types` are type prefixes, `publish_subjects` subject prefixes (`""` allows any; an app gets its own, e.g. `["zot/"]`). Missing either: that client publishes nothing. Empty: every call is refused. |
| `BRIDGE_GITHUB_APP_ID` | App id, for the reconcile loop. Unset (or no key): reconcile is off, with a warning. |
| `BRIDGE_GITHUB_APP_PRIVATE_KEY` | The App's private key, PEM (PKCS#1 as GitHub issues it, or PKCS#8). |
| `BRIDGE_RECONCILE_LOOKBACK` | Go duration, default `6h`. Keep event retention longer than this. |
| `BRIDGE_ALERT_TOKEN` | Bearer token Alertmanager and Grafana send. Unset: both alert endpoints answer 503. |
| `PORT` | Default `8080`. |

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
