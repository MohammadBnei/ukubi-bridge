# ukubi-bridge

The event bus of the `ukubi-cluster` homelab: a Postgres-backed CloudEvents log
that feeds agent-fleet's agents and, later, apps. The design is
[infra-bootstrap ADR-0059](https://github.com/MohammadBnei/infra-bootstrap/blob/main/docs/adr/0059-event-bridge.md);
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
  Pigsty failover). A 204 (ignored type) is never checked. A GUID answered 400
  on 5 attempts is given up on (a 400 stays a 400); any other failure retries
  until it leaves the window. A 403/429 ends the run; the next tick tries again.
- `POST /webhook/alertmanager` and `POST /webhook/grafana` — bearer token,
  one event per alert: `ce_id` = `fingerprint:status:startsAt`, so a
  `repeat_interval` resend of the same firing coalesces while its resolution
  is a new event. Type `dev.bnei.alert.firing|resolved`, subject
  `alert/<fingerprint>`, `actor=machine`, never trusted. 503 when the store is
  down, so the sender retries.
- `GET /healthz`.

Not yet: the `Publish`/`Subscribe`/`Ack`/`Replay` gRPC API.

## Configuration

| Env | Meaning |
|---|---|
| `BRIDGE_DATABASE_URL` | Postgres URL. The primary directly, not pgbouncer (LISTEN needs session mode). |
| `BRIDGE_GITHUB_WEBHOOK_SECRET` | The App's webhook secret. Required. |
| `BRIDGE_TRUSTED_LOGINS` | Comma-separated GitHub logins that may open threads (operator, `renovate[bot]`, CI). |
| `BRIDGE_AGENT_LOGINS` | Comma-separated fleet agent logins. Trusted, and tagged `actor=agent`. |
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
inserts commit out of id order and a cursor skips rows.
