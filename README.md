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
- `GET /healthz`.

Not yet: the `Publish`/`Subscribe`/`Ack`/`Replay` gRPC API, the GitHub
reconcile loop, Alertmanager/Grafana ingest.
ADR-0071 §6's "drop events caused by the thread's own agent identity" is not
done here: the bridge has no thread ownership, so core's dispatcher drops them
and the per-thread agent-wake cap bounds loops.

## Configuration

| Env | Meaning |
|---|---|
| `BRIDGE_DATABASE_URL` | Postgres URL. The primary directly, not pgbouncer (LISTEN needs session mode). |
| `BRIDGE_GITHUB_WEBHOOK_SECRET` | The App's webhook secret. Required. |
| `BRIDGE_TRUSTED_LOGINS` | Comma-separated GitHub logins that may open threads (operator, `renovate[bot]`, CI). |
| `BRIDGE_AGENT_LOGINS` | Comma-separated fleet agent logins. Trusted, and tagged `actor=agent`. |
| `PORT` | Default `8080`. |

## Tests

```sh
go test ./...                                   # store tests skip without a database
docker run -d --rm --name bridge-pg -e POSTGRES_PASSWORD=t -p 55432:5432 postgres:17-alpine
BRIDGE_TEST_DATABASE_URL=postgres://postgres:t@localhost:55432/postgres go test ./...
```

`TestInsertCommitOrder` fails without the insert advisory lock: concurrent
inserts commit out of id order and a cursor skips rows.
