# ukubi-bridge

Event bus of the ukubi cluster: Postgres-backed CloudEvents log, ConnectRPC API (Publish, Subscribe, Replay),
webhook intake (GitHub, Forgejo, Alertmanager, Grafana) and `kwatch`, a k8s watch adapter. Design: ib:ADR-0086 (absorbs superseded ib:ADR-0060).
Go 1.27, module `github.com/MohammadBnei/ukubi-bridge`. README.md is the reference.
Rules: workspace CLAUDE.md; change rules mountain `plan/16-dev-rules.md`.

## Commands
- `go test ./...` (store tests skip without `BRIDGE_TEST_DATABASE_URL`; a throwaway postgres:17 is in README "Tests").
- `cd proto && buf lint && buf generate` regenerates the committed `proto/gen` (protoc-gen-go v1.36.12,
  protoc-gen-connect-go v1.21.0); CI fails on any diff under `proto/gen`.
- `golangci-lint` v2.14.0 (`lint` job in `checks.yml`).
- `python3 .github/scripts/check_trailers_test.py` tests the trailers check.

## Layout
`cmd/bridge` (server), `cmd/kwatch` (second binary, own Deployment), `internal/{event,store,bus,auth,github,forgejo,alert,ingest,contract,metrics}`,
`proto/` (buf module), `contract/events.yaml` (the event contract), `helm/`, `Dockerfile` (one image, both binaries).

## Traps
- `contract/events.yaml` is the contract; change it with its README section and the tests that read it, never alone.
- Inserts take an advisory lock so ids commit in order; a cursor would skip rows without it (`TestInsertCommitOrder`).
- Generated code in `proto/gen` is committed: regenerate, never hand-edit.
- CI is Forgejo Actions in `.github/workflows/` on `k8s-ubuntu-latest`.
