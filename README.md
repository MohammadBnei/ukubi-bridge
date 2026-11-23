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
  one event per alert: `ce_id` = `fingerprint:status:startsAt:episode`.
  The episode is the firing episode the event belongs to: a firing after a
  resolve starts the next one, and a resolved carries the episode it closes.
  It comes from the newest stored alert row of that fingerprint and
  `startsAt`. So a `repeat_interval` resend of the same firing coalesces
  while its resolution, and a re-fire after it, are new events. Ids stored
  before episodes (no suffix) count as episode 0 and still dedup. Type
  `dev.bnei.alert.firing|resolved`, subject `alert/<fingerprint>`,
  `actor=machine`, neither trust fact. 503 when the store is down, so the
  sender retries.
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
  relisting pushes (synchronized), reopens, label changes and runs.
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

## kwatch, the k8s watch adapter

`cmd/kwatch` is a second binary in the same image, run as its own Deployment (`helm/kwatch.yaml`). It is an API
client like any other, the authentik service account `bridge-kwatch`, signing in with a client_credentials grant
(agent-fleet core's way), and publishes under `client/bridge-kwatch`. It watches the ArgoCD Applications
(`argoproj.io/v1alpha1`) in `argocd` and the cluster's Warning events, with client-go informers, and publishes as
below. `<app>` is the Application's name. Only `argocd` is watched: apps-in-any-namespace is off, so an Application
elsewhere is reconciled by nothing (its status is whatever its creator wrote) and the contract has no subject or tag
for it; turning it on widens the watch, the grant and the contract together.

| Type | Subject | Data |
|---|---|---|
| `dev.bnei.deploy.health` | `argocd/<app>` | `health`, `previous` |
| `dev.bnei.deploy.synced` | `argocd/<app>` | `sync`, `previous`, `previous_revisions`, `phase` (the operation's, empty when none synced it); `refs.revisions` from `status.sync.revisions` (or `revision`) |
| `dev.bnei.deploy.flapping` | `argocd/<app>` | `signal` (always `health`), `transitions`, `window`, `current` |
| `dev.bnei.k8s.warning` | `k8s/<ns>/<kind>/<name>` (`_` for a cluster-scoped object) | `refs` (`ns`, `kind`, `name`, `uid`, `api_version`, `field_path`, `reason`), `message_hash`, `count`, `component` |

Against spike contract v0 (mountain-spike-coord `spike/contract/events.yaml`): types carry the `dev.bnei.` prefix,
the Warning type is `k8s.warning` (v0: `k8s.event.warning`), `deploy.flapping` is new, and a Warning's refs have no
`owner_chain` or `field_manager` (each would cost an API read per Event; not built until a reader needs them).

An Application event's data also carries `refs.app` and `hints.system` = `app:<app>`: a hint, which atlas turns
into the System tag (the bridge never resolves). The event's `time` is the object's own: `status.health.lastTransitionTime`
for health; for sync, the last operation's `finishedAt` when it synced those very revisions, otherwise `reconciledAt`
(an app often turns Synced at a new revision with no operation). A Warning's is its last observed time. Only a
Warning's message hash rides the bus: the message is free text a workload wrote. Every id is derived from the object
(its resourceVersion, or a Warning's uid and count), so a retry or a restart deduplicates on `(source, id)`.

What the watcher keeps from spike S4 and doubt cycle 3 (M2):

- The first sight of an app is its baseline, not an edge. So is every app's after a restart: kwatch keeps no state,
  and atlas polls the levels.
- Transitions of one app and signal closer together than `KWATCH_SETTLE` are one run. It emits once, from the first
  previous value to the last, and a run that ends where it began (A → B → A) emits nothing. ukubi-stt's three flips
  within 143 ms after its PR #41 become one `Degraded` → `Progressing`. Only arriving at `Synced` (or at a new
  revision while Synced, when deployed) is a sync edge.
- A run is closed after `KWATCH_SETTLE_CAP` even while it keeps changing, so an app flapping forever still emits.
- Flapping is apart from settling: it counts every health transition into `Degraded` or `Missing` as kwatch sees
  it, before a run absorbs it (a blip the window drops, or three entries within 150 ms, each count), per app in a
  sliding `KWATCH_FLAP_WINDOW`. The `KWATCH_FLAP_COUNT`-th emits one `deploy.flapping` at once; the next only after
  a whole window with none, so an app that keeps flapping, however slowly, flaps once per episode. Sync moves and
  `Progressing`/`Healthy` moves never count, so the normal deploy cadence (`Healthy` → `Progressing` → `Healthy`,
  `Synced` → `OutOfSync` → `Synced`) never flaps. A deploy whose rollout wobbles through `Degraded` (ukubi-stt's
  does) is one entry: three such deploys within the window do flap.
- Sync: a run emits `deploy.synced` when it arrives at `Synced`, or when it showed `Synced` at revisions other than
  the last ones known even if it ends `OutOfSync` (the next commit or a drift landing within the window), and only
  if that `Synced` was deployed: reached from `OutOfSync`, or synced by an operation (`operationState` synced those
  very revisions). A revision-only move with no operation is not a deploy: every app lists infra-bootstrap's
  common-app-chart among its sources, so each infra-bootstrap commit moves ~60 apps' revisions, and only the apps
  it renders differently go `OutOfSync` and sync. `previous_revisions` are the last `Synced` revisions known (a
  revision-only move included), however long it was `OutOfSync` in between; empty when kwatch has not seen the app
  `Synced` since it started.
- An Application whose health, sync status or revisions are not ArgoCD's vocabulary (its health and sync enums, a
  sha, tag or chart version) is skipped and logged, never published: the fields reach agents' context.
- A repeating Warning (its count climbing) is sent again at most every 10 minutes: a repeat within that is held, and
  the latest one held goes out once the 10 minutes have passed, so an Event that goes quiet still has its last count
  published. A Warning last observed more than 2 minutes before kwatch started is a baseline, recorded and not sent:
  a restart or a first deploy does not replay the cluster's last hour, and the 2 minutes cover the restart's own gap
  (what was sent before it dedups at the bridge).
- Every field of a Warning but its message is free text too, and its subject and refs reach agents' context: an
  Event whose namespace, kind, name or reason is not the shape Kubernetes writes (a DNS-1123 label, a CamelCase
  identifier, a DNS-1123 subdomain, `^[A-Za-z][A-Za-z0-9]{0,63}$`) is dropped and logged; a `field_path`,
  `component`, `api_version` or `uid` outside a plain token charset is sent empty.

A refusal no retry can change (`InvalidArgument`, `PermissionDenied`) is logged and dropped; anything else is retried,
backing off to a minute. Behind a bridge down long enough to queue 1024 events, the newest are dropped and logged.
`GET /healthz` is 204 once both informers have listed. On SIGTERM, kwatch closes every run, one still settling
included (the next start baselines on where it ended, so it would never be sent otherwise), sends every Warning held
back, and drains the queue for up to 10 seconds before exiting. A transition that lands while kwatch is down is
lost: the next start's first sight is its baseline. kwatch shares the bridge's image pin (Recreate), so it restarts
exactly when ukubi-bridge and kwatch themselves roll out: their own deploys are visible only through atlas's level
polls. Settings (env):

- `BRIDGE_URL`, `BRIDGE_TOKEN_URL`, `BRIDGE_PASSWORD`: required, or kwatch refuses to start. The password is the
  service account's app password, from a Secret.
- `BRIDGE_AUTH_HOST`: authentik's public host, sent as the token request's Host so the issuer is the pinned one.
- `BRIDGE_USERNAME` (default `bridge-kwatch`), `BRIDGE_CLIENT_ID` (default `ukubi-bridge-api`).
- `KWATCH_SETTLE` (default `30s`), `KWATCH_SETTLE_CAP` (`5m`), `KWATCH_FLAP_WINDOW` (`15m`), `KWATCH_FLAP_COUNT`
  (`3`, at least 2): a value that does not parse is logged at WARN and takes its default, and unless
  `KWATCH_SETTLE` < `KWATCH_SETTLE_CAP` both take theirs.
- `KUBECONFIG`: for a run from a laptop; unset, the pod's own account. `PORT` (default `8080`).

Its grants are read only and live in infra-bootstrap, not here: a standing grant is reviewed there, next to the
cluster's others (`gitops/platform/ukubi-game`, `gitops/platform/thot`, each applied by its own wave-1 Application in
`gitops/bootstrap/`), and the common-app-chart renders no ServiceAccount or RBAC. They are the ServiceAccount
`bridge-kwatch` in `ukubi-bridge-kwatch`; get/list/watch on `argoproj.io` `applications` in `argocd` (a Role); and
get/list/watch on core `events` cluster-wide (a ClusterRole: the API cannot grant by field, so Normal Events are
readable too, though kwatch lists `type=Warning` only). Not running yet: it needs

- those grants, in infra-bootstrap `gitops/platform/ukubi-bridge-kwatch/` with its bounds Application;
- a registry entry `ukubi-bridge-kwatch` (`valuesPath: [helm/kwatch.yaml]`, `deployPath: helm/image.yaml`);
- the authentik service account `bridge-kwatch` (already declared in
  `authentik-blueprint-ukubi-bridge-api.yaml`) with its app password, Infisical `BRIDGE_KWATCH_APP_PASSWORD`,
  rendered as `BRIDGE_PASSWORD` into the Secret `ukubi-bridge-kwatch-config` in `ukubi-bridge-kwatch`;
- kwatch's pods admitted by authentik's ingress fence (infra-bootstrap
  `gitops/bootstrap/authentik-ciliumnetworkpolicy.yaml`, which admits only named pods to `:9000`): a `fromEndpoints`
  entry `{k8s:io.kubernetes.pod.namespace: ukubi-bridge-kwatch, app.kubernetes.io/name: ukubi-bridge-kwatch}` on
  `:9000`. Without it every token request is dropped and kwatch retries forever, logging at WARN, publishing
  nothing. kwatch has no egress lock; one would allow DNS, the kube-apiserver, the bridge `:8080` and authentik
  `:9000`;
- `BRIDGE_OIDC_CERT` set on the bridge.

## Event contract

`contract/events.yaml` lists the shared event types the bridge's adapters and known clients emit: per type its
subject pattern, the exact `ce_id` recipe (`ce_id_kind: fact` is derived from the fact, so a retry or a relisted
copy is the same event; `transport` is a delivery id, so a redelivery is stored twice), its producer and its trust
facts. The same file is the ConfigMap `ukubi-bridge-contract` in `helm/values.yaml` (a test keeps them identical),
mounted as a directory so an edit reaches the pod without a restart. `dev.bnei.agent.*` is a prefix: agents name
their own types under it. The `dev.bnei.world.*` rows are atlas's (`bridge-atlas`, the tagging client, now also a
publisher; its name is frozen, it is the event source). Node ids hold `/`, so the publish grant is the prefix `world/`;
a subscription takes `world/*` (`*` matches `/`, so such ids are covered), and `world/` alone matches only `history.rebased`. A move (Realm/Parent/Group change) is not an event: the library re-reads
atlas for current state.

An event whose type is not in the contract is still stored and delivered, with `flags: ["uncontracted"]` on the
`CloudEvent`. Flags are computed at delivery against the current contract, so blessing a type unflags its backlog
(replays included). **A consumer must ack and skip an event that carries any flag** (never leave it unacked, which
blocks its own stream, and never nack it, which redelivers it); every flag means skip, so an informational flag needs
a new field. Each stored uncontracted event is logged once at ingest (`event type uncontracted`, with its producer); the
chart's Loki rule alerts on it. The contract is knowledge, never trust: if no contract has ever loaded (unset, missing
or unparsable file), nothing is flagged and, for a missing or unparsable file, the bridge logs `event contract not loaded` every minute; a failed reload
logs `event contract not reloaded` and keeps the last good copy. A second Loki rule alerts on both. The runtime parser
ignores unknown fields (an old image accepts a newer contract); a test applies the strict check. The ConfigMap volume is
`optional`, so a missing ConfigMap never keeps the pod from starting.

To bless a type: add its entry to `contract/events.yaml` and the same text to `helm/values.yaml`
(`go test ./internal/bus` checks the copy; adapter tests fail when a type they build is missing), merge, and let
ArgoCD sync: the bridge picks it up within a few minutes of the sync (kubelet's ConfigMap refresh plus the 60 s poll). Land a values change that adds the contract together with the image pin that reads it, so the single writer restarts once.

Every event also stores its raw producer in `events.producer` (jsonb, null before this): `{"kind":"client","name":...}`
for an API client (the name is the client table key: the verified authentik subject, or the row whose `sa` the service account token names; such a token adds
`"ns"`, `"sa"` and `"pod"`, the pod it is bound to), `{"kind":"route","name":...}` for `forgejo-webhook`, `forgejo-relist`, `github-webhook`,
`alertmanager` or `grafana`. A delivered `CloudEvent` carries it as `producer` (JSON bytes, field 18; empty for events
stored before the column), so atlas can tag producer Systems.

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
| `auth.no_key_pinned` | the bridge has no `BRIDGE_OIDC_CERT` (or, for a service account token, no `BRIDGE_K8S_SA_KEY`): every such call is refused (its configuration, not the token) |
| `auth.token_expired` | the token is past its exp, or a stream reached it: refresh and reconnect |
| `auth.not_a_client` | a valid token for an account `BRIDGE_API_CLIENTS` does not list |
| `auth.sa_not_a_client` | a valid service account token whose `<namespace>:<serviceaccount>` is no row's `sa` |
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
| `BRIDGE_FORGEJO_READER_TOKEN` | A Forgejo token with `read:repository` and `read:issue` only (the `bridge-reader` bot), read at start (a rotation needs a pod restart; the chart sets the Infisical auto-reload annotation, so a changed `ukubi-bridge-config` restarts it). Without it and without `BRIDGE_FORGEJO_TOKEN_FILE` the relist loop is off, with a warning. |
| `BRIDGE_FORGEJO_TOKEN_FILE` | Fallback for the token: path of a mounted file with the same token, read on every run. Used only when `BRIDGE_FORGEJO_READER_TOKEN` is unset; to be removed after one release. |
| `BRIDGE_TAG_GRACE` | How long a System-filtered stream holds an untagged event for its tag before it gaps it, a Go duration above 0, default `60s`. |
| `BRIDGE_CONTRACT_FILE` | Path of the event contract (`contract/events.yaml`), read at start and every 60 s; a bad or missing file keeps the last good one, logged at WARN. Unset or never loaded: nothing is flagged (see Event contract). |
| `BRIDGE_FORGEJO_URL` | Forgejo's base URL for the relist loop, default `https://git.bnei.dev`; every page is fetched from this host. Not `https://`: a warning (the token goes in clear). |
| `BRIDGE_TRUSTED_LOGINS` | Comma-separated GitHub logins whose actions on the operator's threads are trusted (operator, CI). Not `renovate[bot]`: its PR bodies carry third-party release notes. |
| `BRIDGE_AGENT_LOGINS` | Comma-separated fleet agent logins. Tagged `actor=agent`, never trusted; the operator's comments and pushes on their PRs are. |
| `BRIDGE_API_CLIENTS` | API clients, JSON, keyed by authentik username: `{"bridge-core": {"kind": "agent", "privileged": true, "publish_types": ["dev.bnei.agent."], "publish_subjects": [""], "subscribe": [{"types": ["dev.bnei.github."], "subjects": [""]}]}}`. `kind` is `human\|bot\|agent\|machine` (default `machine`). `publish_types` are type prefixes, written with their final dot; `publish_subjects` subject prefixes (`""` allows any). `subscribe` is a list of rules, each pairing type prefixes with subject prefixes (`""` allows any subject): a subscription's whole filter must fit one rule, and an empty type list is refused. Only `bridge-core` may be `privileged`, which changes what it may stamp on `Publish`, never what it may read. `tag` lets a client call `Tag`. `sa` (`"<namespace>:<serviceaccount>"`, optional) lets that service account's projected token sign in as the row (see `BRIDGE_K8S_SA_KEY`); two rows may not share one, and the row keeps its name. A namespace's `default` account is refused (every pod that names no account runs as it), and `bridge-core`'s `sa` may only be `agent-fleet:bridge-core`: set it only once the admission policy that keeps provisioner pods off that account is live (plan M3, row B2), since anyone who can start a pod as an account can sign in as its row. Unknown fields are refused. Set in `helm/values.yaml` (no secret in it). |
| `BRIDGE_OIDC_ISSUER`, `BRIDGE_OIDC_CLIENT_ID` | The authentik provider's issuer URL and client id; a token must carry both (`iss`, `aud`, `azp`). |
| `BRIDGE_OIDC_CERT` | The pinned signing certificate(s), PEM: the only trust anchor. Empty: every API call is refused, the webhooks still work. |
| `BRIDGE_OIDC_JWKS_URL` | Optional. The provider's JWKS, fetched hourly and compared with the pinned certificate; a mismatch is logged, never trusted. |
| `BRIDGE_K8S_SA_KEY` | The pinned cluster service account key(s), PEM `PUBLIC KEY` (from `kubectl get --raw /openid/v1/jwks`), beside authentik: a projected token with `iss` `https://192.168.1.211:6443`, `aud` containing `ukubi-bridge`, RS256, a `kubernetes.io` pod claim and `exp - iat` at most 1h (plus 1 min) signs in as the client row whose `sa` is its `<namespace>:<serviceaccount>`. The token's `iss`, read before any check, picks the verifier. The check is offline (no TokenReview): a token stays valid until its `exp`, up to 1h, even after its pod is deleted, and a leaked one can be replayed for that long. So the stored `pod` is the pod the token is bound to, not proof that this pod sent it. Unset or blank: every service account token is refused (`k8s-sa-auth` reads 0, one WARN). Does not parse: the bridge refuses to start. Re-pin after a cluster rebuild. |
| `BRIDGE_K8S_JWKS_URL` | Optional. The cluster's JWKS (`https://kubernetes.default.svc/openid/v1/jwks`), fetched hourly with the pod's own token and the in-cluster CA and compared with the pinned keys; any published key that is not pinned is logged by its `kid` (a signing-key rotation signs new tokens with the new key at once, so they are refused until it is pinned), never trusted. The URL receives the pod's token: it must be https (otherwise a WARN and the check is off), and redirects are not followed. Keep it the API server. |
| `BRIDGE_GITHUB_APP_ID` | App id, for the reconcile loop. Unset (or no key): reconcile is off, with a warning. |
| `BRIDGE_GITHUB_APP_PRIVATE_KEY` | The App's private key, PEM (PKCS#1 as GitHub issues it, or PKCS#8). |
| `BRIDGE_RECONCILE_LOOKBACK` | Go duration, default `6h`. Keep event retention longer than this. |
| `BRIDGE_ALERT_TOKEN` | Bearer token Alertmanager and Grafana send. Unset: both alert endpoints answer 503. |
| `BRIDGE_RETENTION` | Go duration, default `720h` (30 days), at least `24h`. Keep it longer than `BRIDGE_RECONCILE_LOOKBACK` and than the longest consumer outage you accept. |
| `PORT` | Default `8080`. |
| `BRIDGE_METRICS_ADDR` | Where `/metrics` is served, on its own listener (never the public port), default `:9090`; the bridge refuses to start when its port equals `PORT`. |
| `BRIDGE_CLIENTS` | Retired (ADR-0066): ignored, with a warning at start, until the rollout drops it from the Secret. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Optional. The OTLP/HTTP traces URL in full (`…/v1/traces`): a span per API call and webhook route. Unset: no tracing. The SDK still reads its other `OTEL_*` variables (the exporter's headers, timeout, compression and certificates, `OTEL_BSP_*`, span limits, resource attributes); the endpoint and the service name (`ukubi-bridge`) are set in code and win. `OTEL_EXPORTER_OTLP_ENDPOINT` alone turns nothing on. A failed export logs `traces` at WARN. |

## Metrics

`/metrics` is served on its own listener, `BRIDGE_METRICS_ADDR` (default `:9090`), never on the public port; the chart's
Service and ServiceMonitor carry it as the `metrics` port. A flow is one of `forgejo-webhook`, `forgejo-relist`,
`github-webhook`, `github-reconcile`, `alertmanager`, `grafana`, `oidc-jwks` (the hourly certificate check),
`k8s-sa-auth` (service account sign-in, on while `BRIDGE_K8S_SA_KEY` is pinned), `k8s-sa-jwks` (the hourly cluster key
check), or an API client's name (its `Publish`, e.g. `bridge-kwatch`). A flow that is switched off by missing configuration reads 0 on `bridge_flow_enabled` (most log one WARN naming the setting;
an API client's flow reads 0 while none of its tokens can be verified: no certificate pinned, and no cluster key or no `sa`). `oidc-jwks`, `k8s-sa-auth`, `k8s-sa-jwks` and `github-reconcile` only report
enabled: their runs and failures log, they record no event series.

| Series | Meaning |
|---|---|
| `bridge_flow_enabled{flow}` | 1 if the flow is on, 0 if its setting is missing or unusable. |
| `bridge_flow_last_event_timestamp{flow}` | Unix seconds of the last event accepted on the flow (absent until the first one since start). |
| `bridge_flow_events_total{flow,type_prefix}` | Events accepted (webhooks, alert endpoints and `Publish` count redeliveries too; relist counts only inserted events), by the type up to its third dot (`dev.bnei.forge`). |
| `bridge_type_uncontracted_total{producer}` | Stored events whose type is not in the contract (once a contract has loaded), by producer: an API client row or a route name. |
| `bridge_relist_runs_total{result}` | Forgejo relist runs, `ok` or `error`. |
| `bridge_tags_written_total` | Tags stored through `Tag`. |
| `bridge_auth_refused_total{reason}` | API calls refused at sign-in, by their error key (`auth.bearer_required`, `auth.token_invalid`, `auth.no_key_pinned`, `auth.token_expired`, `auth.not_a_client`, `auth.sa_not_a_client`). |

Alerts (`helm/values.yaml`, severity notice): `BridgeForgejoWebhookOff` (the Forgejo secret is unset, or the series is
missing: no Forgejo event arrives). They ship with the ServiceMonitor, which stays `enabled: false` until the pinned image
serves `:9090`: scraping an older image is connection refused, and the chart's TargetDown is a warning that Alertmanager
routes to thot. A down or unscraped bridge lands there once it is on. kwatch liveness has no alert yet: it publishes only on
changes, so silence on a calm cluster is normal; it waits for kwatch's own series.

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
  `checks.yml`. An ignored error is written `_ = x.Close()`; a deferred one
  `defer func() { _ = x.Close() }()`.
- `.github/workflows/trailers.yml` scans every commit message of a pull request
  and its title and body (`.github/scripts/check-trailers.py`). Agent commits
  add no trailers. The check refuses a Co-Authored-By naming Claude or
  Anthropic, a `Claude-Session:` trailer, a generated-with footer (a line that
  starts with it or names Claude; prose such as "files generated with
  protoc-gen-go" passes), a claude.ai or claude.com URL and a model name. It
  also refuses a commit whose author or committer name or email names Claude or
  Anthropic (unless it is `ukubi-agent` at `noreply@bnei.dev`, or the legacy
  `ukubi-claude-<host>`, which agents no longer use), so set `git config user.name`/`user.email` before
  committing. A commit with no trailers and a human author passes. The
  script's own test, `python3 .github/scripts/check_trailers_test.py`, builds a
  scratch repository with each allowed and each refused form. `--policy none`
  is the stricter rule mountain uses.
