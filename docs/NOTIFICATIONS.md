# Tell a person that attention is needed

NQ includes experimental bounded Slack/Discord webhook delivery adapters, a
PagerDuty Events API v2 adapter ([below](#pagerduty-events-api-v2)) and a local
operator-inbox file adapter.
Deterministic transports and the real Nightshift-to-NQ replay interface have been
exercised locally. Local-inbox source `1ef98c9c9934ea9dac481d3dcdc42fb7dd2bd073`
passed 107 application tests, reusing 195 unchanged core tests. A four-component
disposable run performed actual Monitor acquisition, NQ admission, Pulse support
checks and Nightshift replay, then retained one local file; duplicate submission
returned the same delivery identity without a second write. The caller example
is in the [Monitor/Pulse source distribution](https://github.com/unpingable/constellation-nightshift/tree/main/integrations/monitor-predicate-support).
This does not qualify a recurring deployment or human acknowledgment.

Live destination delivery has been verified by hand-run operator-assertion
intents, each with a person confirming receipt:

- Slack on 2026-10-01, on a disposable VM and on the Linode observation host.
  Records: Cartography `audit/2026-10-01-observation-profile-vm-result.md` and
  `audit/2026-10-01-linode-observation-profile-live.md`.
- Discord on 2026-10-02, on the qualification host with the released 0.2.0 binary.
- PagerDuty on 2026-10-02, against a non-production service: trigger, repeated
  trigger on one dedup key, resolve.

The Discord and PagerDuty runs are recorded in Cartography
`audit/2026-10-02-notification-sinks-live.md`. No component
emits intents on its own, and acknowledgment is not implemented. Do not
describe the adapters or retained outbox as a completed notification
migration.

For retained saved checks, the separate [saved-check attention adapter](SAVED_CHECK_ATTENTION.md)
replays Nightshift's task-specific decision before delivery. An actual local
Monitor/NQ/Nightshift example exercised that path, maintenance annotations,
exact duplicate custody and changed-receipt refusal. It does not substitute a
Pulse project-predicate receipt or require Pulse for this particular use case.

Detection, attention and delivery are separate. A diagnostic supplies evidence;
Nightshift/operator policy decides what warrants attention; this adapter attempts
delivery and retains factual state. Human acknowledgment is not implemented.
No notification, acknowledgment or maintenance declaration grants execution authority.

## Sinks are not interchangeable

Notification sinks are not semantically interchangeable.

PagerDuty is an interruption channel. Page eligibility is an evaluator decision and must be explicitly expressed in the notification intent. The PagerDuty transport refuses non-page intents.

A PagerDuty event being accepted/enqueued does not establish that a human received, acknowledged, understood, or acted on it.

Every intent carries a closed `response_class`: `informational`, `attention`
or `page`. The evaluator (Nightshift, operator policy or a site script)
assigns it. NQ never derives it from `severity`, `action`, the condition or
the rule. On a PagerDuty route, an intent whose `response_class` is not `page`,
or is absent, is retained with the refusal reason `response_class_not_page`
before any routing-key resolution or network call. The check runs before
Nightshift replay, so a non-page intent always yields this retained refusal,
even when the enrolled verifier would refuse its receipt. That applies to
`resolve` as well: the resolve of a page is page-class. A page trigger
followed by a non-page resolve leaves the PagerDuty alert open: the resolve is
refused and nothing is sent, so the alert stays open until a resolve with
`response_class: page` is accepted. The refusal is counted under
`refused`, is an unresolved failure in `nq status export`, and appears in
`notification inspect` under `pagerduty.last_event.detail.reason`. A
`response_class` value outside the closed set is a malformed intent and is
refused as a command error, with no retained record.

Slack, Discord and local-inbox routes take any class, including `page`. The
class is optional there and defaults to `attention`; the message starts with
it, for example `[page] Attention required: ...` or, in a local-inbox
message summary, `[attention] check storage`.

## Configure and inspect

Add a route to an explicit NQ configuration whose database, socket, admissions
and helper-runtime paths are all selected by the operator:

```toml
[[notification_routes]]
reference = "operations"
transport = "slack" # or "discord"
endpoint_secret_locator = "NQ_OPERATIONS_WEBHOOK_URL"
timeout_ms = 10000
max_response_bytes = 32768
```

For a local operator inbox, no secret or network route is used. The directory
must already be an absolute, canonical, operator-owned directory satisfying
NQ's protected runtime-root checks (including exact mode `0711` and no
write-granting POSIX ACL).

```toml
[[notification_routes]]
reference = "local-operations"
transport = "local_file"
local_inbox_directory = "/absolute/operator-owned/nq-inbox"
timeout_ms = 10000
max_response_bytes = 32768
```

The locator names an environment variable, not a secret value. Provision it
locally without committing or printing the webhook URL. HTTPS is required;
redirects are disabled. Response bodies are not consumed or logged; the
`max_response_bytes` setting does not establish a separate header/body transfer
budget. One request is attempted, with no automatic retry or fallback.

```sh
nq --config ./nq.toml config check
nq --config ./nq.toml notification submit --intent ./intent.json --route operations
nq --config ./nq.toml notification inspect --notification-id ID
```

An explicitly prepared local intent uses the configured logical destination
identity, then writes one bounded JSON message only through the local command:

```sh
nq --config ./nq.toml notification deliver-local \
  --intent ./intent.json --route local-operations
```

The canonical intent must use `destination_identity` exactly
`local-inbox:local-operations`. It can use `attention_kind:
operator_assertion` with no receipt bundle, or `attention_kind:
nightshift_receipt` with the exact replay material described below. Neither kind
establishes that a person read the resulting file.

The message contains what happened, the inspection reference, and a hashed
directory binding; it does not contain the raw local path, credentials, the
full receipt bundle, or an acknowledgment. A created and synced file establishes
only that local delivery artifact. It does not establish that a person saw it,
that attention was acted on, or that the underlying work succeeded.

Without `--enable-network`, submission retains a refusal without contacting or
resolving the endpoint. It is not a dry run that can later be promoted: repeating
that same event/destination returns its existing record. Any real message needs
explicit operator authorization and a deliberately prepared delivery identity;
never invent new event IDs to bypass an uncertain previous attempt. PagerDuty
routes are the one exception, because their dedup key makes a repeated send
update the same alert; see [Retry by resubmission](#retry-by-resubmission).

The intent is exact canonical JSON, at most32KiB, with schema
`nq.notification_delivery_intent.v1`. It binds attention kind, event, transition,
policy ID/digest, route reference, destination label, summary and inspection link,
and optionally `response_class` (absent means `attention`).
Keep the summary minimal: what happened, what needs attention and where to inspect.
Do not include credentials, prompts, personal data or private evidence bundles in
message text. NQ cannot determine whether operator-authored prose contains secrets.

## Use a Nightshift decision

A `nightshift_receipt` intent requires an exact replay bundle and route enrollment:
absolute executable path, `sha256:` digest, store locator, approved policy digest
and execution account under `nightshift_attention_replay`. NQ invokes the
[bounded stdin replay interface](https://github.com/unpingable/constellation-nightshift/blob/main/runtime/docs/ATTENTION-REPLAY-STDIN.md)
before creating delivery custody or contacting a destination. Older runtimes
without `--bundle-stdin` refuse; there is no fallback.

The nested receipt must say `ATTENTION_REQUIRED`; its policy and receipt digests
must match the intent and configured approval. The event and transition IDs must
both equal the exact receipt digest. The executable is descriptor/digest checked,
with bounded runtime/output and configured local execution identity. Production
builds retain NQ's separate-account requirements; same-account debug qualification
is not a production identity-isolation claim.

`operator_assertion` is a separate explicit attention kind, not a manufactured
Nightshift receipt. Failed or uncertain work should only notify when its owner
or explicit operator policy produces an applicable attention intent. Raw findings
do not automatically send messages. Replay establishes receipt consistency, not
current conditions, upstream evidence legitimacy or successful underlying work.

## Delivery outcomes and recovery

| State | Interpretation and next step |
|---|---|
|refused|No HTTPS request was dispatched by this occurrence. Inspect configuration and retained state.|
|pending|No delivery attempt has been claimed. The record remains pending; inspect the owner and inputs before taking another action.|
|accepted|For HTTPS, an HTTP 2xx response was received. For `local_file`, exclusive file creation, file sync, and parent-directory sync completed. Neither establishes human receipt.|
|failed|For HTTPS, a non-success HTTP status was received. For `local_file`, exclusive creation failed before a file was created. Neither result proves the destination made no record outside the retained custody boundary.|
|unknown|Transport/result uncertainty, including a claimed attempt without terminal state. Inspect before retrying.|

Exact duplicate event/destination submissions converge on one retained record;
changed intent or rendered content refuses. The destination identity is an
operator label used for deduplication, not independently verified channel
provenance. Inspection exposes state and event count, not raw endpoint secrets
or all internal failure detail. Keep the NQ database and its verified backups.

For `local_file`, NQ retains a descriptor-bound directory identity and uses a
generated notification filename with exclusive creation, mode `0600`, file
sync, and parent-directory sync. An exact duplicate reopens custody without a
second file write. If an error occurs after creation begins, delivery is recorded
as `unknown`; NQ does not overwrite the file, retry automatically, or infer a
human acknowledgment. A failed pre-creation open is distinct from an uncertain
post-creation write. Before custody, NQ refuses a rendered local message larger
than 4 KiB; this is a deterministic input-limit refusal, not a failed or unknown
delivery attempt.

`timeout_ms` and `max_response_bytes` bound HTTPS routes only; they are not a
hard local-filesystem write or sync deadline. Use bounded caller supervision for
the local command. If the process is interrupted after its custody claim, inspect
the retained delivery record before any recovery decision; a claimed or `unknown`
record is not permission to issue another delivery attempt, except by
PagerDuty resubmission as described below.

There is no recursive delivery-failure alert, retry daemon, acknowledgment,
automatic resolution or paging escalation. The PagerDuty adapter below sends an
explicit trigger or resolve that a caller submits; it does not decide either.
Delivery failure must remain visible to the operator without generating an
alert storm. Existing inspection and local/operator handoff remain necessary
until consumer binding has been independently verified.

## Failure visibility in status export

`nq status export` derives the `notification`/`outbox` component from retained
delivery custody each time it is read, once any delivery record exists. It
writes nothing and adds no table or index, so the read scans every retained
delivery event; its cost grows with the store's delivery history.

The detail is grouped by route. For each route it gives counts of `pending`
(retained, never claimed), `claimed_without_outcome` (in flight, or
interrupted), `refused`, `failed`, `unknown` and `accepted` records, the time
of the newest acceptance, and the unresolved failures. A failure is
unresolved when it is the newest terminal outcome of its condition: the
route, plus for a PagerDuty record its `site:component:rule[:target_class]`.
A failure here is `failed`, `unknown`, a stale claim, or any refusal except
three, so a missing or malformed routing key and `response_class_not_page`
count. The exceptions are the
deliberate `network_dispatch_not_explicitly_enabled` and the saved-check
refusals `saved_check_attention_event_not_current` and
`saved_check_attention_event_time_invalid`. Those two refuse an owner decision
that was stale or malformed when it reached NQ; they say nothing about whether
the route can deliver, so they do not degrade it. They stay in the `refused`
count and in `inspect`. An acceptance on another route or for another
condition does not resolve a failure. Each listed failure shows its id,
condition, outcome, time and only the closed fields `reason`, `http_status`
and `retry_class`. At most ten are listed per route, newest first; the count
is exact.

A claim without an outcome is in flight for 120 seconds: the longest route
timeout (60 s) plus a margin. After that no send can still be running, so the
summary counts it as `unknown`, with reason `claim_stale`, and it can be an
unresolved failure. It reads as `unknown` in `inspect` from the start and
blocks rollover.

The component is `degraded`/`delivery_failure_unresolved` when any
unresolved failure exists, `healthy`/`delivery_in_flight` when a record is
pending or has a claim younger than 120 seconds, and otherwise
`healthy`/`delivery_custody_current`. A record that stays `pending` (retained
but never claimed) does not degrade the status. It stays in the counts and
blocks rollover. A store without delivery records still shows the row
written by `nq init`. Destination free text, such as a PagerDuty error
message, appears only in `notification inspect`.

This changes the export for every store that has delivery records, including
Slack-only stores: they now report the computed row instead of the
initialization row (`outbox_empty`). The Slack delivery path is unchanged.
Release notes should say so.

## PagerDuty Events API v2

The `pagerduty` transport sends one Events API v2 event per record to the fixed
endpoint `https://events.pagerduty.com/v2/enqueue`. It uses the Events API only:
no REST API token, acknowledgment, incident query or escalation management, so
it works on a PagerDuty Free plan with an Events API v2 service integration.
Live delivery was verified on 2026-10-02 against a non-production service
(trigger, repeated trigger on one dedup key, resolve, with receipt confirmed in
PagerDuty; Cartography `audit/2026-10-02-notification-sinks-live.md`). The adapter's own tests use a loopback server.

```toml
[[notification_routes]]
reference = "pagerduty-ops"
transport = "pagerduty"
routing_key_env = "NQ_PAGERDUTY_OPS_ROUTING_KEY"
timeout_ms = 10000
max_response_bytes = 4096
```

`routing_key_env` names an environment variable ending in `_ROUTING_KEY`. Its
value must be the 32-hexadecimal-character integration key. NQ reads it only
after custody is retained and `--enable-network` is given. A missing value is
retained as the refusal `routing_key_unavailable` and a malformed one as
`routing_key_malformed`. The key is added to the request bytes only. It is not
in the retained payload (the field is absent, not masked), the content digest,
event details, inspection, status export or any error text, and destination
text is masked if it echoes it. `endpoint_secret_locator` is refused on this
transport; the endpoint cannot be redirected by configuration. See
[`PAGERDUTY_RUNBOOK.md`](PAGERDUTY_RUNBOOK.md) for provisioning.

### Intent v2

A PagerDuty route accepts only `nq.notification_delivery_intent.v2`, and other
routes refuse it. A v2 intent has every v1 field (the summary
may be up to 1024 bytes) and, with the same closed field set:

| field | contract |
|---|---|
| `response_class` | required in effect: must be `page`, or the record is retained as the refusal `response_class_not_page` (see [above](#sinks-are-not-interchangeable)) |
| `action` | `trigger` or `resolve` |
| `condition.site` | bounded site or installation id, 1..=64 of `[a-z0-9._-]` |
| `condition.component` | one of `nq`, `host_posture`, `nightshift`, `docket`, `ag`, `service` |
| `condition.rule` | a beta alert registry anchor; see [`PAGERDUTY_ALERT_MAP.md`](PAGERDUTY_ALERT_MAP.md) |
| `condition.target_class` | optional, 1..=48 of `[a-z0-9._-]` |
| `severity` | `critical`, `error`, `warning` or `info` |
| `runbook_url` | optional `https://` URL, at most 1024 bytes |
| `details` | optional JSON object, at most 4 KiB canonical; key `constellation` is reserved and credential-like key names are refused |

For example, as canonical JSON (compact, sorted keys, no trailing newline):

```json
{"action":"trigger","attention_kind":"operator_assertion","attention_policy_digest":"sha256:<64 hex of your operator policy>","attention_policy_id":"operator-test","condition":{"component":"nq","rule":"nq-no-fresh-acquisition","site":"example-site","target_class":"demo"},"destination_identity":"pagerduty:pagerduty-ops","inspection_reference":"nq notification inspect","response_class":"page","route_reference":"pagerduty-ops","schema":"nq.notification_delivery_intent.v2","severity":"critical","stable_event_id":"test-trigger-1","summary":"TEST: NQ route qualification","transition_id":"test-1"}
```

`severity` is PagerDuty's payload field only. It does not make an intent
page-worthy, and a `critical` intent without `response_class: page` is
refused.

v2 records retained before NQ 0.2.2 have no `response_class`. They are read
as legacy: `notification inspect` and status export read them, and inspect
shows `pagerduty.response_class` as `null`. NQ does not assume they were
pages. Resubmitting one is retained as the refusal `response_class_not_page`;
to page again, submit a fresh intent with `response_class: page`.

A condition names a stable class, never an event. NQ refuses, before any
custody, a condition value that contains `sha256`, 32 or more consecutive
hexadecimal characters, a UUID, a run of 8 or more digits, a `YYYY-MM-DD` date,
or only digits. Like every other intent validation error this is a command
error, not a retained record, so the event identity remains unused. The
detection is pattern-based; it cannot recognize every per-event identity, and
NQ cannot tell whether `details` prose holds a secret.

### Dedup identity

The PagerDuty `dedup_key` is derived, never supplied:

```text
constellation:{site}:{component}:{rule}            (no target_class)
constellation:{site}:{component}:{rule}:{target_class}
```

For example `constellation:example-site:nq:nq-no-fresh-acquisition:demo`. A trigger
sends `event_action`, `dedup_key` and `payload` (`summary`, `source` = site,
`severity`, `component`, `group` = rule, `class` = target class, and
`custom_details` = `details` plus `constellation` {schema, stable event id,
transition id, intent digest, inspection reference}), with the runbook as a
link. A resolve sends only `event_action` and `dedup_key`. The retained payload
is this event without `routing_key`; `notification submit` and
`notification inspect` show the dedup key.

NQ records the v2 intent bytes in the existing intent custody row. That table's
`intent_schema` column admits only the v1 value and names the custody row
format; the submitted schema is the `schema` field inside the retained intent,
as it already is for local-inbox wrappers. No store migration is involved.

### Outcomes

| PagerDuty response | Retained outcome | `reason` / `retry_class` |
|---|---|---|
| HTTP 202 with JSON `status: "success"` | `accepted` | — |
| other 2xx | `unknown` | `success_not_confirmed` / `resubmit_safe` |
| 429 | `failed` | `rate_limited` / `retryable` |
| 5xx | `failed` | `server_error` / `retryable` |
| other 4xx | `failed` | `rejected` / `permanent` |
| connection refused or unreachable | `failed` | `connect_failed` / `retryable` |
| timeout or loss after the request may have been sent | `unknown` | `timeout_after_dispatch` or `transport_error_or_response_loss` / `resubmit_safe` |

The detail also keeps the HTTP status and, when present, PagerDuty's `status`,
`message` and up to five `errors`, each at most 256 characters with control
characters removed and key-shaped runs masked. A response body is read up to
`max_response_bytes`. `accepted` means PagerDuty accepted the event for
processing (it was enqueued). It does not establish that an incident exists,
that anyone was paged or that anyone read it. A well-formed but wrong or
revoked routing key also receives HTTP 202 `success`: PagerDuty drops the
event silently. The only confirmation is the alert appearing in PagerDuty.

### Retry by resubmission

The one-claim, one-terminal custody of each record is unchanged, and NQ never
retries inside a record. A retry is a new record: submit an intent with a new
`stable_event_id` and the same condition, or derive one from a retained record:

```sh
nq --config ./nq.toml notification resubmit \
  --notification-id ID --stable-event-id NEW-EVENT-ID --enable-network
```

`resubmit` copies the retained v2 intent with only `stable_event_id` replaced
and submits it to the same route, under the current submission validation, so
a legacy record without `response_class` becomes a retained
`response_class_not_page` refusal. It refuses:

- a record whose outcome is `accepted`;
- a v1 record;
- the record's own event id;
- any record that is not the newest for its condition on its route. The
  error names the later record.

The newest-only rule compares records with the same route reference. Two
routes that point at the same PagerDuty service do not see each other's
records, so configure one route per PagerDuty service. The check is also not
atomic with the submission it precedes. If another submission for the same
condition happens at the same moment, both can proceed; serialize manual
recovery for a condition.

It accepts `failed`, `unknown`, `refused` and `pending` records that are the
newest for their condition.

The newest-only rule matters because PagerDuty matches a dedup key only
against an open alert. Resending an older trigger after a later resolve was
accepted would open a new alert for a cleared condition. Resending an older
resolve after a later trigger would close the newer alert. When the newest
record is resubmitted, it carries the same dedup key, so PagerDuty updates the
alert that record was about instead of opening a second one. A later
`resolve` for the same condition resolves exactly that alert. The original
record keeps its outcome.

A resolve resolves only the exact dedup key. A resolve that omits a
`target_class` the trigger had (or adds one) gets `accepted` and closes
nothing.

A Nightshift-receipt intent binds its event id to the receipt digest, so its
resubmission fails replay; mint a new owner decision instead.

### Restart

Restart semantics are those of every HTTPS route. A record retained before its
claim stays `pending`; a crash after the claim reads as `unknown`; neither is
sent again by NQ. Under the newest-only rule, an `unknown` (or `pending`)
PagerDuty record is safe to resubmit: if the first request did reach
PagerDuty, the second carries the same dedup key and updates the same alert.

Rollover refuses while any `pending` or `unknown` record exists, and
resubmission leaves the original record as it is. Timeouts make `unknown` a
normal PagerDuty outcome, so a single one blocks rollover for the life of that
store. The current contract has no way to mark such a record superseded; that
is a known follow-up.
