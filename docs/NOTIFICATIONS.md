# Tell a person that attention is needed

NQ includes experimental bounded Slack/Discord webhook delivery adapters and a
local operator-inbox file adapter.
Deterministic transports and the real Nightshift-to-NQ replay interface have been
exercised locally. Local-inbox source `1ef98c9c9934ea9dac481d3dcdc42fb7dd2bd073`
passed 107 application tests, reusing 195 unchanged core tests. A four-component
disposable run performed actual Monitor acquisition, NQ admission, Pulse support
checks and Nightshift replay, then retained one local file; duplicate submission
returned the same delivery identity without a second write. The caller example
is in the [Monitor/Pulse source distribution](https://github.com/unpingable/constellation-nightshift/tree/main/integrations/monitor-predicate-support).
This does not qualify a recurring deployment or human acknowledgment.
**Live Slack/Discord destination delivery has not been verified.**
Do not describe the webhook adapters or retained outbox as a completed notification
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
never invent new event IDs to bypass an uncertain previous attempt.

The intent is exact canonical JSON, at most32KiB, with schema
`nq.notification_delivery_intent.v1`. It binds attention kind, event, transition,
policy ID/digest, route reference, destination label, summary and inspection link.
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
record is not permission to issue another delivery attempt.

There is no recursive delivery-failure alert, retry daemon, acknowledgment,
automatic resolution/update, paging escalation or PagerDuty integration. Delivery
failure must remain visible to the operator without generating an alert storm.
Existing inspection and local/operator handoff remain necessary until destination
delivery and consumer binding have been independently verified.
