# Tell a person that attention is needed

NQ includes an experimental, bounded Slack/Discord webhook delivery adapter.
Deterministic transports and the real Nightshift-to-NQ replay interface have been
exercised locally. **Live destination delivery has not been verified.** Do not
describe the adapter or retained outbox as a completed notification migration.

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
|refused|No request was dispatched by this occurrence. Inspect configuration and retained state.|
|pending|No delivery attempt has been claimed. The record remains pending; inspect the owner and inputs before taking another action.|
|accepted|HTTP2xx received; this does not prove a human saw the message.|
|failed|Non-success HTTP status received; do not assume the destination made no record.|
|unknown|Transport/result uncertainty, including a claimed attempt without terminal state. Inspect before retrying.|

Exact duplicate event/destination submissions converge on one retained record;
changed intent or rendered content refuses. The destination identity is an
operator label used for deduplication, not independently verified channel
provenance. Inspection exposes state and event count, not raw endpoint secrets
or all internal failure detail. Keep the NQ database and its verified backups.

There is no recursive delivery-failure alert, retry daemon, acknowledgment,
automatic resolution/update, paging escalation or PagerDuty integration. Delivery
failure must remain visible to the operator without generating an alert storm.
Existing inspection and local/operator handoff remain necessary until destination
delivery and consumer binding have been independently verified.
