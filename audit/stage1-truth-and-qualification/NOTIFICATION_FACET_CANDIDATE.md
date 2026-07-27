# Notification Facet Candidate

## Status

Stage-1 architecture candidate and falsification record.

Authority: none.

This document does **not** ratify:

- an `nq-notify` repository, crate, package, binary, daemon, or process;
- a notification wire schema or database;
- a routing language;
- retry, backoff, ordering, deduplication, or retention semantics;
- an exactly-once, at-most-once, or at-least-once guarantee;
- the meaning of `delivered`;
- any Slack, Discord, generic-webhook, or future transport as a required
  product default.

It records the boundary that must be evaluated before implementation.

The corrected ownership stack is:

```text
witness/provider testimony
    -> one bounded NQ diagnostic disposition/refusal
        -> Nightshift recurrence/expiry/campaign and current posture
            |-> typed enterprise output -> Maude or another frontend
            `-> exact alert intent for a diagnostic/operational transition
                    -> nq-notify transport attempt and receipt
```

NQ does not own operational alert intent. A raw NQ finding, evaluation,
disposition, or refusal does not automatically page. Nightshift applies
recurrence and expiry and composes diagnostic results and operational context
over time; humans or agents may contribute separately identified
interpretation. Explicit operator policy decides whether an identified
diagnostic or operational state transition creates alert intent.
AG/Docket remain the owners of separately governed authority and execution.
The primary NQ object remains one diagnostic; monitoring is built by repeating
those diagnostics under Nightshift, not by expanding NQ into a recurring
whole-estate console.

## Evidence basis

Committed source was read through Git objects rather than mutable working-tree
files.

### Classic

| Evidence | Identity |
|---|---|
| Deployed-baseline commit reported by the cutover audit | `361c5cdfa49163c96b550e8a0f38165b49305994` |
| Current committed Classic head | `2e956d27616bcb7e49016b4d7867c9455c4129a7` |
| `crates/nq-db/src/notify.rs` blob at both commits | `e64778e9d7ab112b673b0e01d458ec4263f7fa59` |
| notification-state migration blob at both commits | `128556f4ecdac1c3e877cf0c0d82e52f17811816` |
| ack/dedup migration blob at both commits | `e81aefca37e8e053d87fb99fe8ac61caf57c9fea` |
| notification-history migration blob at both commits | `7f9da7006ee6f1b8e96005e1326906f17b45b352` |

The Classic notification engine and its three notification migrations are
byte-identical between the deployed-baseline commit and current Classic head.
The changes to `nq-monitor/src/cmd/serve.rs` between those commits are startup
configuration/listener-preflight changes; the notification send loop is
unchanged.

### NQ-NG

Committed source pin:

```text
638a1a8507080d2e3653b826b036bf3746b1ba5d
tree f0d375d190292ca4f822d8b4d52ba517193042fb
```

Primary evidence:

- `crates/nq-store/src/schema.sql`
- `crates/nq-store/src/lib.rs`
- `crates/nq-core/src/engine.rs`
- `crates/nq-app/src/cli.rs`
- `crates/nq-app/src/daemon.rs`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/NORTH_STAR.md`
- `docs/SEQUENCING.md`
- `audit/classic-reconciliation/CUTOVER_GAP_MATRIX.md`
- `audit/classic-reconciliation/CUTOVER_PLAN.md`

### Stage-1 census

- [LINODE_CENSUS.md](LINODE_CENSUS.md)
- [SUSHI_K_CENSUS.md](SUSHI_K_CENSUS.md)
- [FRESH_OPERATOR_AUDIT.md](FRESH_OPERATOR_AUDIT.md)

No remote host was accessed for this subtask. Endpoint and recipient secrets
remain redacted.

## Candidate verdict

There are three distinct ownership planes:

| Plane | Owner | Owns | Must not claim |
|---|---|---|---|
| Diagnostic output | NQ | one exact typed diagnostic disposition or refusal for a scoped, bounded subject and question, with its evidence/custody/admissibility/coverage boundary | operational composition, alert intent, route, attempted delivery, operator attention |
| Operational alert intent | Nightshift plus explicit operator policy | recurrence, expiry, campaigns, current posture, and the exact diagnostic or operational state transition that warrants notification; policy and route identity | a new NQ diagnostic fact, evidence reinterpretation, transport success, or action authority |
| Delivery and custody | candidate notification facet | bounded rendering, destination resolution, attempts, retry execution if later authorized, and attempt/result custody | diagnostic authority, alert-intent creation, operational disposition changes, human attention, or repair authority |

This split is the candidate. A separate repository or process is not.

`nq-notify` is therefore only a convenient name for the third responsibility.
The candidate remains valid if a later falsification campaign shows that the
best implementation is an in-process worker, a separate service, or another
shape, provided the ownership and custody boundaries remain testable.

## Plane 1: NQ owns exact diagnostic dispositions and refusals

NQ selects the exact required evidence, checks custody, admissibility, and
coverage, and evaluates one scoped, bounded subject and question. Its
notification-facing source must therefore be a stable typed diagnostic
disposition or refusal. NQ-to-NQ recursion may carry that result as bounded
testimony for the same exact parent diagnostic question; it does not turn NQ
into an operational composer.

NQ-NG currently has immutable `finding_events` linked to exact evaluations and
evidence.

The committed event carries:

- `event_id`, `finding_id`, and monotone event/evaluation revisions;
- lifecycle kind: `opened`, `updated`, `resolved`, `reopened`, or
  `operator_updated`;
- instance, profile, detector, detector-semantic, and evaluator-artifact
  identity;
- exact subject;
- condition state: present, explicitly absent, or cannot evaluate;
- visibility state: sufficient, partial, stale, missing, or refused;
- operator work state;
- severity and summary;
- limitations, safe next checks, freshness, basis, optional refusal, and
  historical references;
- exact admitted evidence references.

Those records are useful diagnostic scaffolding, but this Stage-1 candidate
does not ratify `finding_events` as the notification carrier. NQ must expose an
exact typed disposition or refusal without requiring Nightshift, a notifier,
or a frontend to scrape rendered text, open private tables, or reconstruct
authority from an ordinary endpoint. The carrier must bind any contributing
finding/evaluation identities rather than silently replacing them.

NQ does not establish, merely by opening or updating a finding or emitting a
diagnostic result, that:

- anyone should be paged;
- the event belongs on Slack, Discord, email, or another destination;
- quiet hours, digests, escalation, or suppression apply;
- a delivery was attempted or accepted;
- an operator saw, understood, acknowledged, or acted on it.

Notification failure must not mutate the NQ finding into a different
condition, visibility, severity, or disposition. Conversely, successful
delivery must not increase the authority of the finding.

## Plane 2: Nightshift and operator policy own alert intent

Nightshift composes exact diagnostic results and operational context over
time, including recurrence, applicability, expiry, and campaign state. Humans
or agents may interpret that composition. Explicit operator policy—not NQ, a
detector, or a transport adapter—must own the declared answer to questions
such as:

- which exact diagnostic dispositions or refusals and which operational
  state transitions create alert intent;
- whether present, resolved, stale, missing, refused, or cannot-evaluate states
  notify differently;
- which severities, scopes, applications, or host roles route where;
- whether maintenance, operator work state, quiet hours, grouping, or digest
  policy changes immediate delivery;
- whether escalation or recurrence should re-notify;
- whether a destination is required, optional, disabled, or temporarily
  unavailable.

Nightshift/operator policy evaluation must consume typed NQ dispositions or
refusals and bind every diagnostic input, previous/current state, expiry, and
operational context used to identify the transition. It must not:

- parse Slack/Discord prose;
- change NQ evidence, disposition/refusal, or contributing record identity;
- infer a route from a detector's human summary;
- turn “no alert intent” into “delivered” or “healthy”;
- turn a disabled destination into evidence that no operational condition
  exists.

A later design must decide how Nightshift recurrence/campaign identity,
previous/current state, transition identity, policy identity, version,
effective time, evaluation result, and operator ownership are recorded. This
document does not select that schema.

The important requirement is inspectability:

> “Why was this result not sent?” must be answerable without guessing whether
> alert intent was not created, no route existed, the worker was down,
> an attempt failed, or a transport response was ambiguous.

## Plane 3: candidate delivery and receipt custody

A delivery facet may receive only an exact Nightshift/operator alert intent for
an identified diagnostic or operational state transition, plus the bound NQ
diagnostic-output identities and explicit operator-policy result. It may then:

- render a destination-specific projection;
- resolve a destination alias to secret transport configuration;
- enqueue eligible work;
- make a bounded delivery attempt;
- retry only under a separately ratified policy;
- retain bounded, redacted attempt evidence;
- expose its own freshness, queue, worker, and destination coverage.

It must preserve the diagnostic-output, state-transition, alert-intent, and
policy identities it consumed. It must not:

- decide that the absence of alert intent makes a diagnostic output
  semantically unimportant;
- reinterpret evidence, mint a new NQ finding or disposition, or create
  alert intent;
- claim that HTTP success proves human attention;
- treat a timeout as proof the receiver did nothing;
- store secret endpoint values in public receipts;
- use transport success as authorization for remediation.

Destination-specific formatting is a projection. Nothing may parse the
rendered message back into semantic identity.

## Classic: exact current behavior

Classic describes notifications as best effort. The source confirms a more
specific and operationally important behavior.

### Eligibility and recurrence

`find_pending` considers a `warning_state` row only when:

- `notified_severity` is absent or differs from current severity;
- work state is not `quiesced`, `suppressed`, or `closed`;
- visibility is `observed`;
- basis is not `retired`; and
- severity meets configured `min_severity`.

Configured minimum severity accepts `info`, `warning`, or `critical` and
defaults to `warning`.

Durable `notification_history`, keyed by `(host, kind, subject)`, classifies a
candidate as:

- new when no history exists;
- escalated when current severity ranks above the last recorded severity;
- recurring when the same or a lower severity is outside a 24-hour cooldown.

The cooldown does not cause a still-present finding at the same severity to be
retried: after `mark_notified`, `warning_state.notified_severity` equals
current severity, so the row no longer enters `find_pending`. It can re-enter
when severity changes or its lifecycle row is recreated.

### Rendering and routes

Pending findings are grouped by:

```text
(host, state_kind, detector_family)
```

Classic renders generic webhook, Slack, and Discord payloads. Every configured
channel is attempted sequentially for each rollup.

### Transport

Classic constructs one `reqwest` client with a ten-second timeout. For each
configured channel:

- HTTP 2xx is logged as `rollup sent`;
- non-2xx is logged as `rollup failed`;
- transport error or timeout is logged as `rollup send error`.

There is no retry loop, durable queue, per-destination attempt record, lease,
backoff, or dead-letter state.

The network calls occur while the monitor holds its write-database mutex and
before the current generation is sealed. Notification latency and failure are
therefore coupled to the observation/publish loop rather than isolated behind
a durable handoff.

### Mark-notified-on-failure

After all channels have been attempted, Classic executes `mark_notified` for
every finding in the rollup:

```text
for every rollup:
    attempt every configured channel
    ignore success/failure when deciding notification state
    mark every finding notified at its current severity
```

The source comment is explicit: mark every finding “regardless of send
success” to avoid spam on transient failures.

`mark_notified` then:

1. sets `warning_state.notified_severity`, `notified_at`, and a dedup-key
   string; and
2. inserts or updates `notification_history`, including
   `last_notified_at`, last severity, and `notification_count`.

The history schema has no channel, route, HTTP status, attempt identity,
outcome, or delivery receipt. `notification_count` increments once per
finding mark, not once per channel and not once per successful delivery.

Consequences:

- all channels may fail and Classic still attempts to record the finding as
  notified; when that database write succeeds, failure is durably
  indistinguishable from success;
- a same-severity persistent finding is then excluded from future attempts;
- one channel may succeed and another fail, but durable state cannot preserve
  that distinction;
- a timeout is transport-ambiguous but is recorded exactly like a successful
  dispatch for future eligibility;
- a crash after one successful channel but before `mark_notified` can produce
  duplicate sends after restart;
- a crash after marking cannot prove the receiver processed the payload;
- the stored dedup-key string does not supply receiver-side idempotency and is
  not a durable per-channel attempt identity.

Classic's `notification_history` is therefore durable suppression/history
state, not delivery custody.

The separate Classic refusal handle
`TRANSPORT_ACK_NOT_SEMANTIC_RECEIPT.md` correctly states that HTTP or
transport acceptance is not application receipt. The deployed send loop goes
further in the unsafe direction: it records “notified” even without transport
acceptance.

## Stage-1 deployed evidence

### Linode

The read-only Linode census verified:

- Slack and Discord channels are configured;
- minimum notification severity is `warning`;
- endpoint and recipient values were not inspected;
- historic `notification_history` rows exist for service state, stale
  testimony, disk pressure, WAL/freelist bloat, source errors, check failure,
  and service flap.

Given the committed deployed-baseline behavior above, those rows are the
durable output of the mark-notified ledger path. They do **not** establish:

- which channel accepted a payload;
- that either channel accepted it;
- that a receiver displayed it;
- that a human saw it;
- retry or recovery behavior.

The census therefore proves transport configuration and historical
mark-notified activity, not delivery guarantees.

### Sushi-k

The sushi-k census found:

- notification minimum severity is `warning`;
- zero delivery channels are configured;
- the live Classic database exposes five active critical findings.

This is a live example of why semantic finding state and notification
coverage must remain separate. A critical finding can exist correctly while
no outbound delivery path exists. “No channel” must be visible as delivery
coverage state; it must not change or erase the findings.

### Still unknown

Stage 1 has not established:

- required recipients or destination ownership;
- whether both Linode channels are required at cutover;
- acceptable duplicate, loss, latency, or retry bounds;
- quiet-hours, digest, escalation, recovery, or resolution policy;
- whether operator acknowledgment is required;
- how long delivery evidence must be retained;
- whether an explicit manual alert procedure is acceptable temporarily.

## NQ-NG: exact implemented, unratified scaffold

Everything in this section is an observed implementation fact, not selected
notification architecture. The tables, methods, state names, optional
`finding_event_id`, and initialization component status are unratified
scaffolding. They do not establish that findings are notification inputs, that
NQ creates alert intent, or that this storage belongs in NQ.

NQ-NG schema v4 contains append-only:

### `notification_outbox`

- `notification_id` primary key;
- unique `idempotency_key`;
- optional `finding_event_id`;
- `destination_kind`;
- canonical JSON payload;
- `available_at`;
- positive `max_attempts`;
- `created_at`.

### `notification_attempts`

- `(notification_id, attempt_number)` primary key;
- `attempted_at`;
- outcome constrained to `delivered`, `failed`, or `retryable`;
- optional `delivery_identity`;
- canonical JSON detail.

The public notification-status view derives:

- `delivered` if any attempt has outcome `delivered`;
- `failed` if attempt count reaches `max_attempts` without a delivered row;
- `pending` otherwise.

The store provides two write methods:

- `enqueue_notification`;
- `append_notification_attempt`.

Both append their row in an immediate transaction. Outbox and attempts are
protected by immutable update/delete triggers.

### What is not implemented

Committed-source call-site search found no caller of either store method.
There is no implemented:

- finding-to-notification eligibility evaluation;
- stable typed diagnostic disposition/refusal export for notification use;
- Nightshift/operator alert-intent ingestion or identity binding;
- routing or destination registry;
- policy identity or policy-decision custody;
- renderer/transport adapter;
- pending-work query;
- worker, claim, lease, heartbeat, or concurrency protocol;
- attempt scheduler;
- retry or backoff executor;
- destination secret mechanism;
- dead-letter or cancellation behavior;
- notification retention automation;
- end-to-end notification CLI/API;
- live notification worker status.

`nq init` records a one-time component status:

```json
{
  "component_kind": "notification",
  "component_id": "outbox",
  "state": "healthy",
  "code": "outbox_empty",
  "detail": {
    "delivery_enabled": false
  }
}
```

That is fresh-store initialization metadata, not proof of a working
notification subsystem. A future operator surface must not present
`healthy/outbox_empty` with delivery disabled as equivalent to delivery
coverage.

The schema and methods are unratified scaffolding; their existence and field
names do not ratify ownership or semantics:

- the idempotency-key derivation and scope are unspecified;
- destination-kind vocabulary and destination identity are unspecified;
- the optional finding link permits non-finding notifications but no ownership
  law is defined;
- `available_at` and `max_attempts` have no executing worker;
- `delivered`, `failed`, and `retryable` lack a transport-versus-semantic
  receipt contract;
- the public view has no eligible, disabled, in-flight, ambiguous, suppressed,
  cancelled, or policy-refused distinction;
- no ordering, clock, restore/replay, or policy-change behavior is specified.

The committed implementation-status and cutover audit correctly report:

```text
notification outbox/attempt storage exists
notification delivery workers: 0
```

## Required distinctions before design

A future contract must decide whether and how to represent each distinction
below. This list is a requirements probe, not a schema:

1. exact NQ diagnostic disposition or refusal exists versus no diagnostic
   result;
2. Nightshift/operator alert intent exists versus no intent for an exact
   diagnostic or operational state transition under an exact policy;
3. intent exists but no route exists;
4. route disabled or intentionally unconfigured;
5. queued versus not durably queued;
6. not attempted versus attempt started;
7. transport rejected, timed out, or returned an ambiguous result;
8. transport accepted;
9. receiver supplied an application-level semantic receipt, if supported;
10. retry permitted versus retry exhausted or refused;
11. one destination succeeded while another failed;
12. delivery evidence retained versus expired/tombstoned;
13. human acknowledged or acted, if that is ever in scope.

Neither transport acceptance nor an application receipt automatically proves
human attention. Human acknowledgment, incident ownership, and remediation
authority are separate surfaces.

## Falsifying questions

The independent-facet candidate should be rejected or narrowed if it cannot
answer these by execution.

### Boundary value

1. Does process/repository separation actually isolate network, secret, crash,
   and backpressure failure domains, or merely add deployment complexity?
2. Can the same ownership boundary be enforced and qualified in-process with
   less operational risk?
3. Does any required alert-intent rule need new NQ semantic law rather
   than Nightshift/operator policy? If so, which side is wrongly scoped?
4. Can the facet consume immutable Nightshift/operator alert intent with exact
   NQ diagnostic identities without opening NQ's private database or
   reconstructing authority from a read endpoint?

### Transition and policy identity

5. Which exact diagnostic or operational state transitions create alert
   intent: opened, updated, escalated, resolved, reopened, stale, missing,
   refused, expired, or cannot-evaluate?
6. What makes two policy evaluations the same operation?
7. What happens when policy changes while old events remain queued?
8. May a new policy replay old events? If so, who authorizes the replay and
   how is it distinguished from a duplicate?
9. Can rollups preserve every constituent event identity without laundering
   differences?

### Delivery reality

10. What precisely can Slack, Discord, and generic webhooks acknowledge?
11. If the endpoint cannot accept an idempotency key, what duplicate behavior
    is honest?
12. Does HTTP 2xx mean transport acceptance, application acceptance, durable
    queueing, or something undocumented?
13. How are timeout-after-apply and connection-reset-after-apply represented?
14. What happens when one route succeeds and another fails?
15. Can a process crash at every boundary—before enqueue, after enqueue,
    during send, after remote acceptance, and before local attempt commit—
    without silent loss or false delivery claims?

### Operations

16. How does the operator learn that the notifier itself is down without
    depending solely on that notifier?
17. How are queue age, backlog, retry exhaustion, destination refusal, and
    disabled coverage surfaced?
18. Where do endpoint secrets live, who can read them, and how are they kept
    out of payload/receipt/public-view data?
19. What survives backup/restore, and what must not automatically replay?
20. How are clock rollback and long suspension handled for availability and
    retry times?
21. What bounded retention is required for payloads and attempt evidence?
22. Can a literal fresh operator install, configure, test, disable, recover,
    and remove the facet without a source checkout?

### Product need

23. Are Linode Slack and Discord both real cutover requirements?
24. Is sushi-k intentionally no-notification, or is its zero-channel state an
    operational gap?
25. Would a documented manual procedure satisfy the first cut, or is durable
    active delivery mandatory?
26. Does the candidate change an operator outcome compared with a competent
    external alert manager, or should Nightshift hand exact alert intents to
    one?

## Minimum falsification matrix

Any later implementation should be tested at least against:

| Case | Required observation |
|---|---|
| Policy creates no intent | diagnostic output remains intact; no delivery attempt; reason inspectable |
| Intent exists, no route | explicit delivery-coverage failure; diagnostic output unchanged |
| One route succeeds, one fails | per-route distinction preserved |
| All routes reject | no false delivered/notified state |
| Timeout after possible remote apply | ambiguous outcome retained; retry behavior explicit |
| Same intent submitted twice | bounded duplicate behavior under exact idempotency scope |
| Process crash before enqueue commit | no phantom queued state |
| Crash after enqueue commit | work remains discoverable |
| Crash after remote acceptance before local attempt commit | duplicate/loss ambiguity is explicit |
| Retry ceiling reached | terminal state visible; finding unchanged |
| Worker stopped | self-diagnosing coverage loss |
| Queue backlog | age/backpressure visible |
| Opened then resolved before delivery | ordering/coalescing policy explicit |
| Severity escalation | new policy evaluation tied to exact diagnostic output and operational context |
| Missing/stale/refused evidence | not promoted to ordinary condition success/failure |
| Policy revision during backlog | old/new policy identity preserved |
| Backup and restore | no unauthorized replay |
| Secret-bearing destination | no secret in logs, public views, payload receipts, or archives |
| Clean install | documented worker/disabled state and first bounded delivery test |

Passing storage-unit tests alone cannot earn notification delivery.

## Cutover requirements

Classic remains notification authority until one of two paths is explicitly
accepted:

1. qualified replacement delivery; or
2. a signed, time-bounded manual coverage procedure.

Before an authority switch:

### Requirements recovery

- identify required recipients and route owners without checking secrets into
  the repository;
- decide whether Linode Slack, Discord, or both are required;
- decide whether sushi-k intentionally has no route;
- ratify which exact diagnostic or operational state transitions create alert
  intent, including escalation, recurrence, resolution,
  suppression, quiet-hours, and digest expectations;
- define acceptable loss, duplication, latency, retry, and retention bounds;
- define whether any receiver offers a semantic receipt beyond HTTP status.

### Contract and implementation

- preserve exact NQ disposition/refusal and contributing finding/evaluation
  identities;
- bind every Nightshift/operator alert intent to the exact state transition,
  diagnostic inputs, operational context, and policy identity;
- keep alert-intent decisions distinct from delivery attempts;
- keep delivery outcomes distinct from human acknowledgment;
- expose disabled, missing-route, queued, attempted, partial, ambiguous,
  failed, exhausted, and delivered coverage as later-ratified typed states;
- redact secrets and bound retained response material;
- self-diagnose worker, queue, and destination failure;
- prevent notification failure or success from changing NQ finding semantics;
- document backup, restore, replay, upgrade, rollback, and removal.

### Qualification

- run the falsification matrix with deterministic receivers;
- run an authorized live receiver test for every required production transport;
- prove partial multi-channel behavior;
- inject HTTP rejection, timeout, reset, slow response, worker crash, database
  contention, restart, clock change, and restore;
- prove current NQ collection/evaluation continues when delivery is slow or
  unavailable;
- prove a fresh operator can inspect why a notification did or did not happen;
- compare diagnostic outputs, Nightshift/operator alert intents, and
  actual delivery behavior with Classic during an isolated parallel window.

### Authority switch

- record the last Classic finding and mark-notified times;
- preserve Classic configuration and notification history in the frozen
  archive, but do not import it as current NQ-NG delivery state;
- avoid unplanned dual paging during parallel qualification and cutover;
- drain, explicitly abandon, or otherwise account for every pre-switch queued
  item under a ratified procedure;
- verify replacement delivery or manual coverage immediately before disabling
  Classic;
- retain a rehearsed rollback that does not silently replay old notifications.

## Nonclaims

This record does not claim that:

- NQ-NG notification scaffolding is defective merely because it is incomplete;
- an independent process is necessarily safer;
- Slack or Discord must remain supported;
- transport acceptance can become semantic receipt through better naming;
- exactly-once delivery is achievable;
- every NQ finding, evaluation, disposition, or refusal should create
  alert intent;
- operator policy can authorize remediation;
- Classic historic notification counts are successful-delivery counts;
- the candidate facet is implemented, qualified, packaged, or selected.

## Disposition

`nq-notify` remains a candidate independent facet.

The ownership split is strong enough to guide Stage-1 requirements recovery:

```text
exact NQ diagnostic disposition or refusal
    -> Nightshift/operator alert intent for an identified state transition
        -> nq-notify delivery attempt and receipt custody
```

The implementation shape and all retry/dedup/delivery semantics remain
unratified until the falsifying questions and deployed requirements are
answered.

No code, schema, configuration, remote system, commit, tag, or release was
changed by this audit.
