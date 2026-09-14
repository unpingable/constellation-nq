# Deliver attention about a saved check

The additive saved-check adapter uses the existing `nightshift_receipt` intent
kind and configured `nightshift_attention_replay` route. It accepts exactly
`nightshift.saved-check-attention-replay-bundle/v1`, alongside the existing,
separate Pulse project-predicate bundle. The two evidence contracts are not
aliases. The route pins the Nightshift executable digest and approved policy
digest; unsupported bundles and policy or receipt mismatches refuse.

Nightshift owns the attention decision and durable receipt. NQ recomputes that
receipt using `nightshift --store STORE saved-check attention-replay
--bundle-stdin`. The intent's stable event and transition IDs must both equal
the exact receipt digest. Its inspection reference must equal the receipt's
reference. `ATTENTION_REQUIRED` or `LOSS_OF_ASSURANCE` with explicit delivery
eligibility is required. These are not action authorization or evidence of a
successful check. A covered maintenance declaration annotates a failed check;
this closed policy does not automatically suppress its notification.

The receipt preserves source currentness separately from its fixed attention
event window. Before a new delivery claim, NQ checks that window against its
own clock; it cannot exceed 300 seconds from the retained condition projection.
An expired or future event is retained as a refused delivery without contacting
a destination. An exact duplicate returns existing custody instead of renewing
the window. Inspect uncertain existing delivery before any different submission.
This is a snapshot-currentness check at delivery admission, not atomic clock
agreement or retroactive cancellation after delivery has started.

For a disposable local inbox, use the existing `notification deliver-local`
command. Slack and Discord use the existing explicitly enabled HTTPS commands;
source support does not establish live delivery. No new daemon, retry mechanism,
provider route, acknowledgment or downstream execution authority is introduced.
See [Notifications](NOTIFICATIONS.md) for provisioning, minimal message fields,
secret handling and recovery. HTTPS messages contain only the summary and
inspection reference. Local inbox messages also include event, route and
destination identities, the directory-binding digest and a statement that human
receipt is not established. The replay bundle stays in local custody. Operators must choose
public-safe summaries for external destinations. The existing 32 KiB canonical
intent bound still applies; larger evaluation bundles refuse rather than being
silently truncated or transmitted through another route.

Focused qualification covers the closed replay union, malformed/expired time
refusals, fractional window bounds, delivery-surface refusal, exact duplicates
when the producer or inbox is unavailable, and changed-material refusal.
Those deterministic checks do not establish real Nightshift receipt replay or
a supported released saved-check-to-notification profile; actual composition
qualification is a separate required check.
