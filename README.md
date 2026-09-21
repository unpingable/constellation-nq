# Constellation NQ

NQ collects and checks bounded evidence for a specific question. It records what
was admitted, what was refused, and the diagnostic conclusion its profile can
support. It does not authorize or execute the work that might follow.

The current immutable Constellation integration release is
[0.1.0-alpha.6](https://unpingable.com/constellation/releases/0.1.0-alpha.6/guide.html).
Its `reviewed-local-copy/v1` profile uses NQ for bounded host-observation
admission before one reviewed, authorized-once local effect. The public
newcomer procedure reproduces retained evidence without repeating the provider
call or effect. This does not qualify a complete monitoring deployment, live
notification delivery, or a transfer of Classic NQ operational responsibility.

For a smaller starting point, [run a saved check](docs/SAVED_CHECKS.md) against
a disposable SQLite source and inspect its retained result. The
[notification adapter](docs/NOTIFICATIONS.md) provides bounded Slack/Discord
delivery mechanics; live destination delivery remains unverified. Saved checks
and maintenance annotations are local capabilities, not a complete recurring
monitoring deployment or a migration approval for Classic NQ.

For the connected local path, [evaluate a saved check and deliver attention](https://unpingable.com/constellation/saved-check-attention.html).
That guide pins the actual Monitor, NQ and Nightshift combination, preserves a
failed result under maintenance, and shows exact replay, one local inbox file,
duplicate handling and retained-state inspection. Public-only reproduction is
verified; human acknowledgment, live webhooks and unattended installation are
not implied. Use the pinned composition rather than arbitrary repository heads.

To keep a past result inspectable, see
[read saved checks from a sealed archive](docs/HISTORICAL_READS.md). This verified
historical read path does not supply automated retention or migration.

> **Source and profile status:** use the tested source pins for your selected
> [integration profile](https://unpingable.com/constellation/integration.html).
> The retained cache-result profile pins `ce0a04a175b6d87ac17395f08fd7bc70ddf1e7b3`;
> saved-check attention and objective-read profiles pin
> `e259852ed58b8c0bf65a629b3c494afba28d9ce9`. Neither is a
> production deployment, an authority switch from classic NQ, or a claim of
> complete host coverage. Start with [the public preview guide](docs/PUBLIC_RELEASE.md),
> the [retained synthetic-cache-result profile HOWTO](docs/SYNTHETIC_CACHE_RESULT.md),
> and [operations/trust limits](docs/OPERATIONS.md). The HOWTO is one bounded
> local profile, not a completed consumer cache workflow.

<details>
<summary>Historical status and authority notices</summary>

> **CLASSIC-RETIREMENT update (2026-09-08):** the operator authorizes native
> replacement contracts and the identified Codex, Monitor, Nightshift and older
> AG consumer migrations. The July restriction below is historical and no longer
> limits that implementation campaign. The integrated runtime candidate is
> `022419593b1065da7e83802d1fb6efc77362f6a1`; exact independent component evidence
> and final integrated witnesses are tracked in Constellation's
> `coordination/CLASSIC_RETIREMENT_COMPLETION_GATE.md` and the campaign recovery
> record. The retirement gate remains open pending those integrated results.
> This authorization does **not** establish fleet cutover, remote publication,
> production deployment, or complete Host Operational Portrait coverage. M2's
> original acceptance stays attached to its original revisions.

## Historical July status (not current campaign authorization)

> **Status (2026-07-28): selected successor development line, not the
> operationally authoritative NQ.** Classic at `~/git/nq-root/nq` remains the
> live authority until NQ-NG earns functional equivalence, isolated parallel
> qualification, and an explicit authority switch. The ratified direction is
> [`docs/NORTH_STAR.md`](docs/NORTH_STAR.md); the cumulative campaign gates are
> [`docs/SEQUENCING.md`](docs/SEQUENCING.md). Host Operational Portrait v1 is
> now a
> [ratified specification](audit/host-operational-portrait-v1-ratification/RATIFICATION_DECISION.md),
> but neither `sushi-k` nor `labelwatch-host` has earned completeness. Classic
> replacement, parallel qualification, and cutover remain unauthorized. The
> minted `v0.1.0` release and post-release provider-intake receipts remain
> frozen evidence. Current main is unpublished, untagged after `v0.1.0`, and
> not deployed. It now includes one narrow canonical
> `nq.diagnostic_execution.v2` production path, the frozen v1 consumer
> boundary, schema-v5 immutable artifact custody, restart-safe inspection and
> exact export/import, and reproducible v1/v2 contract packages. This local
> untagged work is not remotely published and does not yet provide a generic
> host portrait or subject qualification.

</details>

## Product direction

Constellation NQ is a local-first deterministic diagnostic engine and
recursive evidence fabric. For one exact profile, subject, scope, and vantage,
it takes custody of bounded witness or child-NQ testimony, retains accepted
evidence and rejected custody artifacts, and emits only the diagnostic
disposition or typed refusal mechanically supported by that evidence. Helpers
and child nodes receive no authority over NQ conclusions or actions. The
implemented subset is stated separately below.

The product framing is:

> Diagnostics are what monitoring is built on.

Nightshift owns recurrent diagnostic operations and the whole-estate operator
portrait. NQ remains the scoped analysis engine underneath that surface.

The governing rule is:

> Mechanically open integrations, compiled and versioned semantics.

This repository is the selected greenfield successor foundation. Legacy NQ
bytes may be referenced at a cutover, but legacy verdicts are never imported
as current state. Selection authorizes staged successor development; it does
not itself authorize release, deployment, production reliance, or cutover.

The current developer preview contains the protocol/SDK and executable hostile
corpus, explicit profile registry, generic SQLite evidence substrate, bounded
stdio and authenticated persistent-Unix helper supervisors, admission locks,
detector lifecycle, daemon-local API/console, a broad developer-preview
operator CLI, one native host helper, a canonical diagnostic-execution
contract with one bounded live durable emission/export/import path, a Python
wire-compatible specimen, and a bounded Rust compiler
for authority-free system cuts and consumer-specific projections. The cut
contract is not yet wired into daemon storage, NQ evaluation, Porter, NetBox,
or AG. See
[docs/NORTH_STAR.md](docs/NORTH_STAR.md) for the governing product direction,
[docs/SEQUENCING.md](docs/SEQUENCING.md) for the live implementation order,
[the Portrait v1 packet](audit/host-operational-portrait-v1-ratification/HOST_OPERATIONAL_PORTRAIT_V1.md)
for the ratified replacement-completeness contract and current subject
verdicts,
[docs/PORTER_NETBOX_ADDENDUM.md](docs/PORTER_NETBOX_ADDENDUM.md) for the
Porter/QEMU/NetBox system-cut contract and later integration specimens,
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for the exact
developer-preview boundary, and
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for verification commands. The
older [docs/PLAN.md](docs/PLAN.md) is preserved as historical design material;
where it conflicts with the north-star or sequencing record, those current
records govern.
