# NQ-ng implementation status

The governing product direction is [`NORTH_STAR.md`](NORTH_STAR.md), and the
current implementation order is [`SEQUENCING.md`](SEQUENCING.md). The older
[`PLAN.md`](PLAN.md) is preserved as historical design material; it does not
override those records. This file reports executable delivery status and does
not turn selected direction into implemented capability.
The separately labeled [`PORTER_NETBOX_ADDENDUM.md`](PORTER_NETBOX_ADDENDUM.md)
records the future disposable-package specimen, persistent-deployment
specimen, and shared system-cut contract. The bounded contract compiler is
implemented; the specimens and live consumer integrations are not. The
addendum does not change the v1 operational-core or authority boundary.

Host Operational Portrait v1 is now an
[operator-ratified specification](../audit/host-operational-portrait-v1-ratification/RATIFICATION_DECISION.md).
That is a policy result, not an implementation result. Neither `sushi-k` nor
`labelwatch-host` has earned Portrait v1 completeness; Classic remains
authoritative; parallel qualification and cutover are not authorized. The
current preview package and executable names are explicitly not the final
production namespace because a bare `/usr/bin/nq` collides with Debian's
unrelated package. The focused blocker-closure unit remains incomplete. The
operator subsequently authorized separate bounded Stage-6 foundation,
published-consumer/concordance, and completeness-map campaigns. Those
campaigns did not authorize deployment, parallel qualification, cutover, or
the missing product breadth listed below. This status document grants no
implementation authority.

Current `main` preserves the frozen versioned
`nq.diagnostic_execution.v1` package and publishes the sibling
`nq.diagnostic_execution.v2` schema, canonical/hostile vectors, verifier, and
package subtree. One actual production-code path commits exact canonical v2
bytes for a fresh admitted `nq.host/v1` load-pressure execution. The supported
v2 outcomes include determinate evaluation, governed provider or detector
refusal, and no-byte provider no-response/acquisition failure; an admission
refusal creates no execution artifact. Each emitted artifact commits in the
same transaction as its exact ordinary run/evaluation history, reopens before
return, and supports restart-safe inspection plus exact export/import through
the developer-preview CLI. The v1 package remains an immutable compatibility
boundary rather than the current live-emission format.

The cross-repository proof remains deliberately narrow: Nightshift intake is
not durable, both lab vantages share one local failure domain, only the
existing host load-pressure family emits the contract, pre-v5 history is not
backfilled with invented artifacts, the production namespace and identity
catalog remain records-only policy, and neither production subject is
involved.

## Current developer preview

The repository implements the stage-one operational spine:

- the `nq` operator CLI and resident `nqd` scheduler;
- strict version-pinned NDJSON helper contracts, schemas, fixtures, Rust DTOs,
  and an independent Python conformance specimen;
- one-shot stdio and supervised request/response Unix carriers;
- compiled profile registration, strict profile validation, typed projection,
  and compiled detector evaluation;
- explicit helper test/admission/rotation/rollback/revocation with immutable
  admission history and drift refusal;
- a schema-v9 append-only SQLite evidence substrate. It retains schema v3's
  exact raw/report/refusal/evaluation/finding/status custody, schema v4's
  versioned provider-intake parent, a distinct NQ-derived local-provider
  admission, an exact local-watcher-run subtype, and a durable acknowledgment
  returned only after commit. Schema v5 adds immutable diagnostic-artifact
  commitments, exact payload custody, exclusive local/import origins, durable
  import events, typed unsupported/unavailable/corrupt access states, and
  exact rematerialization. The only live provider kind is the existing
  NQ-controlled local helper; this is not a remote or provider-neutral intake
  service;
- one atomic collection-completion boundary: the provider attempt, local
  watcher run, exact native outcome and raw capture, raw submission when one
  exists, admission or linked refusal, report, evaluations/findings, status,
  sequence/watermark, and provider-intake acknowledgment become visible
  together. The acknowledgment is returned only after commit and means durable
  custody plus canonical processing, never admission, health, testimony, or
  authority. SQLite assigns report and evaluation order inside that transaction;
- versioned governed collection/evaluation/refusal carriers: non-admitted
  collection results remain V1, admitted results are V2 with their exact
  ordered `EvaluationEnvelopeV2` set, and the outer evaluation envelope wraps
  `EvaluationResultV1` without semantic erasure. They preserve
  exchange-timeout phase, retryability, structured details, profile semantic
  identity and boundary, and stable refusal linkage through storage, protocol,
  daemon/API, CLI/status, backup, and immutable cold-archive reopening. A
  `CannotEvaluate` envelope is producer-closed to the detector boundary/code,
  exact refusal message/summary, and absence of affirmative evidence;
- consistent finding/status DTOs through CLI export, local Unix HTTP API,
  bounded public SQL, and an opt-in (off-by-default) loopback server-rendered
  console; current typed status is V3, governed findings are V3, and immutable
  evaluation history is exposed through bounded, frozen
  `nq.evaluation_history.v1` pages (`/v1/evaluations` and
  `nq evaluations export`). V2 status returns an explicit conflict whenever
  evaluations exist, and older routes fail explicitly when they cannot
  represent the current carrier;
- a frozen `nq.diagnostic_execution.v1` contract package, a sibling canonical
  `nq.diagnostic_execution.v2` package, and one bounded live v2 path for the
  existing `nq.host.load_pressure/v1` diagnostic. The live path preserves
  determinate results, governed received-input or detector refusals, and
  typed no-byte provider no-response/acquisition failures without converting
  admission refusal into an execution. The artifact commits with its exact
  source history, reopens before return, and is available through
  read-only `diagnostics qualify`, `diagnostics inspect`, exact-byte
  `diagnostics export`, and custody-only `diagnostics import`. Qualification
  emits `nq.diagnostic_admission_provenance.v1` only after exact local v2
  history reopens, binding source genesis, artifact bytes, run/evaluation,
  provider intake, admission context, profile semantics, and judgment when
  present. Imported custody remains explicitly unauthenticated and cannot be
  qualified. Qualification, import, and access grant no freshness, reliance,
  authorization, or action and do not create a general historical emitter.
  The same exact watcher may now perform one explicit V3-bound successor via
  `diagnostics acquire-next-linode-origin`: a new caller-owned acquisition ID
  obtains fresh origin evidence, one provider invocation, and one
  occurrence-scoped diagnostic artifact. `diagnostics replay-substrate-origin`
  has no helper/provider surface and returns only completed historical bytes.
  Neither command defines cadence or automatic retry;
- an optional bounded recurring diagnostic office, separate from `nqd` and
  Nightshift cadence. A content-addressed deployment safety envelope maps exact
  watcher semantics to explicit coordination domains; one finite immutable
  operator enrollment selects an anchored fixed interval, closed startup and
  missed-slot behavior, bounded retries/failure pause, occurrence limit, and
  exclusive expiry within that envelope. Repeated one-shot `recurring tick`
  wakeups converge on deterministic slot/acquisition identities. Durable domain
  epochs, provider-start fencing, V3 origin custody, provider-safe spacing,
  store guards, and append-only status prevent replay, restart, clock movement,
  or service-manager overlap from becoming provider authority. The packaged
  timer is disabled and NQ recurrence never creates a Nightshift cycle.
  Schema v9 adds exact local-stdio provider-activity evidence and a separate
  reconciliation event that may release coordination while leaving the
  diagnostic outcome permanently unknown; it adds no force-clear path;
- a native host profile/helper plus the conformance fixture profile;
- strict, bounded `SystemSpecV1` validation and deterministic compilation into
  schema-domain-separated `ScopeCut` proposals, ratification-bound cuts,
  NQ-observation projections, and future Porter-scope projections. Publication
  resolves every observation obligation against the exact compiled profile,
  descriptor digest, full coverage vocabulary, capabilities, and profile-owned
  freshness/subject/scope/vantage rules. Immutable custody verification is
  separate from current-catalog qualification so a historical cut does not
  become corrupt merely because a profile version leaves a later binary; all
  documents are explicitly authority-free. The Porter-shaped projection keeps
  direct plan scope separate from dependency-derived affected consumers and
  their witness obligations; it does not call collection itself a satisfied
  detector/result postcondition;
- Linux systemd, tarball, and Debian packaging that creates identities/layout
  but never initializes, migrates, starts, overwrites, or purges state; and
- hostile tests for protocol planes, profile overclaim, append-only custody,
  evidence lifecycle, executable/config races, cross-process binding mutation,
  checkpoint isolation, provider identity and replay, schema integrity,
  schema-v3/v4 migration, live-WAL backup/restore, diagnostic-artifact
  corruption and missing-byte states, and cold-archive reopening.

The resident `nqd` scheduler remains an implemented preview mechanism, not a
claim that NQ owns the target product's recurrent reasoning posture. The
separate bounded recurring office owns only finite operator-enrolled provider
acquisition slots. Nightshift still owns its reasoning/currentness cadence,
campaigns, transition detection, and the estate-level operational view. NQ
acquisition never fabricates a Nightshift cycle.

The preview treats the SQLite binding history as authoritative. Active
admission files are crash-recoverable materializations, and every collection
or binding mutation is serialized per database/instance across `nq` and
`nqd`. Helpers execute as a separately admitted local account with a bounded,
sanitized launch and no NQ database or admission-directory custody.
Native startup qualification is intentionally limited to supported glibc
ELF64 deployments: it prequalifies a fixed-path recursive dependency closure,
then requires the loader result for the exact retained memfd to match it, and
refuses writable/custom runtime paths or redirecting dynamic tags. It does not
claim to inventory later dynamic-language, plugin, `dlopen`, NSS/PAM, or
driver-module loading; the Python program remains a conformance specimen only.
Helpers are held in a seccomp-locked process group with configured hard
rlimits and service-wide systemd resource ceilings. These are bounded preview
controls, not per-instance cgroup or filesystem quotas; a shared execution
account remains a shared sibling trust and resource domain.

The post-release provider-intake factoring is a semantic boundary inside the
existing vertical slice, not a process split. `ProviderIdentityV1` is derived
from the active NQ admission, retained execution identity, protocol,
configuration, profile, and evaluator facts; a helper response cannot mint it.
`ProviderIntakeRecordV1` retains the complete NQ-owned request/context, native
acquisition outcome, exact raw bytes and digest, and pre-admission response
interpretation. Provider success or refusal is therefore still candidate input
to NQ normalization and policy, not an NQ judgment. See
[`PROVIDER_INTAKE_FOUNDATION.md`](PROVIDER_INTAKE_FOUNDATION.md).

Schema v9 accepts only exact schema v8 directly, or older exact supported
stores through the explicit version-by-version chain. Every source stage
receives its own verified backup and migration receipt. The v3 step
preserves each old watcher run with an explicit
`provider_intake_not_recorded` gap; the v5 step records that historical
diagnostic-artifact commitments were absent and synthesizes none. Migration
through v6 continuity, v7 substrate origin, v8 bounded recurrence, and v9
provider-activity reconciliation likewise
synthesizes no historical authority, origin proof, recurrence enrollment, slot,
or diagnostic occurrence. The v9 migration also synthesizes no provider
activity/quiescence evidence and releases no historical outcome-unknown fence.
Migration therefore invents neither historical intake bytes nor diagnostic
executions.

## Selected successor, deliberately not replacement-ready

The following governing-plan stages are not claimed by this preview:

- conformance to the ratified Host Operational Portrait v1 specification for
  either `sushi-k` or `labelwatch-host`;
- role-oriented core/host/application packaging or an independently installed
  witness authoring and conformance surface;
- static private profile-cohort assembly, cohort lifecycle, or recursive child
  disposition intake;
- ZFS, SMART, GPU, log-activity, and Prometheus sample-lane parity;
- notification delivery workers and retention automation;
- a historical multi-version migration chain and full install/upgrade matrix;
- broad durable Nightshift conversion, installed recurrence, and shipped-binary
  contract tests. One exact local read-only importer and additive concordance
  evaluator are qualified separately, without durable intake or live-subject
  correspondence;
- an operator-approved legacy cut manifest produced from an actual old NQ;
- DNS/TLS/reachability/path observation profiles;
- WLP custody transport, remote enrollment, or fleet administration;
- an independently deployed provider, provider-neutral durable intake,
  provider-owned sequence protocol, remote submission surface, plugin host, or
  physical monitoring split;
- claims, governed inquiry, remediation/action authorization, or authority of
  any kind;
- daemon/SQLite/API/CLI publication or consumption of system cuts, NetBox
  snapshot import, Porter plan or receipt integration, AG cut binding, the
  disposable Noble QEMU specimen, and the `sushi-k` deployment described by
  the Porter/NetBox addendum;
- typed endpoint, persistent-storage, backup-capability, and actuation-surface
  properties, plus compiled expected detector/result semantics for transition
  postconditions.

There is no legacy importer or verdict compatibility mode. A future cut may
reference an immutable legacy manifest, but it must not import legacy findings
as current nq-ng state.

## Acceptance posture

The local acceptance suite is documented in [`DEVELOPMENT.md`](DEVELOPMENT.md).
The bounded 2026-07-17 runtime-hardening campaign is recorded separately in
[`../hardening/CAMPAIGN_2026-07-17.md`](../hardening/CAMPAIGN_2026-07-17.md).
Its system-cut mutation, environment-perturbed release assembly, partial-write,
and extracted-package checks passed locally. The Noble QEMU runs exercised the
package lifecycle, real cross-UID AF_UNIX custody, parent-side helper
socket-mode enforcement, and byte-tamper/helper-drift refusals. The 2026-07-20
mint-gate audit found that the old candidate's historical run was
insufficiently sealed: its internally valid 50-file manifest omitted mandatory
`guest-results/RESULT`. The same audit closed the dependency's scope as
release-required and found package-level refusal-preservation failures.
Neither historical run is a current mint qualification, and the exact
`44e7bd1a…` candidate remains blocked. See
[`HARDENING_PROGRAM.md`](HARDENING_PROGRAM.md) §8 and
[`../audit/REFUSAL_PRESERVATION_CROSSWALK.md`](../audit/REFUSAL_PRESERVATION_CROSSWALK.md)
for the scope, and
[`../audit/receipts/run-2026-07-20-qualification-repair-r4/RECEIPT.md`](../audit/receipts/run-2026-07-20-qualification-repair-r4/RECEIPT.md)
for the authoritative clean-pin blocked verdict.

The semantic transport repair is clean-pinned at
`2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`. Its r5 admissibility ledger passes
all three active controls and records both mutation commands biting. Rebuilt
package SHA-256
`24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`
is reproducible at epoch zero and passed fresh KVM qualification
`run-2026-07-20-2c41b0a`; the exact 51-file seal includes mandatory
`guest-results/RESULT`. Operator ratification created the local lightweight tag
`v0.1.0` at that exact candidate commit and tree; the package bytes were not
changed. The release is **NQ-V0.1.0-MINTED**. The authoritative receipt is
[`../audit/receipts/run-2026-07-20-qualification-repair-r5/RECEIPT.md`](../audit/receipts/run-2026-07-20-qualification-repair-r5/RECEIPT.md).
Some named kernel boundaries remain **outside this qualification** — executable
memfd policy and the full `SO_PEERCRED` wrong-PID/UID/GID matrix among them.
Any later claim over those boundaries requires its separately documented
unsandboxed Linux package/VM job; no sandbox skip or current four-marker pass is
treated as evidence for them.

The provider-intake foundation begins after the tag from record-only commit
`e3c451f9722cb81dd22af25c52b264e6b888ed81`, tree
`328c41c97f11e57500d9207824d35b086a889454`, on
`campaign/provider-intake-foundation`. It is not part of `v0.1.0` and inherited
neither that release's clean-pin audit nor its package/VM qualification. The
foundation is independently clean-pinned at
`44e556709e629eb3c83d1d74bfbcf12cb4c9a549`, tree
`9aee37f90b93f27296550d9664af5ec574e5bf27`. Its admissibility gate passes with
all three controls and 2/2 biting mutations; rebuilt package SHA-256
`4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`
passed fresh KVM run `run-2026-07-22-44e5567` with the exact corrected 51-file
seal. Its immutable qualification verdict is
**READY-FOR-PROVIDER-INTAKE-RATIFICATION**; the operator subsequently issued
**RATIFY-PROVIDER-INTAKE**, producing the bounded decision verdict
**PROVIDER-INTAKE-RATIFIED** for those exact objects. The qualification receipt
is
[`../audit/receipts/run-2026-07-22-provider-intake-foundation/RECEIPT.md`](../audit/receipts/run-2026-07-22-provider-intake-foundation/RECEIPT.md),
and the separate ratification record is
[`../audit/receipts/run-2026-07-22-provider-intake-ratification/RECEIPT.md`](../audit/receipts/run-2026-07-22-provider-intake-ratification/RECEIPT.md).
Ratification creates no post-`v0.1.0` tag or publication and does not alter the
tagged release.

Delivery proceeds through [`SEQUENCING.md`](SEQUENCING.md). A later stage may
add a profile module, helper, and registry entry, but may not silently move
profile semantics into configuration, SQL, helper-owned verdicts, or a runtime
plugin surface.
