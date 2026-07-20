# NQ-ng implementation status

The governing product plan is preserved verbatim in [`PLAN.md`](PLAN.md).
This file records delivery status; it does not replace or narrow that plan.
The separately labeled [`PORTER_NETBOX_ADDENDUM.md`](PORTER_NETBOX_ADDENDUM.md)
records the future disposable-package specimen, persistent-deployment
specimen, and shared system-cut contract. The bounded contract compiler is
implemented; the specimens and live consumer integrations are not. The
addendum does not change the v1 operational-core or authority boundary.

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
- a schema-v3 append-only SQLite evidence substrate, exact raw and semantic
  identities, mandatory typed refusal linkage for rejected custody, exact
  compiled-profile evaluation identity, store-wide evaluation sequence,
  optional trigger-run linkage, full context and evaluator identity, evaluation
  watermarks, finding events, public views, backup/restore, and an upgrade
  receipt skeleton; old schema v1 and v2 data are preserved as incompatible
  history and are never silently rewritten;
- one atomic admitted-completion boundary: SQLite assigns the report sequence
  inside the transaction, detectors build exact watermarks from that pending
  report, and the run, custody, report, evaluations/refusals/findings, and V2
  run-linked status become visible together. Every completed run requires one
  canonical result. Reopening also binds the exact evaluation set to the
  admission's detector-suite and evaluator-artifact identities, rejecting
  omission, duplication, extension, or substitution even when stored rows and
  the outward carrier were changed coherently;
- versioned governed collection/evaluation/refusal carriers: non-admitted
  collection results remain V1, admitted results are V2 with their exact
  ordered `EvaluationEnvelopeV2` set, and the outer evaluation envelope wraps
  `EvaluationResultV1` without semantic erasure. They preserve
  exchange-timeout phase, retryability, structured details, profile semantic
  identity and boundary, and stable refusal linkage through storage, protocol,
  daemon/API, CLI/status, backup, and immutable cold-archive reopening;
- consistent finding/status DTOs through CLI export, local Unix HTTP API,
  bounded public SQL, and an opt-in (off-by-default) loopback server-rendered
  console; current typed status is V3, governed findings are V3, and immutable
  evaluation history is exposed through bounded, frozen
  `nq.evaluation_history.v1` pages (`/v1/evaluations` and
  `nq evaluations export`). V2 status returns an explicit conflict whenever
  evaluations exist, and older routes fail explicitly when they cannot
  represent the current carrier;
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
  checkpoint isolation, schema integrity, and live-WAL backup/restore.

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

## Deliberately not replacement-ready

The following governing-plan stages are not claimed by this preview:

- ZFS, SMART, GPU, log-activity, and Prometheus sample-lane parity;
- notification delivery workers and retention automation;
- a historical multi-version migration chain and full install/upgrade matrix;
- Nightshift conversion and its mandatory shipped-binary contract tests;
- an operator-approved legacy cut manifest produced from an actual old NQ;
- DNS/TLS/reachability/path observation profiles;
- WLP custody transport, remote enrollment, or fleet administration;
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
mint-gate audit subsequently found that the current candidate's historical run
was insufficiently sealed: its internally valid 50-file manifest omitted
mandatory `guest-results/RESULT`. The same audit closed the dependency's scope
as release-required and found package-level refusal-preservation failures.
Consequently neither historical run is a current mint qualification, and the
exact `44e7bd1a…` candidate remains blocked and cannot inherit the current
source repair. See [`HARDENING_PROGRAM.md`](HARDENING_PROGRAM.md) §8 and
[`../audit/REFUSAL_PRESERVATION_CROSSWALK.md`](../audit/REFUSAL_PRESERVATION_CROSSWALK.md)
for the scope, and
[`../audit/receipts/run-2026-07-20-qualification-repair-r4/RECEIPT.md`](../audit/receipts/run-2026-07-20-qualification-repair-r4/RECEIPT.md)
for the authoritative clean-pin blocked verdict.
The semantic transport repair is implemented in the current working source,
including authoritative V3 evaluation status/history and real host-detector
same-code refusals carried through the governed store/status/backup/reopen path,
with cross-boundary finding contamination refused. Its new clean-pinned admissibility ledger,
rebuilt package identity, and fresh VM qualification are still pending. This
is not a ready or inherited release verdict.
Some kernel boundaries remain **not** qualified and still require the documented
unsandboxed Linux package/VM job — executable memfd policy and the full
`SO_PEERCRED` wrong-PID/UID/GID matrix among them. A sandbox skip is never treated
as release evidence for those boundaries.

Delivery proceeds through the stages in `PLAN.md`. A later stage may add a
profile module, helper, and registry entry, but may not silently move profile
semantics into configuration, SQL, or helper-owned verdicts.
