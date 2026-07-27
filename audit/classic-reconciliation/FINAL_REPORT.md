# NQ-NG / NQ Classic reconciliation and cutover survey

Audit date: 2026-07-27

Scope: local repositories only. No production contact, push, deployment,
release, tag, remote configuration, history rewrite, or Classic modification
was performed.

## 1. Outcome

NQ-NG is the cleaner successor architecture candidate. It already has the
stronger foundation for bounded acquisition, provider intake, raw custody,
profile admission, evaluator identity, refusal preservation, atomic
publication, store ownership, explicit upgrade, packaging, and hostile
lifecycle qualification.

It is not functionally equivalent to the deployed Classic system. NQ-NG
currently has one operational first-party helper, one operational profile, and
one operational detector family. It has no storage profile, Labelwatch,
Driftwatch, external-provider intake, notification delivery worker, general
consumer-reliance layer, or replacement dashboard.

Classic's twenty-commit rewrite is a donor and evidence corpus, not a second
completed successor architecture. Its most useful contributions are:

- bounded acquisition algorithms that may later be adapted manually;
- immutable hostile and correspondence specimens;
- consumer-purpose reliance as a real semantic requirement if a deployed
  consumer needs it;
- installation-research methodology and adverse clean-room evidence; and
- evidence of architectures and UX that must not be reproduced.

No implementation slice was selected. The deployed capability set,
notification and reliance obligations, historical-retention duties, and
definition of functional equivalence are not yet declared. Choosing a
collector or import seam without those facts would optimize NQ-NG against an
assumed deployment. The authorized result is therefore the completed,
committed survey and cutover gates.

## 2. Exact repository identities

### NQ-NG

| Property | Identity |
|---|---|
| Root | `/home/jbeck/git/skunkworks/nq-ng` |
| Branch | `campaign/provider-intake-foundation` |
| Starting HEAD | `f1e37563de0b59b0abb38f04ace0c3170a954c51` |
| Starting tree | `0c515678258e5902d469b8aa4df77af3dbbd830b` |
| Survey-map commit | `0f934d4` |
| Rollback/upgrade-evidence commit | `05d6b54d40d2e6d91922a6e8878fd6a0bd754e02` |
| Exact ending survey-content HEAD before this closing report | `05d6b54d40d2e6d91922a6e8878fd6a0bd754e02` |
| Exact ending survey-content tree before this closing report | `e17276963f50e46b313ac5cc5ecaa62f9006d101` |
| Remotes/upstream | none |
| Starting status | clean, no untracked files |

The final report commit cannot contain its own Git identity without a
self-reference. The exact post-commit HEAD and tree are recorded in the
campaign handoff together with the final clean-status check. There are no
source changes after `44e5567`; the two survey commits above contain
documentation only.

### NQ Classic

| Property | Starting and ending identity |
|---|---|
| Root | `/home/jbeck/git/nq-root/nq` |
| Branch | `main` |
| HEAD | `2e956d27616bcb7e49016b4d7867c9455c4129a7` |
| Tree | `428be9d34a5cf36d4c97532578d4bb4a99d22e80` |
| Upstream | `origin/main` |
| Upstream identity | `55e35ac886130a92ec656433a44a4c2b3bc13342` |
| Ahead/behind | 20 ahead, 0 behind |
| Status | clean, no untracked files |

Classic remained strictly read-only.

## 3. Authoritative NQ-NG working line

The selected line is `campaign/provider-intake-foundation`, not `main` or the
`v0.1.0` tag:

```text
2c41b0a  v0.1.0
    |
e3c451f  main
    |
44e5567  provider-intake implementation
    |
ef7e1b8  provider-intake qualification
    |
2d10443  operator ratification record
    |
f1e3756  experimental-mechanism/cutover status
    |
0f934d4  reconciliation survey
    |
05d6b54  rollback and upgrade evidence
```

`44e556709e629eb3c83d1d74bfbcf12cb4c9a549` is the latest implementation
commit. Its descendants preserve qualification, adverse evidence, operator
status, and this survey. The line is a strict descendant of both `v0.1.0` and
`main` and is the most advanced coherent local candidate.

This selection does not make NQ-NG released, deployed, canonical, or
production-authoritative.

## 4. Recovered NQ-NG implementation

The detailed inventory is
[`NQ_NG_IMPLEMENTATION_INVENTORY.md`](NQ_NG_IMPLEMENTATION_INVENTORY.md).
The implemented path is:

```text
strict configuration
    -> exact bounded helper execution
    -> NQ-derived provider attempt and identity
    -> raw native outcome and byte custody
    -> strict protocol decoding
    -> compiled profile admission or typed refusal
    -> compiled detector evaluation or typed refusal
    -> atomic append-only publication and acknowledgment
    -> versioned store, CLI, and API projections
```

`nq-system-contract` is a separate authority-free artifact path. It compiles
strict system-scope and cut artifacts but is intentionally isolated from the
daemon, live publication path, and store.

Authoritative owners are:

| Concern | NQ-NG owner |
|---|---|
| Helper wire protocol and canonical identity | `nq-protocol` |
| Profile vocabulary, binding, coverage, freshness and detectors | `nq-profiles` |
| Bounded host acquisition | `nq-host-helper` |
| Privilege/resource boundary | `nq-helper-sandbox` |
| Admission, provider intake and evaluation orchestration | `nq-core` |
| Append-only schema v4, histories, watermarks and upgrade | `nq-store` |
| CLI and daemon lifecycle | `nq-app` |
| Authority-free system scope and cut artifacts | `nq-system-contract` |
| Release-cohort identity | `nq-build-info` |

The internal dependency graph is acyclic:

```text
nq-build-info       -> []
nq-helper-sandbox   -> []
nq-protocol         -> []
nq-profiles         -> nq-protocol
nq-store            -> nq-protocol
nq-system-contract  -> nq-profiles, nq-protocol
nq-core             -> nq-helper-sandbox, nq-profiles, nq-protocol, nq-store
nq-app              -> nq-build-info, nq-core, nq-helper-sandbox,
                       nq-profiles, nq-protocol, nq-store
nq-host-helper       -> nq-build-info, nq-profiles, nq-protocol
```

`cargo metadata --no-deps --offline` found no cycle and no path dependency
outside this workspace. Executable source contains no dependency or reference
to the Classic repository, Classic crates, `nq-suite`, or
`nq-monitor-check`. The Classic schema-64 table set and migration chain are
absent. NQ-NG has its own independently developed schema v4; shared generic
words such as `finding_evidence` do not imply schema correspondence.

## 5. Classic donor commit ledger

The exact range is:

```text
55e35ac886130a92ec656433a44a4c2b3bc13342
    ..
2e956d27616bcb7e49016b4d7867c9455c4129a7
```

The canonical per-capability A-G ledger, including split classifications
within commits, is
[`CLASSIC_DONOR_LEDGER.md`](CLASSIC_DONOR_LEDGER.md). The twenty commits are:

| # | Commit | Principal result |
|---:|---|---|
| 1 | `2efa22d` | archaeology and proposed architecture |
| 2 | `1d32be3` | bounded Classic protocol leaf |
| 3 | `6e05456` | newer-schema refusal plus retained Classic migration lineage |
| 4 | `ff610bb` | isolated witness kernel, projection receipts and compatibility facades |
| 5 | `8f25635` | Classic dependency-boundary checker and negative fixtures |
| 6 | `08e2449` | strict startup/config refusal within mixed Classic lifecycle |
| 7 | `c09f748` | disposition/refusal isolation and consumer-purpose reliance |
| 8 | `dacfc1a` | clean-room baseline evidence |
| 9 | `aca9dcd` | database compatibility preflight over Classic schema lineage |
| 10 | `2195015` | dashboard semantic work and the rejected UX redesign |
| 11 | `2e11224` | witness tool seam and `zab2nq` corpus validation |
| 12 | `7f9056e` | check registry, host/storage extraction and Labelwatch plan |
| 13 | `c5e3486` | planning-only suite composition |
| 14 | `17f998e` | honest ownership/dependency checkpoint |
| 15 | `f853180` | first-run method, persona/scenario corpus and Classic-specific harness |
| 16 | `ab249e6` | unavailable-versus-unknown distinction and wording evidence |
| 17 | `02081fa` | raw synthetic and clean-room records |
| 18 | `028f8e8` | evidence-schema correction |
| 19 | `e62fad2` | formatting-only check-pack delta |
| 20 | `2e956d2` | final constellation report and refused verdicts |

Important corrections:

- much of the witness, reliance, host, ZFS, SMART and GPU behavior predates
  the twenty commits; the stack isolates or adapts it rather than creating
  twenty commits of new parity;
- the Labelwatch package contains descriptors, configuration and a typed plan
  but no executable collector;
- every `nq-suite` plan says `launch.available=false`; and
- the stack retains raw SQLite crossings, an all-collectors runtime, mixed
  ownership and dashboard-specific coupling.

## 6. Semantic crosswalk

The full crosswalk is
[`SEMANTIC_CROSSWALK.md`](SEMANTIC_CROSSWALK.md).

### Acquisition and composition

Pack, helper, provider and profile are not synonyms:

- a Classic pack mixes check descriptors, acquisition, configuration and
  registry metadata;
- an NQ-NG helper only performs bounded acquisition;
- an NQ-NG provider is an NQ-derived acquisition-source identity and custody
  boundary;
- an NQ-NG profile owns semantic vocabulary, bindings, coverage, freshness,
  normalization and detectors; and
- explicit watcher configuration selects an admitted helper/profile instance.

One Classic pack may therefore become zero or more profile versions, one or
more helpers, and explicit watcher instances. It must not become a second
registry or composition framework.

### Witness and admission

Classic `nq.witness.v1` acceptance establishes structural validity of a
declared artifact. NQ-NG separately preserves:

```text
provider attempt
    -> native outcome and raw bytes
    -> protocol-valid candidate
    -> profile admission or refusal
    -> detector evaluation or refusal
    -> finding projection
```

Those stages carry different authority. Calling an NQ-NG artifact
`nq.witness.v1` would create a dangerous version-name collision. A Classic
witness cannot reconstruct the original NQ-NG provider request, execution
identity, capability grant, profile admission, or evaluator source closure.
Static witness material may be archived or later imported through a new,
explicitly lossy historical contract. It cannot become current native
observation.

### Decision and reliance

NQ-NG is stronger for operational admission, evaluation, typed refusals,
evidence identity, watermarks, and refusal-safe finding resolution. It has no
general consumer-purpose reliance or standing layer. That is a genuine gap if
a named deployed consumer depends on it, not permission to map “admitted,”
“healthy,” or “acknowledged” to authorized reliance.

### Runtime, store and packaging

NQ-NG's exact watcher path, provider custody, Store API, schema v4, atomic
publication, explicit backup-first upgrade and reproducible packages are the
target. Classic's private tables, 64 migrations, raw connections, binary
compatibility shims and all-collectors runtime are excluded.

NQ-NG packaging is materially stronger, but the current provider-intake line
is untagged and unpublished. Both the ratified foundation and post-provider
candidate still identify themselves as `0.1.0` despite different bytes and
schemas. A distinct candidate version and true two-version qualification are
required.

## 7. Classic capability classification

Every material donor capability has exactly one classification in the donor
ledger and transfer manifest. The aggregate result is:

| Class | Result |
|---|---|
| A — already implemented | No transfer required; correspondence only |
| B — NQ-NG stronger/cleaner | Protocol, admission/refusal, custody, store, migration safety, packaging and lifecycle stay NQ-NG-native |
| C — missing semantic requirement | Named consumer reliance where required; generic evidence/freshness/unknown/conflict presentation; symmetric anti-overclaim and anti-underclaim invariants |
| D — portable candidate | Bounded host/storage acquisition algorithms and clean-room methodology only, after dependency and unsafe-code review |
| E — fixture/evidence only | Witness/reliance/install specimens, hostile vectors, raw transcripts, dashboard failure evidence |
| F — compatibility debt | Classic DB/runtime, pack registry, suite planner, all-collectors dispatch, facades, dashboard HTML/SQL and private deployment residue |
| G — deferred capability | Labelwatch executable implementation, broader dashboard, notifications and other unproven product breadth |

No Classic crate, directory, migration, commit or runtime is approved for
wholesale transfer.

## 8. Exact cutover gap

The capability-level matrix is
[`CUTOVER_GAP_MATRIX.md`](CUTOVER_GAP_MATRIX.md). Locally provable counts are:

- NQ-NG: 1 operational helper, 1 operational profile, 1 operational detector
  family;
- NQ-NG: 0 storage profiles;
- NQ-NG: 0 Labelwatch or Driftwatch implementations;
- NQ-NG: 0 provider-neutral external intake paths;
- NQ-NG: 0 notification delivery workers;
- NQ-NG: 0 general consumer reliance/standing contracts;
- NQ-NG: 0 replacement dashboards; and
- NQ-NG: 0 Classic database import paths, deliberately.

The local-only survey cannot establish:

- exact enabled checks and thresholds on each deployed host;
- notification transports and recipients;
- operational dependence on Labelwatch, Driftwatch, storage, Docket,
  Continuity, Nightshift, or reliance receipts;
- historical evidence retention and access duties;
- an acceptable parallel qualification and rollback window; or
- whether a CLI-only first cut is operationally acceptable.

These are the G0 deployed-capability inputs. They must be recovered directly
and deliberately before implementing parity slices.

## 9. Deployed, rolled-back and candidate states

These three states are distinct:

1. The operator reports the current four-host fleet at Classic
   `361c5cdfa49163c96b550e8a0f38165b49305994`, tree
   `793f240abdd39db7fa65fdefc7601ac15667e25f`, schema 64.
2. Classic `2e956d2` was deployed for about fifteen minutes and rolled back.
   It is not current, but it is also not “never deployed.”
3. NQ-NG on `campaign/provider-intake-foundation` is undeployed,
   unpublished, and post-`v0.1.0`.

The fleet facts were supplied by the operator. This campaign did not contact
production. Reported active services, HTTP 200 responses, boundary checks and
zero leak checks prove bounded availability after rollback; they do not prove
dashboard correctness or functional parity. The corrected VM
`publisher.json` remained valid for both Classic binaries and the operator
reported that its WAL probe continued observing after rollback. Candidate
`2e956d2` binaries were retained at the operator-recorded NAS/crow, VM and
local paths. These are rollback records, not locally reverified deployment
state; exact paths and details remain in
[`REPOSITORY_STATE.md`](REPOSITORY_STATE.md).

No Classic migration ran during the trial. Both binaries used schema 64, and
the trial writes remained readable after rollback. This is useful
Classic-to-Classic compatibility evidence for that exact interval. It says
nothing about Classic-to-NQ-NG schema correspondence.

## 10. Dashboard conclusion

The `2e956d2` dashboard redesign was a UX failure and is rejected as a donor.
During its production trial, a critical observed finding could coexist with a
no-action headline. The restored old dashboard again made
`Service 'driftwatch' is down.` direct and restored maintenance-coverage
visibility.

The redesign's useful residue is requirements and failure evidence:

- current, stale, missing and conflicting evidence must remain distinct;
- NQ component health and monitored-system state must remain distinct;
- evidence basis, coverage, unknowns and safe next inspection must remain
  visible;
- generic presentation must not branch on check IDs; and
- material under-claim must be tested as rigorously as overclaim.

A mandatory future invariant is:

```text
a critical + observed finding must never coexist with a no-action headline
```

Classic HTML, SQL loaders, detector-specific presentation, information
architecture and interaction model are class F. NQ-NG's current escaped-JSON
console is not a replacement dashboard either. A successor surface must be
designed and qualified from operator tasks against NQ-NG's generic read DTOs.

`DEPLOY_CONTRACT.md` contains verify strings for the restored old surface. They
must change only when a future replacement surface is accepted; this campaign
did not edit Classic.

## 11. Upgrade lifecycle conclusion

Upgrade lifecycle belongs to NQ-NG.

Direct `cp` over a running Classic binary has produced `ETXTBSY` on three
reported occasions. The failures left the running service intact; staging a
sibling file and using rename worked. That is operational evidence against
in-place executable overwrites.

NQ-NG's Debian path already provides the safer boundary:

- `prerm upgrade` stops `nqd.service`;
- package replacement is refused unless the service is inactive;
- `dpkg` replaces packaged files;
- `postinst` does not initialize, migrate, restart or enable;
- `nq admin upgrade` performs the explicit backup-first schema transition;
  and
- restart remains an explicit operator action.

The remaining gap is a real different-version package upgrade and rollback,
including backup, schema behavior, admission drift/rotation, manifest
validation, explicit restart and rollback. Two different artifacts both
labeled `0.1.0` cannot honestly satisfy that test.

The Classic `nq-monitor-check` `RUNS`/`SUBSTITUTION_RUNS` race is separate:
parallel tests reset shared counters and can interfere under load. It remains
unowned Classic CI debt until those tests receive per-test counters or
serialization. It is not detector behavior, a parity requirement, or an
NQ-NG donor.

## 12. Selected cutover model

Use isolated parallel observation for qualification, ending in a clean
replacement.

The full gate sequence is in
[`CUTOVER_PLAN.md`](CUTOVER_PLAN.md):

1. G0: declare actual deployed capabilities, consumers and retention duties.
2. G1: assign an unambiguous NQ-NG candidate version and requalify it.
3. G2: create an isolated qualification environment with distinct config,
   state, socket, service, helper-runtime and console identities.
4. G3: implement required NQ-NG-native profiles/helpers/detectors one vertical
   at a time.
5. G4: compare independent observations and supported conclusions while
   Classic remains authoritative.
6. G5: freeze Classic with exact binary/config/unit identity and a
   WAL-consistent, content-manifested archive.
7. G6: initialize a fresh NQ-NG store, admit qualified components, verify
   collection and alert coverage, then switch authority explicitly.
8. G7: retain a bounded Classic rollback path and retire it only after the
   qualification and rollback windows pass.

Classic findings, generations, current pointers, notification state and
inferred provider/profile/evaluator identities must not be migrated as current
NQ-NG state. Immutable historical artifacts may later cross only through a
new versioned import contract with original bytes, provenance, transformation
identity, semantic-loss fields and non-current classification.

The later move into the public NQ repository is a separate history,
packaging, and promotion operation after functional equivalence. It was not
performed here.

## 13. Transfer proposal and actual transfer

[`TRANSFER_MANIFEST.json`](TRANSFER_MANIFEST.json) records every proposed
donor file or fixture, source commit/path, SHA-256, license, classification,
semantic purpose, required adaptation, transfer status, proposed destination
when one exists, and byte-preservation policy. Because no transfer was
selected, destination owner, imported dependency set, and architectural
correspondence test remain intentionally unset; they become mandatory before
any later D or E item changes from deferred/reference-only to transferred.

Proposed D candidates are limited to:

- bounded `/proc/meminfo` and filesystem acquisition behavior;
- field-level unavailable/incapacity principles;
- bounded ZFS, SMART and GPU acquisition algorithms after profile and runtime
  review; and
- clean-room campaign methodology adapted to NQ-NG packages.

Proposed E specimens are immutable witness, reliance, installation and
operator-evidence vectors.

Actual transfers:

```json
[]
```

No Classic code, fixture, schema, migration, dependency, private deployment
value, or database state entered NQ-NG.

## 14. Rejected Classic architecture

The following is deliberately excluded:

- mixed `nq-core` and `nq-db` ownership;
- Classic's 64 migrations and raw/private SQLite crossings;
- `nq-witness-api`, binary rename and compatibility re-exports;
- `nq-monitor-check` as an NQ-NG registry;
- the closed collectors envelope and all-collectors dispatch;
- planning-only `nq-suite`;
- check-ID-aware dashboard and notification behavior;
- source-workspace/sibling-path composition;
- private paths, thresholds, hostnames and custom service defaults; and
- the rejected dashboard presentation and interaction model.

This prevents the cutover work from recreating a distributed monolith inside
the greenfield repository.

## 15. Implementation gate

No bounded implementation slice was selected or implemented.

Plausible work exists, especially a new `nq.filesystem/v1` vertical or a
Classic freeze-manifest verifier. Neither is uniquely justified yet:

- the deployed minimum is undeclared;
- changing `nq.host/v1` would violate versioned-profile discipline;
- Classic host code depends on Classic DTOs and unsafe libc while NQ-NG
  confines unsafe code to the sandbox boundary;
- the archive asset/authority contract is not ratified; and
- the current post-provider package identity is ambiguous.

After G0, choose exactly one required vertical. If root filesystem capacity is
part of the minimum deployment, prefer a new versioned
`nq.filesystem/v1` profile/helper/detector rather than mutating
`nq.host/v1`.

This refusal materially preserves NQ-NG's architecture. It is not a claim that
the successor is complete.

## 16. Verification results

Verification was run against the survey line after the seven gate artifacts
existed. Documentation commits do not alter executable code.

### Passed

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- release build
- `nq protocol check`: 12 fixtures; 5 valid accepted, 7 invalid refused;
  corpus digest
  `sha256:d6dfabe73e8cf2374670103ce2886ee6eb16e8f0b7932c87dd2c52328b0271b6`
- Python helper conformance: 3 tests, 1 conditional skip
- profile catalog: 2 compiled descriptors
- protocol assets: 3 schemas and 12 fixtures
- system-contract assets: 5 strict schemas/fixtures
- release-verifier suite: 13 tests
- release reproducibility under path, insertion-order, umask, locale,
  timezone and `TMPDIR` perturbations
- release failure atomicity: lock exit 1, injected failure exit 97, killed
  publication exit 137
- hardening static and negative harness
- clean source-archive
  `cargo build --workspace --locked --offline` in 31.81 seconds, without a
  sibling checkout or network
- focused provider-intake suite: 6 tests
- sealing compile-fail suite: 1 harness with 3 hostile construction fixtures
- `nq-host-helper`: 8 tests
- `nq-profiles`: 17 tests
- `nq-protocol`: 23 tests
- `nq-store`: 52 tests
- `nq-system-contract`: 24 tests
- `nq-build-info`: 1 test
- all `nq-app` library and integration suites that ran before the workspace
  failure passed
- internal dependency cycle and external path-dependency check
- Classic runtime/crate/path and private-check leakage searches

Current reproducibility outputs were:

| Artifact | SHA-256 |
|---|---|
| tar | `efb866a5a0f47759040941f70b62023afa87e620fc5bae7abe94b17530054dd8` |
| Debian package | `4f92b126cbb2498e1b8c43b1b256bc32edfdb10c49a2ee5c9aab72034b915ec5` |
| embedded 49-file manifest | `ca872fe517852d199557c5a7ec89d489fe3f2cc4bb5638cd9de62de2580e8c3d` |

### Failed and preserved

`cargo test --workspace --all-targets` is not green.

- `nq-core --lib`: 112 passed, 11 failed. The failures comprise one stale cwd
  expectation, one distinct-UID fixture using production-invalid `/tmp`, two
  pipe/output fixtures whose Python helper exits nonzero, and seven
  `unix_runner` cases whose inline `python3 -c` source is treated as a
  path-like fixed argument and rejected with `ENAMETOOLONG`.
- `nq-helper-sandbox`: 10 passed, 1 failed. The descendant probe encountered
  host-wide `RLIMIT_NPROC` pressure and `/bin/sh: Cannot fork`.
- focused `checkpoint_commit`: 0 passed, 1 failed. Dry collection/admission
  returned `Io(NotFound)`.

The first two categories match adverse runner/host evidence already recorded
at the provider-intake qualification pin; they were not waived. The focused
checkpoint failure is separately recorded as a current local failure.

A fresh Noble QEMU lifecycle run was not performed. Existing clean-pinned VM
receipts remain historical evidence, not a fresh campaign result. Likewise,
the clean archive build proves source self-containment, not public artifact
availability, literal-docs usability, or a non-author first successful
operation.

No true two-version package upgrade/rollback, non-author clean-room first run,
or time-to-first-meaningful-operational-result test was earned.

## 17. Unresolved blockers

1. Recover the G0 deployed-capability and consumer matrix.
2. Give the post-provider NQ-NG line an unambiguous candidate version.
3. Repair or deliberately re-specify the 11 core runner fixtures, the
   host-dependent sandbox test, and the failing checkpoint integration test.
4. Implement only the required replacement verticals.
5. Provide alert delivery or an explicit temporary manual alert contract.
6. Design an NQ-NG-native operator surface; neither Classic redesign nor the
   current NQ-NG console is acceptable as the successor dashboard.
7. Qualify a real two-version package upgrade and rollback.
8. Run literal documented installation and first useful operation in a fresh
   non-author environment.
9. Define the Classic freeze/archive manifest and retention contract.
10. Perform isolated semantic parallel observation before authority changes.

The Classic `RUNS` test race is a separate Classic maintenance item and does
not block NQ-NG architecture work, though it will continue to cause Classic CI
noise until fixed.

## 18. Authority effect and work-hours boundary

This campaign establishes:

- which NQ-NG line contains the accumulated greenfield implementation;
- what the Classic twenty-commit stack actually contributes;
- which Classic architecture must be excluded;
- the exact locally visible cutover gap; and
- a gated successor strategy.

It does not establish functional equivalence, release readiness, deployment
readiness, dashboard usability, historical-state compatibility, or production
authority.

No code or fixture transfer, production contact, deployment, push, tag,
release, remote configuration, history rewrite, sibling-repository change, or
Classic mutation occurred.

## 19. Verdicts

Earned:

- `NQ-CLASSIC-DONOR-STATE-AUDITED`
- `NQ-NG-CURRENT-STATE-AUDITED`
- `CLASSIC-TWENTY-COMMIT-DELTA-INVENTORIED`
- `CLASSIC-TO-NQ-NG-SEMANTIC-CROSSWALK-COMPLETE`
- `PACK-PROVIDER-PROFILE-RELATIONSHIP-RESOLVED`
- `WITNESS-AND-ADMISSION-RELATIONSHIP-RESOLVED`
- `DECISION-SEMANTIC-GAP-IDENTIFIED`
- `RUNTIME-AND-STORE-GAP-IDENTIFIED`
- `INSTALLATION-AND-OPERATOR-GAP-IDENTIFIED`
- `CLASSIC-CAPABILITIES-CLASSIFIED`
- `CUTOVER-GAP-QUANTIFIED`
- `CUTOVER-STRATEGY-SELECTED`
- `CLASSIC-DATABASE-MIGRATION-NOT-ASSUMED`
- `CLASSIC-COMPATIBILITY-DEBT-EXCLUDED`
- `NQ-NG-ARCHITECTURE-PRESERVED`
- `NQ-CLASSIC-UNCHANGED`
- `NO-PUSH-NO-DEPLOY-WORK-HOURS-BOUNDARY-PRESERVED`
- `FULL-CUTOVER-NOT-YET-CLAIMED`

Refused:

- `ONE-BOUNDED-CUTOVER-SLICE-IMPLEMENTED`
- `ONE-BOUNDED-CUTOVER-SLICE-VERIFIED`
