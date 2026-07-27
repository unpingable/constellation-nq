# NQ-NG successor cutover gap matrix

## Three states that must not be conflated

| State | Identity known locally | Deployment status |
|---|---|---|
| Currently deployed Classic system | Operator reports `361c5cdfa49163c96b550e8a0f38165b49305994`, schema 64, on four hosts; exact per-host configuration, enabled collectors, notification paths and durable-state obligations remain unresolved locally | Deployed after rollback; four services/dashboard endpoints reported active |
| Rolled-back Classic rewrite | `main` at `2e956d27616bcb7e49016b4d7867c9455c4129a7`, exactly 20 commits ahead of `origin/main` | Temporarily deployed for about fifteen minutes, then rolled back for dashboard UX regressions; candidate binaries retained |
| Undeployed NQ-NG candidate | `campaign/provider-intake-foundation` at `f1e37563de0b59b0abb38f04ace0c3170a954c51`; implementation pin `44e5567…` | Experimental, qualified/ratified locally, untagged after `v0.1.0`, unpublished and not deployed |

The twenty Classic commits are not current deployed state merely because they
are on local `main`. Their brief trial is preserved as deployment evidence and
must not be misreported as either “never deployed” or “still deployed.”

## Replacement matrix

“Blocker” means a blocker to a full successor cut, not to continued NQ-NG
development.

| Capability | Deployed owner/state known locally | Undeployed Classic implementation | NQ-NG implementation now | Required NQ-NG-native work | Historical import / clean restart | Authority or evidence risk | Verification required | Blocker |
|---|---|---|---|---|---|---|---|---|
| Minimal host monitoring | Classic family; exact enabled fields and thresholds unknown | Executable load, memory, root-filesystem, uptime, kernel and boot collection; extracted host pack | Real admitted helper/profile; hostname, uptime, CPU and one-minute load; load-pressure detector | First declare minimum. Add separately versioned profile/helper/detectors for required missing dimensions; do not mutate `nq.host/v1` | No import. Independent fresh observations are preferable | A copied aggregate or absent field could become false health; profile-version drift would relabel evidence | Live fixture and same-target parallel comparison; missing/partial/stale refusal; package/admission tests | Yes until minimum is declared and covered |
| Memory/swap | Unknown | Memory total/available/derived pressure; swap support elsewhere in Classic inventory | Absent | Bounded Linux profile fields and detector only if required; explicit units and coverage | Clean start | Derived pressure must not hide missing `MemAvailable`; sample does not prove workload impact | Parser fixtures, unavailable coverage, threshold identity, live bounded read | Conditional |
| Root filesystem capacity/inodes | Unknown | Root capacity bytes/percentage; no complete NQ-NG equivalent | Absent | Prefer narrow `nq.filesystem/v1` with exact mount/path, bytes and inodes, local vantage, explicit filesystem identity | Clean start | Mount replacement and stale path identity; percent-only loss; capacity is not application impact | Mount/path identity, bytes/inodes, partial coverage, stale and namespace tests | Conditional, likely for minimum host |
| Network interface state/errors | Unknown | Generic Classic collector inventory exists, exact deployed use unknown | Absent | New bounded profile/helper only after required interface semantics are declared | Clean start | Interface presence is not reachability or service health | Fixture plus real local observation; unknown interface/refusal | Conditional |
| ZFS | Unknown | Executable helper-based collector and typed pack | Absent | NQ-NG profile/helper/detectors; exact helper artifact, privilege, timeout and source closure | No import; retain old evidence archive | Existing `nq.witness.zfs.v0` cannot be admitted as an NQ-NG report; helper privilege risk | Real harmless pool/fixture; unavailable helper; privilege and timeout refusals | Conditional / likely if deployed |
| SMART | Unknown | Executable helper-based collector and typed pack | Absent | NQ-NG profile/helper/detectors with device identity and privilege contract | No import | Device identity and permission failures can be laundered into empty health | Real or virtual device fixture; permission/missing-tool/refusal tests | Conditional / likely if deployed |
| NVIDIA/GPU | Unknown | Executable `nvidia-smi` collector | Absent | NQ-NG profile/helper only after late driver/module loading is reconciled with current launch-identity limits | No import | Current NQ-NG runtime explicitly does not qualify later GPU-driver/plugin loading | Dedicated platform qualification and explicit limitation | Conditional; architectural gate |
| Logs and Prometheus | Unknown | Classic collectors/runtime | Absent | Separate profiles/helpers with exact source, window, cursor and coverage semantics | Clean start, optionally archive old reports | Cursor/window mismatch and source silence can create false absence | Restart/checkpoint, low-volume, malformed source and missing coverage tests | Conditional |
| Labelwatch | Unknown | Base Classic has detector/config/runtime behavior; twenty-commit “pack” is descriptors/config and a non-executable plan | Absent | Recover the actual acquisition/detector contract, then implement an application-specific profile/helper/detector; no check-ID UI branch | Clean start; historical baseline policy must be explicit | Porting only the plan would falsely claim parity; local thresholds/private paths must not enter product defaults | Deterministic error-rate fixtures, real bounded source, baseline/sample/freshness/unknown tests | Conditional, blocker if live |
| Driftwatch or other custom checks | Unknown | Scattered/private; not cleanly extracted by the twenty commits | Absent | Deployment inventory first, then one NQ-NG-native profile per actual semantic contract | Clean start unless a baseline is explicitly adopted with provenance | Private assumptions and hidden thresholds | Private overlay tests without product leakage | Unknown |
| External witness ingestion | Unknown | Structural `nq.witness.v1` validation/adoption; static `zab2nq` corpus accepted | No provider-neutral/external intake | Either archive-only treatment, or a future explicitly versioned external-provider/import boundary with semantic-loss receipt | Preserve immutable archive; do not make current observation | Structural witness validity lacks NQ-NG provider/request/profile/evaluator facts | Frozen vectors, provenance/substitution/unsupported-version tests, no-current-observation assertion | Conditional |
| `zab2nq` static corpus | Unknown runtime relevance | 6,874 static external projections validated as a packet set | Not consumed | Keep as external archive specimen unless a real query requires import | Archive only | Static projection could be mislabeled runtime evidence | Exact manifest/digest and explicit static classification | No for clean replacement |
| Docket/Continuity support | Unknown | Classic projection/reliance fixtures and broader existing integrations | No live integration or general reliance layer | Determine live consumer requirement; if necessary define an NQ-NG consumer-purpose contract over exact artifacts | Archive old receipts; no current-state import | Imported reliance could grant unsupported standing; source substitution | Consumer contract, purpose mismatch, stale/contradictory/unsupported refusal tests | Conditional |
| Nightshift | Unknown | Existing constellation relation; no new integration authorized | Explicitly absent | Separate future campaign; not a cutover shortcut | None | Missing check-in must not become subject failure | Shipped-binary and missing-coverage contract tests | Conditional |
| Operational evaluation/refusal | Unknown deployed revision | Findings/status/reasons and newly isolated disposition/refusal | Strong exact profile/detector/evaluator/evidence/watermark chain; typed `CannotEvaluate` | Correspondence tests, not a port | Clean start | Naming differences can mask authority differences | Golden semantic cases across present/absent/stale/refused | No for narrow monitoring |
| Consumer reliance/standing | Unknown deployed use | Purpose-bound reliance request/outcome/receipt; twenty-commit isolation is undeployed | Absent by explicit design | Implement only for a named real consumer and purpose; preserve no-action-authority | Archive old receipts; no automatic adoption | “Admitted,” “healthy,” or “acknowledged” must not become authorized reliance | Purpose/consumer/substitution/stale/contradiction/idempotence corpus | Yes if any live workflow depends on it |
| Persistence | Classic SQLite presumed; exact schema and WAL state unknown | Shared/private SQLite and 64 migrations | Exact append-only schema v4, atomic provider/evaluation publication, verified backup/archive | Fresh NQ-NG initialization; no Classic adapter | Archive Classic DB; clean NQ-NG store | Parsing/migrating Classic rows could invent provider/profile/evaluator context | Fresh init, schema fingerprint, archive/restore and no-Classic-table gate | No if clean replacement accepted |
| Historical durable state | Exact retention obligation unknown | Long Classic history | Optional legacy manifest digest only; no importer | Define retained archive manifest and operator access policy | Retain, do not import as current | Absence of imported finding does not establish health; archive digest is not semantic admission | Freeze/backup/WAL/archive manifest verification and explicit UI/docs distinction | Qualification gate |
| Dashboard/operator surface | Old Classic dashboard restored; operator reports direct down-service wording and maintenance badge | The `2e956d2` redesign is a rejected UX; its tests guard overclaim but missed a critical-observed/no-action under-claim | Versioned CLI/API DTOs and escaped-JSON read-only console, not a replacement dashboard | Design from operator tasks and NQ-NG read DTOs; add symmetric under-claim/overclaim invariants and clean-room qualification; do not port Classic UX | No import | A semantically cautious page can still hide urgent supported facts; coarse status or empty findings can become false reassurance | Critical observed finding cannot coexist with no-action headline; literal-docs operators identify issue/freshness/evidence/refusal without SQL | Yes if dashboard is required; CLI-only cut remains conditional |
| Notifications | Actual configured transport unknown | Delivery/runtime present in Classic | Outbox/attempt storage only; no worker | Replacement transport or an explicit temporary manual operating procedure | Do not import delivery state | Silent absence of alert delivery is a serious cutover hazard | End-to-end delivery/failure/retry/dedup test or signed manual coverage plan | Yes if alert delivery is required |
| Installation | Exact deployed install unknown | Static/source paths; local rewrite adds adverse clean-room harness | Strong reproducible tar/Deb packaging and hostile lifecycle evidence | Build and qualify a distinct post-provider candidate; publish only in later authorized campaign; add literal-docs first useful result | N/A | Current code is not in tagged `v0.1.0`; same `0.1.0` version has different bytes/schema in local evidence | Clean artifact install, exact version identity, no sibling path/network, useful host result | Yes |
| Upgrade | Direct `cp` over a running Classic binary has produced `ETXTBSY` on three occasions; staged sibling plus rename worked; exact fleet playbook still external | Current Classic trial/rollback stayed on schema 64; no migration ran; `DEPLOY_CONTRACT.md` verify strings are stale for the redesign | Debian `prerm` stops and proves `nqd` inactive before package replacement; package leaves it stopped; explicit `admin upgrade`; same-package reinstall tested | Make package lifecycle the supported path; forbid in-place copy; run a true different-version package upgrade/rollback matrix; update verification strings only for an accepted future surface | No Classic DB conversion | Partial binary swaps, running old inode vs new path, stale admission, and ambiguous restart can split evidence identity | Inject `ETXTBSY`/active-service conditions, prove stop/inactivity, atomic package replacement, manifest/config/schema/admission checks, explicit restart and rollback | Yes as release/operations gate |
| Recovery/rollback | Unknown | Classic database/service recovery patterns | Verified NQ-NG backup/restore/cold archive; no reverse migration | Preserve a complete Classic freeze artifact and rehearse rollback separately | Classic restored as Classic; NQ-NG data cannot be backported | Split observation interval and alert ownership | Offline rollback drill and disclosure of unmergeable interval | Gate |
| Deployment | Classic live family; exact identity intentionally not contacted | Local rewrite undeployed | NQ-NG undeployed | Isolated parallel qualification followed by explicit authority switch | Fresh store | Default path/service names collide; shared paths could corrupt or confuse evidence | Separate host/VM or all paths/unit identities isolated; hash checks | Yes |

## Local facts still required before a cut

The local-only campaign cannot independently verify or fully resolve:

- per-host running/on-disk binary digests behind the operator-reported
  `361c5cd`/schema-64 fleet identity;
- enabled collectors/checks and thresholds;
- notification transports and recipients;
- operational dependence on Labelwatch, Driftwatch, storage, Docket,
  Continuity, or reliance receipts;
- required historical retention/access period;
- acceptable qualification window and rollback window; and
- whether a clean restart is operationally acceptable.

These are deployment inventory inputs, not reasons to import Classic
architecture. They are the first gate for the next implementation sequence.

## Quantified local code gap

From repository code alone:

- NQ-NG has **1** operational first-party helper, **1** operational profile,
  and **1** operational detector family.
- Classic has executable generic host and storage acquisition, plus broader
  legacy collectors/detectors/notifications/dashboard behavior.
- The twenty-commit Labelwatch pack has **0** executable collectors.
- The twenty-commit `nq-suite` has **0** launchable plans.
- NQ-NG has **0** notification delivery workers.
- NQ-NG has **0** general consumer reliance/standing contracts.
- NQ-NG has **0** Classic database import paths, deliberately.

The gap is operational breadth and named consumer behavior, not absence of a
successor foundation.
