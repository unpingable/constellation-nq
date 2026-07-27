# NQ-NG implementation inventory

Basis: NQ-NG commit
`f1e37563de0b59b0abb38f04ace0c3170a954c51`. This inventory distinguishes
executable implementation from plans and receipts.

## Architectural summary

NQ-NG is a working but narrow operational-evidence vertical. Its strongest
implemented boundaries are:

```text
strict configuration
    -> admitted local helper and exact execution identity
    -> typed, bounded helper exchange
    -> NQ-owned provider intake and raw custody
    -> compiled profile admission/refusal
    -> compiled detector evaluation/refusal
    -> one atomic append-only publication
    -> versioned CLI/API/store projections
```

It is not a broad Classic replacement today. Its only operational provider is
the NQ-controlled local helper, its only operational profile is
`nq.host/v1`, and its only operational detector is host load pressure.

## Concept inventory

| Concept | Authoritative owner | Public contract | Persistence contract and executable path | Executable evidence | Known limitation |
|---|---|---|---|---|---|
| Helper wire protocol | `crates/nq-protocol` | Strict one-frame NDJSON `nq.helper.v1`; request, response, evidence report, observations, coverage, errors, refusal, exact profile/subject/scope/vantage/capability/checkpoint/deadline bindings; RFC 8785/JCS and SHA-256 identity | Owns no database. Stdio or authenticated persistent-Unix bytes are decoded before profile semantics | JSON Schemas and hostile/valid corpus in `protocol/`; Rust conformance suite; independent Python specimen; asset verifier | V1 only; local stdio/Unix carriers; no remote or provider-neutral transport |
| Profile compilation | `crates/nq-profiles` | `ProfileModule`: descriptor, binding validation, report validation, typed projection, detector registry; compile-time exact registry | Descriptor/profile semantic identities accompany admitted reports and evaluations | `profile_validation` covers registry, profile drift, vocabulary, coverage, scope, capability, forbidden helper authority, freshness, detector behavior | Static code/release registration; only conformance and host profiles |
| Normalization | `crates/nq-profiles::validation` plus each profile module | `ReportInput::from_protocol`, `ValidationContext`, `ValidatedReport`, typed `ProfileRefusal` | Protocol-valid candidate is normalized, then either admitted with exact semantic identity or retained with refusal | Hostile profile tests and semantic-surface tests | No universal record and no provider-neutral normalizer registry, intentionally |
| Host acquisition | `crates/nq-host-helper` | One bounded `nq.host/v1` request/response; local hostname, uptime, CPU count, and one-minute load; explicit coverage and basis | Helper emits candidate bytes only. Core owns launch, intake, admission, evaluation, and publication | Helper stdio/build-info tests and live helper path in CLI/daemon tests | Linux/glibc operational path; no memory, swap, filesystem, inode, storage, service, log, or network observation |
| Helper sandbox and launch identity | `crates/nq-helper-sandbox`, `nq-core::{runner,unix_runner,identity,runtime}` | Fixed argv, no shell; exact executable/interpreter/fixed-file/cwd/startup-runtime identity; bounded stdout/stderr/time/resources; separate UID and authenticated Unix peer | Admission binds the identity. Later launches use retained, revalidated artifacts; run resource outcomes are stored | Sandbox, runner, admission, sealing/trybuild, race/substitution tests and Noble VM receipts | Bounded Linux glibc ELF64 AMD64/ARM64 startup closure only; later dynamic loading outside the claim; shared helper UID remains a sibling trust/DoS domain |
| Configuration | `crates/nq-core::config` | Deny-unknown `nq.config.v1` TOML; absolute paths; bounded watcher count; exact command/account/profile/binding/capabilities/schedule/resources | Loaded configuration pins file identity and canonical intent; apply is explicit and atomic | Config unit tests and CLI/lifecycle tests | Local process configuration only; no estate/fleet composition model |
| Helper admission | `crates/nq-core::admission` | `AdmissionLockV1` binds config, execution, profile/digest, protocol, capability grant, conformance, evaluator context; explicit test/admit/rotate/rollback/revoke | Immutable admission/binding history is authoritative; active JSON is a crash-recoverable materialization | Admission, mutation-serialization, drift, rollback, recovery tests | Admission is local-helper-specific and is not truth, report admission, standing, or action authority |
| Provider intake | `crates/nq-core::provider_intake`; schema-v4 support in `nq-store` | NQ-derived `ProviderIdentityV1`; sealed non-deserializable `VerifiedProvider`; pre-bound `ProviderAttempt`; exact `ProviderIntakeRecordV1`; durable acknowledgment | Provider attempt, local watcher subtype, exact native outcome/raw bytes, interpretation, admission/refusal, evaluation/finding/status, watermarks and acknowledgment publish atomically | Provider identity, native-outcome, replay, revocation, migration, archive, and transaction rollback tests; separate qualification receipt | Only `ProviderKind::LocalHelper`; still one process boundary; no independent/remote provider, provider-owned sequence, queue, submission service, or plugin host |
| Raw custody and provenance | `nq-core::provider_intake`, `nq-store` | Exact raw bytes, length and digest; declared backend identity remains untrusted candidate provenance; typed native acquisition outcome stays distinct from parsed response | Append-only provider/raw/submission rows and linked refusal/report rows; archive reopens and rechecks canonical documents | Byte substitution, partial timeout, protocol reinterpretation, replay, archive mutation tests | No external custody service or signature infrastructure |
| Evaluator identity and source closure | `crates/nq-core::evaluator_identity`, `nq-profiles` build/source identity | Sealed evaluator identity and admission context bind profile semantics, detector suite/source closure, evaluator artifact, helper artifact, config, and protocol | Historical records verify against their admitted identities and do not silently reevaluate | Compile-fail construction/injection tests and archive/identity substitution tests | Historical semantic reopening requires compatible evaluator bytes; source closure is deliberately conservative, not a proof system |
| Observation time and freshness | Protocol leaves plus profile policy | `observed_at` is distinct from received/evaluated time; profile owns reliance/alignment windows | Immutable leaves retain times. Freshness sweep evaluates without recollection; staleness yields `CannotEvaluate` and does not resolve an existing finding | Freshness, future/stale, and finding-preservation tests | Coarse descriptor seconds; no general acquisition intervals, epochs, or recursive temporal logic |
| Sequence and watermarks | `nq-store`, consumed by `nq-core` | Database-assigned report/evaluation/finding order; exact evidence refs; checkpoint contract over admission/binding/profile/subject/scope/vantage/capabilities | Sequence allocation and watermark movement occur in the publication transaction; only admitted and acknowledged evidence advances checkpoint | Checkpoint, replay, sequence-order, identical-semantic-report and transaction rollback tests | Current local provider has no provider-owned sequence protocol |
| Durable store | `crates/nq-store` | Profile-neutral Store API, typed finding/status/evaluation/refusal DTOs, bounded public views and queries | Exact schema v4; append-only histories, immutable raw evidence, rebuildable current pointers; one atomic collection completion boundary | Large store contract/unit corpus plus core/app end-to-end tests | SQLite only; `nq-core` directly links store; notification storage exists without delivery worker |
| Schema upgrade | `nq-store` and `nq-app admin` | Runtime open never migrates; explicit `admin upgrade`; exact compatibility refusal | Exact frozen v3 -> v4 migration only, verified backup first, explicit gaps for unavailable historical intake; newer or altered schemas remain untouched | `admin_lifecycle`, store migration, backup/restore, archive tests | No Classic 64-migration chain, v1/v2 upgrade, or generic migration framework |
| Detector/evaluation semantics | Each compiled profile plus `nq-core::engine` | Direct typed `Present`, `ExplicitlyAbsent`, or `CannotEvaluate`; evidence IDs, limitations, watermarks and typed refusal | Immutable evaluations and finding events; insufficient/refused evaluation cannot resolve prior evidence | Host detector, engine, store and semantic-transport tests | Only host load-pressure detector; no positive multi-witness composition |
| Finding lifecycle | `nq-core::engine`, `nq-store` | Versioned finding snapshots with condition, visibility, operator-work, severity, freshness, basis, refusal, origin, evidence and times | Immutable events with current pointer; stale/refused states retain prior condition/evidence; explicit sufficient absence is required for resolution | Finding-lineage, stale-preservation, exact-evidence, API/CLI export tests | No Classic breadth of detector families and no action/coordination workflow |
| Decision, standing, and reliance | Not implemented as a product layer | Provider/report admission and detector evaluation are deliberately narrower and do not confer claim entitlement or action authority | No general disposition, consumer reliance receipt, standing, inquiry, or action authorization store | Negative authority tests prove providers cannot inject these fields | Material semantic/product gap; “stored decision” in replay documentation is not Classic-style decision law |
| System contract and scope cuts | `crates/nq-system-contract` | Strict `SystemSpecV1`, proposal, ratification-bound `ScopeCut`, NQ and future Porter projections; authority always `None`; bounded required-observation coherence witness | Language-neutral schemas, fixtures and manifests only | Unit, public-asset, hostile-mutation, coherence and Python asset-verifier tests | Isolated from daemon/store/runtime; no live NetBox/Porter/Governor specimen; no general epoch/concurrency/causality proof |
| Daemon lifecycle | `crates/nq-app::daemon` | `nqd`; strict startup checks; independent schedules with jitter/backoff; freshness sweeps; persistent helper quiescence on binding change | SQLite and admissions are checked before listeners/status; Unix read API always, loopback console only by explicit option | CLI/admin/mutation tests, hostile lifecycle and VM receipts | No reload/socket activation; manual stop/apply/start; no external scheduler/Nightshift integration |
| Operator CLI | `crates/nq-app::cli` | `init`, `config`, `profiles`, `protocol`, `watcher`, `collect`, `doctor`, `backup`, `restore`, `admin`, `findings`, `status`, `evaluations`, `refusals`, bounded `query` | Reads/writes only through NQ-owned config/store/admission paths | Black-box `e2e_cli`, semantic surfaces, custody pagination, refusal surfaces | Precise but expert-heavy; first operational setup requires explicit account/systemd workflow |
| HTTP/API and console | `crates/nq-app::api` | Versioned read-only local endpoints; compatibility routes fail explicitly when representation would lose semantics; loopback-only optional console | Uses Store public DTOs, not arbitrary write APIs | API compatibility, paging, escaping, socket and mutation tests | Console is escaped JSON in `<pre>`, not a decision dashboard; no HTTP mutation |
| Notification | `nq-store` outbox/attempt rows only | Immutable outbox/attempt storage and public status view | Store can retain notification state | Store validation tests | No delivery worker or transport; not functional parity |
| Backup, restore, archive | `nq-app::cli`, `nq-app::archive`, `nq-store` | Explicit verified backup/restore; sealed cold archive with its own verifier; no current authority from historical custody | SQLite online backup captures WAL state; restore requires absent destination; archive records when source cannot be semantically reopened | Admin lifecycle and hostile archive substitution tests | Reverse migration is restore of prior verified backup plus prior binary; no automatic rollback |
| Packaging | `scripts/`, `packaging/`, `hardening/` | Prebuilt no-Cargo/no-network tar and Debian artifacts containing `nq`, `nqd`, `nq-host-helper`; explicit manifest/modes/digests; upgrade hook stops and proves `nqd` inactive before package replacement | Package creates accounts/layout only; never initializes, migrates, starts, overwrites config, or purges durable state; post-upgrade verification/schema action/start remain explicit | Reproducibility/failure-atomicity scripts; maintainer-script active/stop-failure tests; AMD64 Noble QEMU install/reinstall lifecycle evidence | No configured remote or public artifact source; no true different-version VM upgrade/rollback; VM evidence is AMD64 Noble, not every supported script target |
| Installation/removal | `docs/OPERATIONS.md`, Debian maintainer scripts | Explicit init/config/admission/start workflow; `remove` stops/removes package; `purge` preserves config/state/evidence/accounts | Authoritative state locations documented; destructive erasure deliberately manual | Hostile install/reinstall/remove/purge/reinstall lifecycle receipt | Safe but not a short non-author first run; package-name conflict with Debian's unrelated `/usr/bin/nq`; no published artifact |

## Supported operational set

| Kind | Implemented |
|---|---|
| Compiled profiles | `nq.conformance/v1`, `nq.host/v1` |
| Live provider kinds | `local_helper` only |
| First-party operational helper | `nq-host-helper` |
| Host evidence | identity, uptime, CPU count, one-minute load |
| Operational detectors | `nq.host.load_pressure/v1` |
| Carriers | one-shot stdio; authenticated persistent Unix |
| Persistence | SQLite schema v4 |
| Operator presentation | JSON/JSONL CLI, local read API, escaped-JSON console |

The Python helper is a protocol conformance specimen, not a supported runtime
SDK/provider. The system-contract specimens are authority-free static
artifacts, not live observations.

## Explicitly unresolved

- memory, swap, filesystem capacity/inodes, ZFS, SMART, GPU, logs,
  Prometheus, Labelwatch, Driftwatch, Docket, Continuity, and Nightshift;
- external static-witness intake and provider-neutral/remote intake;
- notification delivery and retention automation;
- a decision/reliance/standing layer above detector evaluation;
- task-first operator presentation and action semantics;
- an operator-approved real Classic cut manifest;
- Classic historical-state transformation;
- positive multi-witness composition and general temporal/epoch semantics;
- daemon use of system cuts and any live constellation integration;
- a complete historical upgrade matrix; and
- a distinct-version package upgrade/rollback run proving that running
  executables are never overwritten in place; and
- production deployment, publication, remote configuration, and cutover.

These are not “planned implementation” and are not counted as current
capability.
