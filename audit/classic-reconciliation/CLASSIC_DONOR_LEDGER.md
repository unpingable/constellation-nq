# NQ Classic donor ledger

Donor range:

```text
55e35ac886130a92ec656433a44a4c2b3bc13342
    ..
2e956d27616bcb7e49016b4d7867c9455c4129a7
```

The range is exactly twenty local commits on Classic `main`; it is not
deployed according to the operator's starting state. Every row below assigns
one material capability to exactly one A-G class.

## Classification key

- **A** — already implemented in NQ-NG; no transfer.
- **B** — NQ-NG has a stronger or cleaner model; retain NQ-NG.
- **C** — semantic requirement missing from NQ-NG; implement NQ-NG-native.
- **D** — bounded implementation algorithm may be manually transplanted.
- **E** — fixture, scenario, test idea, or evidence corpus only.
- **F** — Classic compatibility debt; exclude.
- **G** — useful product capability deferred beyond this campaign.

## Commit ledger

| # | Commit | Work and material result | Key files/packages | Class |
|---:|---|---|---|:---:|
| 1 | `2efa22daf2f8de9f3df908057d2170cab979b155` | Repository archaeology and proposed constellation architecture | `CONSTELLATION_INVENTORY.md`, `CONSTELLATION_ARCHITECTURE.md`, clean-room baseline | E |
| 2a | `1d32be3bf1c7add5d8dfd0c0bd01af739936d6b3` | Bounded identifiers, digests, schema IDs, timestamps and refusal wire primitives | `crates/nq-protocol/**` | B |
| 3a | `6e054565d6e119db044813c5d029b603aa8dc1c1` | Refuse a newer schema without altering it | `nq-db/src/migrate.rs` behavior/tests | B |
| 3b | same | Classic migration implementation and schema lineage | same | F |
| 4a | `ff610bbb3d930100e5a42731521aec09dd8bbd77` | `nq.witness.v1` validation, canonical identity, projection receipt and packet-set adoption isolated under `nq-witness` | `crates/nq-witness/**` | B |
| 4b | same | Witness/projection hostile vectors | `crates/nq-witness/tests/**` | E |
| 4c | same | Binary rename, `nq-core` re-export facades, monitor/API compatibility route | `nq-monitor-agent`, `nq-core`, `nq-witness-api`, `nq-monitor` | F |
| 5a | `8f2563539ba2863534754163f0a448e01575a91c` | Classic-specific dependency/boundary checker | `scripts/check-constellation-boundaries.*` | B |
| 5b | same | Positive/negative dependency-violation specimens | embedded checker fixtures | E |
| 6a | `08e2449e83510bfaec99a015be11cb513526184d` | Strict startup/configuration refusal and port preflight behavior | `nq-core::config`, monitor/agent CLI/tests | B |
| 6b | same | Failure cases and operator wording | config/startup tests and docs | E |
| 6c | same | Mixed-core configuration and binary-private lifecycle | `nq-core`, `nq-monitor`, `nq-monitor-agent` | F |
| 7a | `c09f748935a4a04f5cbff399b566908b744d3f26` | Disposition/refusal behavior already covered more precisely by NQ-NG admission/evaluation/refusal boundaries | `crates/nq/src/{disposition,refusal}.rs` | B |
| 7b | same | Purpose-bound consumer reliance request/outcome/receipt semantics | `crates/nq/src/reliance.rs` | C |
| 7c | same | Reliance profile corpus | `crates/nq/tests/fixtures/reliance-profiles.json` | E |
| 7d | same | `nq-core` compatibility facades | `nq-core/src/{receipt,reliance,wire}.rs` | F |
| 8 | `dacfc1a3b0320538bf987ea5265c88773d593c45` | Clean-room baseline harness evidence and raw transcripts | install scripts and `docs/install/campaign/**` | E |
| 9a | `aca9dcdc25dccaeb2536e5a931892d897b04fdf9` | Explicit absent/uninitialized/current/upgrade/newer/malformed/unrecognized database preflight semantics | `nq-db::schema_compatibility`, CLI/tests | B |
| 9b | same | Preflight scenario corpus | `database_compatibility.rs` | E |
| 9c | same | Classic schema-64/raw SQLite implementation | `nq-db` | F |
| 10a | `21950152fd86758790dd7b85c753bc67e0b87cce` | Operator requirements for structured evidence, sample/baseline/time/source/conflict/missing coverage, without producer-ID rendering branches | dashboard DTO/renderer behavior | C |
| 10b | same | Fictional unrelated-producer generic-render tests | `dashboard_generic_rendering.rs` | E |
| 10c | same | Classic HTML, detector-specific SQL loaders, and database-coupled finding DTO | `nq-db::dashboard`, `operator_dashboard.rs` | F |
| 10d | same | Full task-first dashboard product | whole dashboard beyond a minimal replacement surface | G |
| 11a | `2e1122437c8d32614cdbe4754ddb5d3e3ec86b93` | Standalone structural validation/adoption seam, where NQ-NG's profile/admission/custody model is stronger | `nq-witness-tool` and library seam | B |
| 11b | same | `zab2nq` corpus validation result and immutable external-projection specimen | witness fixture and result | E |
| 12a | `7f9056e7e01aa3d3b7333637d0483839ed2c3378` | Classic pack/check registry abstraction | `nq-monitor-check` traits/registry | F |
| 12b | same | Conservative local host acquisition algorithms | `nq-check-pack-host/src/{host,host_bsd}.rs` | D |
| 12c | same | ZFS, SMART and GPU acquisition algorithms | `nq-check-pack-storage/src/{zfs,smart,gpu}.rs` | D |
| 12d | same | Labelwatch descriptors/configuration/typed plan, with no executable collector | `nq-check-pack-labelwatch` | G |
| 12e | same | Closed collector envelope, all-collectors dispatch and concrete-pack agent dependencies | `nq-monitor-check::wire`, `nq-monitor-agent` | F |
| 13a | `c5e348624fb0fc85fd7468c43c5f79b6210551b4` | Planning-only `nq-suite` composition vocabulary (`launch.available=false`) | `crates/nq-suite/**` | F |
| 13b | same | Fail-closed selection/topology scenarios | suite tests/examples | E |
| 14 | `17f998e8f389656cbb444663e5b979168eb2bdca` | Honest ownership/dependency checkpoint | `CONSTELLATION_INVENTORY.md` | E |
| 15a | `f853180cfa6b3368f1a0335d257ddf1be7b50be3` | First-run methodology: isolated environment, exact command/timing capture, failure matrix and first-meaningful-result distinction | install harness behavior | D |
| 15b | same | Persona/scenario corpus and result schema | `docs/install/campaign/**`, install schemas | E |
| 15c | same | Classic package/binary/source-workspace assumptions in the harness | `install-first-run-campaign.py` as written | F |
| 16a | `ab249e67acbb5e9eb18f5ef19990a7c06c98460f` | Distinguish unknown from known-but-unavailable component/configuration | suite/harness behavior | B |
| 16b | same | Failure wording cases | harness self-tests | E |
| 17 | `02081fa7e8d69f4fa6ed06d511547430f52539d0` | Unedited clean-room and synthetic operator transcripts/results | `docs/install/campaign/raw/**` and curated results | E |
| 18 | `028f8e8da37debf94ddda73b4735a6acf588ac84` | Evidence-schema correction and regression | install campaign schema/self-test | E |
| 19 | `e62fad21c10262e8a6bccccfbeb2dabdadb0b043` | Formatting-only delta | five check-pack files | F |
| 20 | `2e956d27616bcb7e49016b4d7867c9455c4129a7` | Final results and explicit unearned decomposition/install verdicts | `FINAL_CONSTELLATION_REPORT.md` | E |

## Critical historical corrections

Several apparent “new” Classic capabilities predate the twenty-commit stack:

- `nq.witness.v1` and `nq.projection_receipt.v1` already existed in
  `nq-core` at `origin/main`; commit 4 isolates and tightens them.
- `nq.reliance.request.v1`, `.receipt.v1`, and `.profiles.v1` already existed
  in `nq-core`; commit 7 isolates them and adds typed boundary tests.
- host, ZFS, SMART, and GPU collectors already existed under the old
  `nq-witness` collector server; commit 12 moves/adapts them.

The stack is therefore useful donor refactoring and evidence, not twenty
commits of newly created operational parity.

## Bounded D candidates

All donor files are Apache-2.0 at Classic HEAD. Classic `LICENSE` SHA-256:
`f8c96bf1a1e2b2e6f57d8ae035d6207de5fa64ba92428c1e822569e11a071405`.

| Donor path | SHA-256 | Permitted value | Dependencies/coupling to remove |
|---|---|---|---|
| `crates/nq-check-pack-host/src/lib.rs` | `636341675b6475592fa930c40705671ecf577dc4e1a3dc0aa66a387133b90c77` | Descriptor intent only | Entire Classic pack trait/registry |
| `crates/nq-check-pack-host/src/host.rs` | `38ba7b2ae1756b9defb1816134a7fa903729cc42b0ed662ed7750d183850986f` | Bounded `/proc/meminfo` and root `statvfs` acquisition behavior | `nq-monitor-check` DTOs/status; unsafe libc implementation |
| `crates/nq-check-pack-host/src/host_bsd.rs` | `6603a133adf1dca412f0c4f240f33242999561184e661aef6c073ec5b9df6bad` | Field-level incapacity principles | Classic DTOs and platform scope not qualified by NQ-NG |
| `crates/nq-check-pack-storage/src/lib.rs` | `0bf6970dc8f86f0ea0baf72ea5910a3bf747c7c164a4f6405e1786845fd5d33e` | Explicit-only configuration requirements | Pack registry and closed envelope |
| `crates/nq-check-pack-storage/src/zfs.rs` | `6eb3ad920b4c4cde766a7f499f2fb6e964cc482278c04ca1f7bedc6d2a28fdf9` | Later bounded acquisition behavior | Classic witness-v0/status/helper assumptions |
| `crates/nq-check-pack-storage/src/smart.rs` | `d0e06e3e91a91e5e3fb4fc4713f60ad37d35f88c25316de277b6b480be6e5821` | Later bounded acquisition behavior | Classic witness-v0/status/helper assumptions |
| `crates/nq-check-pack-storage/src/gpu.rs` | `331d868e98561eeeb318d9fe781a5309986b66a318cd34c0433e826c0232ad77` | Later bounded acquisition behavior | Classic status/config assumptions and runtime-module qualification gap |
| `scripts/install-first-run-campaign.py` | `9e6d020ae1b9880e0121152e5f46cbe1a48922efbab4dcf7adb6354b3beabb14` | Methodology only, not source copy | Classic names, ports, workspace/source installation and suite assumptions |

No crate, directory, commit, migration, or Classic runtime is approved for
wholesale transfer.

## E specimens retained as donor references

| Donor path | SHA-256 | Semantic purpose |
|---|---|---|
| `crates/nq-witness/tests/fixtures/zab2nq-external-projection.json` | `ace5000fa8533403fa6f58005d5521c2338f54298e4ef28f775c02208f521968` | Static external-projection compatibility vector |
| `crates/nq-witness/tests/fixtures/projection_receipt/continuity-imported.json` | `d7511108e1bebc6ad2ec60aa8c19d3163e71da15565100c078f6ad931041f4db` | Imported-projection custody/refusal behavior |
| `crates/nq-witness/tests/fixtures/projection_receipt/docket-substitution-refused.json` | `47d8873e145ad4cbb003cc0d7037bc51ee6af65a2f048d1e3a393e051893ea8e` | Source-substitution refusal behavior |
| `crates/nq/tests/fixtures/reliance-profiles.json` | `dc35bfc749fd41689c00d40a64c4258981e8a5e78bbd138e5f841709315d9e2b` | Consumer-purpose reliance correspondence |
| `docs/install/campaign/installation-operator-scenarios.v1.json` | `5dd5b70d36cfb1fc5c9fb5ce26cd7713f314fc09d5956bb24bd3b894f6d4e7ff` | Literal-docs and failure-recovery scenarios |
| `docs/install/campaign/clean-room-f853180-results.json` | `596b73a967f2d73d9f483f1f139446021bbeb6607cc32d3729b2b528a9fc5c2e` | Adverse Classic installation baseline |
| `docs/install/campaign/synthetic-20260727-results.json` | `ceba71f7b847a123822dadde80af65f646ddc19c9ce6b89d674139d595db9cc8` | Synthetic operator evidence, not human usability proof |

These specimens are not copied by the survey. A later import must record source
commit/path/license/digest and must not promote static external projections
into current runtime observations.

## Classic compatibility debt excluded

The following is a negative transfer list:

- `nq-core` compatibility re-exports and mixed ownership;
- `nq-db`, its 64 migrations, raw `rusqlite::Connection`, and private-table
  crossings;
- `nq-witness-api` mixed DTO transport;
- `nq-monitor-agent` and the compatibility `nq-witness` binary rename;
- closed `nq.witness_packet.v1`/`Collectors` envelopes;
- all-collectors dispatch and concrete-pack dependencies;
- planning-only `nq-suite` and its second composition vocabulary;
- detector-specific dashboard loaders and notification metadata;
- source-workspace/path-only package composition;
- private/deployment paths, thresholds, service names, and historical corpus
  assumptions.

Classic's report explicitly says these prevent independent releases and full
deployment reconstruction. Moving them would reproduce the problem.
