# Provider-intake foundation qualification receipt

Date: 2026-07-22

Verdict: **READY-FOR-PROVIDER-INTAKE-RATIFICATION**

This receipt records two constitutionally separate acts: the exact local mint
of the already-qualified `v0.1.0` release, followed by a new clean-pinned
provider-intake foundation campaign. No post-release source is contained in or
claimed by the release tag.

## Exact v0.1.0 mint

Pre-mutation verification matched every operator pin. The repository was on
clean `main` at record-only commit
`e3c451f9722cb81dd22af25c52b264e6b888ed81`, tree
`328c41c97f11e57500d9207824d35b086a889454`, with no tags and no remote.
The qualified package was `nq-ng 0.1.0 amd64`, SHA-256
`24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`.

Operator ratification created one local lightweight tag:

- tag: `v0.1.0`;
- commit: `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`;
- tree: `f7f244d69461e342997850869cb243abdbdedf27`;
- mint verdict: **NQ-V0.1.0-MINTED**.

The tag was not created at record-only HEAD, was never moved, and contains none
of the provider-intake work. `dist/nq-ng_0.1.0_amd64.deb` remains the exact
minted package above and was not rebuilt or modified during this campaign.

## Provider-intake source pin

Post-release work was created on `campaign/provider-intake-foundation` from the
exact record-only base:

- candidate commit:
  `44e556709e629eb3c83d1d74bfbcf12cb4c9a549`;
- candidate tree:
  `9aee37f90b93f27296550d9664af5ec574e5bf27`;
- parent:
  `e3c451f9722cb81dd22af25c52b264e6b888ed81`;
- technical commit:
  `feat(provider): establish typed local intake custody`.

The candidate is one combined operational-evidence implementation, not a new
daemon or remote service. The existing retained-descriptor local helper is the
only live provider and crosses the typed intake boundary before NQ protocol,
profile, detector, status, or archival judgment.

## Boundary and storage decision

The canonical NQ-specific boundary is headed by `ProviderIdentityV1`, the
private non-deserializable `VerifiedProvider`, `ProviderAttempt`,
`ProviderIntakeContextV1`, `ProviderResponseInterpretationV1`, and
`ProviderIntakeRecordV1`. It preserves the NQ-owned request and attempt
identities, independently verified provider/admission/executable/protocol/
configuration/profile/evaluator identity, subject/scope/vantage/capabilities,
exact native acquisition outcome, timeout phase, resource result, raw bytes and
digest, timestamps, candidate response, coverage, incompleteness, structured
provider errors, declared provenance, checkpoint, and replay identity.

Schema v4 uses the provider-intake parent-record design. It adds
`local_provider_admissions`, `provider_intake_attempts`,
`local_watcher_provider_intakes`, `provider_intake_acknowledgments`, and
`legacy_v3_watcher_run_intake_gaps`. Every new intake remains linked to an
exact watcher run; no nullable provenance shortcut or independent untracked
submission lane exists.

The exact released schema v3 is frozen and verified before migration. The
v3-to-v4 migration may derive a prospective local-provider admission for
future attempts, but every old watcher run receives an explicit
`provider_intake_not_recorded` gap. No historical raw capture, intake identity,
or acknowledgment is synthesized. Older or modified schemas remain preserved
and fail closed.

Replay is exact before semantic evaluation. The same provider admission,
attempt identity, complete bound context, and raw digest returns the existing
stored result and acknowledgment without re-evaluation or checkpoint movement.
Changed bytes, provider, subject, scope, vantage, profile, evaluator,
capability, checkpoint, native outcome, or interpretation refuses. Rotation or
revocation blocks live reuse while historical receipt reopening remains
read-only and grants no provider authority.

`DurableIntakeAcknowledgment` is inserted after the intake, run, raw custody,
admission or linked refusal, evaluations/findings, status, sequence, and
watermark inside one immediate SQLite transaction. It is returned only after
commit. It means only that NQ durably committed the exact attempt and canonical
downstream outcome. It does not mean report admission, detector presence,
health, testimonial sufficiency, ratification, standing, or authority. A
checkpoint is eligible only through the corresponding committed intake and
acknowledgment.

## Clean-pinned admissibility audit

The authoritative ledger is copied byte-for-byte under
`audit/receipts/run-2026-07-22-provider-intake-foundation/refusal-audit`:

- `ledger.json` SHA-256:
  `bb1a8fad28bde6b4d4d6a3f7f581be54c70c7ee7b2955da3703ade19e94c36e2`;
- `ledger.md` SHA-256:
  `4b5ff168254402f16a2e8352b76c82ac4284ae55482beb84b836ebc9d0524b33`;
- initial and final target pin:
  `git:44e556709e629eb3c83d1d74bfbcf12cb4c9a549`, clean;
- gate: **Pass**;
- controls: AC-R4-001 Pass, AC-R4-002 Pass, AC-R4-003 Pass;
- census: zero unclassified projections, zero serialization violations, zero
  missing entry points, and zero obstructions;
- waivers: none;
- mutations: 2/2 executed and 2/2 bit from pristine green to mutant red.

Verifier and specification identity:

- verifier SHA-256:
  `4cef41d898e4ad770196a5709d1bcbcc5bd6757a3c63938f53824363aa68ede9`;
- control catalog SHA-256:
  `ec7ffee1192d5411f4adab2569288d4bcd61581040d9c6b66473871c3999c3ef`;
- `controls/v14/BASELINE.toml` SHA-256:
  `a28c44cab85f22264f713084f91a700bbae196b047f777dfbd898578dbe5a7f9`;
- AC-R4 control SHA-256:
  `4d130b594a0804c2f8607638feff940167ed741939fcf96bc64e11a04a43e460`;
- Lean release/revision/tree: `14.0.0` /
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9` /
  `72cba07e35588e9f67c252b0bd92cf0523ab178f`.

The exact audit command was:

```text
/home/jbeck/git/audit/target/debug/admissibility-audit run . \
  --controls /home/jbeck/git/audit/controls/v14 \
  --out /home/jbeck/nqlab/nq-ng-provider-intake-artifacts/44e5567/refusal-audit \
  --as-of 2026-07-22
```

The independent `gate` command also returned Pass. The first mutation erased
exchange-timeout phase and the forcing assertion turned red. The second
rederived stored status detail from a coarse code and typed reopening turned
red. The ledger is executable correspondence evidence, not a verified-runtime
or authority claim.

## Build and local verification

The following gates passed at or immediately before the clean source pin:

- `cargo fmt --all -- --check`;
- `git diff --check`;
- `cargo clippy --offline --workspace --all-targets --all-features -- -D warnings`;
- all 46 `nq-store` library tests and all six store-contract tests;
- provider identity, raw/native custody, replay, revocation/replacement,
  acknowledgment rollback, checkpoint, migration, restart, backup, API/CLI,
  and cold-archive hostile tests;
- the real cross-process `nqd` collection plus `nq` revocation test;
- debug and release locked offline workspace builds;
- protocol, Python helper, profile catalog, packaged protocol asset, and
  system-contract verifiers;
- 13 release-verifier unit tests;
- the hardening static/negative harness;
- release failure atomicity for contention, injected failure, and killed
  publication;
- epoch-zero reproducibility under path, insertion-order, umask, locale,
  timezone, and `TMPDIR` perturbations.

The broad all-target/all-feature workspace invocation reached the campaign
tests successfully and then reported eleven pre-existing runner-fixture/host
failures. They are not provider-intake regressions: the relevant `identity.rs`,
`runner.rs`, and `unix_runner.rs` blobs are identical at the minted pin, the
campaign base, and this candidate. Exact base/current reproduction identifies
an existing inline `python3 -c` fixture rejected as `ENAMETOOLONG`, a stale cwd
rename expectation contradicted by the ratified ancestry refusal, a distinct-UID
fixture using production-invalid `/tmp`, and host-wide `RLIMIT_NPROC=32`
colliding with the current UID process population. These failures were not
waived or relabeled as provider success; the clean-pinned provider evidence,
package checks, and VM qualification ran independently and passed.

## Rebuilt candidate identity

The post-release candidate was assembled outside `dist` from the exact clean
technical pin:

- package:
  `/home/jbeck/nqlab/nq-ng-provider-intake-artifacts/44e5567/release/nq-ng_0.1.0_amd64.deb`;
- Debian identity: `nq-ng 0.1.0 amd64`;
- package size: 7,343,630 bytes;
- package SHA-256 before and after VM qualification:
  `4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`;
- tar SHA-256:
  `bcc568a62ee7953564f2ac60a4a0562be28c78555e763baf1c85069459c994d3`;
- embedded 49-file payload manifest SHA-256:
  `0d7960c5c108f58d3c0d158105d17d32a116d9aebc10f6d205b87d8c1f6d2fd9`.

The rebuilt bytes differ from the minted package SHA-256 `24ca5e0b…`, as
required for runtime and schema changes. The minted package remains unchanged
in `dist`.

## Fresh Noble KVM qualification

- run identity:
  `/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-22-44e5567`;
- started: `2026-07-22T08:38:14-04:00`;
- completed: `2026-07-22T08:40:30-04:00`;
- top-level result: `pass`;
- acceleration: KVM, CPU `host`;
- Ubuntu Noble image SHA-256:
  `ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6`;
- staged and post-run package SHA-256:
  `4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`;
- guest lifecycle driver SHA-256:
  `b1ff672343df21d22945ac4da4b08ff9fd7db46385f774e92e705133a3d32b7c`;
- evidence manifest SHA-256:
  `b8262fdd58c99ca0f0c21ac8dff6017214289d0edbf33ce1d685467a6ddae4f1`;
- sealed inventory: 51 files, all recomputed successfully;
- sealed guest verdict SHA-256:
  `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2`.

Independent guest-result admission and complete evidence-seal reopening both
passed. The four mandatory markers passed: `AF_UNIX_CROSS_UID`,
`BYTE_TAMPER_REFUSAL`, `HELPER_DRIFT_REFUSAL`, and
`SOCKET_CONTRACT_REFUSAL`. Mandatory `./guest-results/RESULT` is inside the
seal; only the documented top-level result, seal log, and manifest are created
outside the canonical evidence inventory.

## Ratification gate and non-claims

The provider-intake foundation is ready for operator ratification at the exact
technical commit and package/run identities above. Ratification must not move
`v0.1.0` or imply that the post-release package is a tagged release.

The campaign creates no JCP crate or generic claim protocol, no AG integration
or action authority, no physical watcher split, no remote/network provider or
public submission endpoint, and no eBPF, TPM, formal-verifier, cloud, or human
provider. The provider boundary remains deliberately NQ-specific and
local-helper-only.

Nothing was pushed, published, uploaded, remotely configured, or tagged beyond
the separately ratified exact `v0.1.0` mint. No post-`v0.1.0` tag exists.
