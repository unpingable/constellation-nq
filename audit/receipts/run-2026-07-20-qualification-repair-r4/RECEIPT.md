# Authoritative clean-pin qualification-repair receipt (r4)

Date: 2026-07-20

Verdict: **BLOCKED — exact candidate requires rebuilt package bytes; fresh VM
qualification not started**

This receipt supersedes r1-r3 only as the authoritative campaign verdict. All
earlier attempts and ledgers remain preserved as historical evidence. The r4
ledger was generated from clean target commit
`d82cf574b16cf4ff1d21ab5adda4b2b275f35069`; it is a failed release preflight
and crosswalk-closure receipt, not a passing mint qualification.

## Bound objects

- candidate: `dist/nq-ng_0.1.0_amd64.deb`
- Debian identity: package `nq-ng`, version `0.1.0`, architecture `amd64`
- packaged source commit: `06aa918b7b51cf165070d53215ee4e943192102e`
- campaign implementation/record commit:
  `d82cf574b16cf4ff1d21ab5adda4b2b275f35069`
- candidate SHA-256 before and after:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`
- Noble image SHA-256:
  `ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6`
- guest lifecycle driver SHA-256:
  `b1ff672343df21d22945ac4da4b08ff9fd7db46385f774e92e705133a3d32b7c`

Historical current-candidate VM run:

- path: `/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918`
- manifest SHA-256:
  `7ede5edb25a7f80f4e2532b5bd7bd62ff3cb74f7d2ad51a5d7d41ebb6bc68b11`
- manifest entries: 50; all 50 hashes recompute successfully
- corrected canonical inventory entries: 51
- omitted mandatory path: `./guest-results/RESULT`, SHA-256
  `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2`

The ambient-locale historical manifest and corrected `LC_ALL=C` manifest also
differ in ordering. The sole path-set defect is the omitted mandatory guest
verdict. The old run is cryptographically intact but insufficiently sealed and
not mint-sufficient; it is not corrupted. It was not edited, replaced, or
supplemented. The pre-rename
`/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-19-4abc478` run has the same
omission; its 50-entry manifest SHA-256 is
`11eef8a74ddbb14f921c642d850de866a33688d9a0efeb0d7e9e12ae487c7237`.

## Verifier and ledger identity

- verifier executable:
  `/home/jbeck/git/audit/target/debug/admissibility-audit`
- verifier executable SHA-256:
  `56ef1f313a7b428487420557696afc053c35265b309371acbe76c6a34f9270ad`
- verifier 39-path source-list digest:
  `3b14e0b400c5889d25d95a0f7e71186d0b05582fe6ef366822adca80370b0caf`
- source-list digest command, run in `/home/jbeck/git/audit`:
  `rg --files -g '!target/**' -g '!.git/**' | LC_ALL=C sort | xargs sha256sum | sha256sum`
- control baseline SHA-256:
  `2ad530769f8de10104b80b6aa90172eef3d12f354411161172a41c6a40865c30`
- AC-R4 control SHA-256:
  `f4369b7de1fa49009a80b99c41b62aaa4b50cab487f534f5e6dc8525d3ea2fcf`
- Lean revision/tree/release:
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9` /
  `72cba07e35588e9f67c252b0bd92cf0523ab178f` / `14.0.0`
- audited `audit/admissibility.toml` SHA-256:
  `b52bc8f99b5659bdbebb1fcccfb85f50a93845dc75e9d315cfd54d71cc1a051b`
- audited `audit/REFUSAL_PRESERVATION_CROSSWALK.md` SHA-256:
  `53cc13fb415df190ba4d036c853e5016909d511940b61109fde41bb7b46a8321`
- repaired `hardening/run-noble-qemu.sh` SHA-256:
  `2360f9a0d975fe6762152494c84e2cd44331531cd9d033db2b3f73a1397e313c`
- hostile `hardening/test-harness.sh` SHA-256:
  `9b05facf31de786af2e839718cc308b728a59ee11ede5967b3c9c8ffc1d4af84`
- forcing source `crates/nq-core/src/engine.rs` SHA-256:
  `20965a14f1808e4ecb8ee3388e529b0321ad047af6aaf0008dba8569a07031dd`
- forcing source `crates/nq-store/src/lib.rs` SHA-256:
  `eb37adb145d5efecd77318a72e2f688fe2fd5e348e6a112bf15bc24799914de1`
- wire-test source `crates/nq-protocol/tests/conformance_corpus.rs` SHA-256:
  `0f56079441377e25e3439412f46d866f40b6ab82e7e1a420266882084debd843`

The framework repository has no commit and all its source is untracked; the
executable digest and reproducible source-list digest therefore identify the
verifier.

Authoritative ledger:

- directory:
  `audit/receipts/run-2026-07-20-qualification-repair-r4/refusal-audit`
- target pin: `git:d82cf574b16cf4ff1d21ab5adda4b2b275f35069`
- `ledger.json` SHA-256:
  `24f2cb75c3e40ee20f41aebaf965159ad22979c6a49e210480cd71bfdfe6c896`
- `ledger.md` SHA-256:
  `d4b867396bf7dc30d8020bce00f7f73eea37c471e2cfadedaf6278ac2eb2765d`
- gate: **Fail**
- census: 0 unclassified projections, 0 serialization violations, 0 missing
  entry points, and 0 obstructions
- waivers: none; expired waivers: 0
- controls: AC-R4-001 Fail, AC-R4-002 Pass, AC-R4-003 Fail
- mutation record: 2/2 commands reported biting

The v1 ledger records only nonzero mutation-command exits and cannot establish
whether a mutant compiled and failed its named assertion. Mutation is auxiliary
to this verdict. The independently rerunnable forcing cases below, together
with the bound code-path/type inspection, establish the release failures.

## Exact checks

```text
working directory: /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918
sha256sum --strict --check ARTIFACTS.sha256
PASS: all 50 historical entries recompute

working directory: /home/jbeck/git/skunkworks/nq-ng
hardening/run-noble-qemu.sh --check-guest-results \
  /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918/guest-results
PASS: independent guest admission and all four mandatory markers

hardening/run-noble-qemu.sh --check-evidence-seal \
  /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918
EXIT 1: historical manifest is not the exact canonical sealed inventory

bash -n hardening/run-noble-qemu.sh hardening/test-harness.sh
PASS

hardening/test-harness.sh
PASS: exact coverage plus hostile top-level/nested RESULT, omission,
      alteration, duplication, unsealed evidence, symlink/non-regular-entry,
      physical-root alias, completion marker, guest admission, input hash,
      and stale-output cases

cargo test --offline -p nq-protocol --test conformance_corpus same_code_distinct_refusals_remain_distinct_on_wire -- --exact
PASS

cargo test --offline -p nq-core engine::tests::status_store_and_backup_preserve_same_code_distinct_detail -- --exact
PASS

cargo test --offline -p nq-core engine::tests::forcing_exchange_timeout_phase_survives_dry_and_status_surfaces -- --ignored --exact
EXIT 101: write/read timeout phases collapse to identical outward evidence

cargo test --offline -p nq-core engine::tests::forcing_protocol_refusal_dependent_fields_survive_collection_status -- --ignored --exact
EXIT 101: helper retriable/structured detail collapses after the wire boundary

cargo test --offline -p nq-core engine::tests::forcing_profile_refusal_identity_survives_collection_status -- --ignored --exact
EXIT 101: profile identity, boundary, and detail collapse in status evidence

cargo test --offline -p nq-store tests::forcing_rejected_submission_requires_typed_refusal -- --ignored --exact
EXIT 101: rejected custody without a typed refusal is accepted

/home/jbeck/git/audit/target/debug/admissibility-audit run . --controls /home/jbeck/git/audit/controls --out audit/receipts/run-2026-07-20-qualification-repair-r4/refusal-audit --as-of 2026-07-20
EXIT 1: gate Fail at clean target pin d82cf574b16cf4ff1d21ab5adda4b2b275f35069
```

The r4 ledger-bound surface commands are the timeout-mapping forcing case
(reused for collection-cli, daemon-log, status-read-model, and local-api) and
the SQLite/status backup-reopen positive case. The wire pair test and the
protocol-adapter, profile-adapter, and rejected-custody forcing tests above are
separate target-owned crosswalk evidence, not r4 ledger surface findings.

The `nq-core` and `nq-store` additions are test-only. Their production portions
still match packaged source `06aa918`:

```text
nq-core engine production portion  e0fe928f4ec72496430039b4a362e92da9ffc6c3fe019313a24b70b2146d0b41
nq-store production portion        278618f16ddd57f49578ab1ce2f5343aeea7a72423553e6ab81114fe8106941e
```

## Residual limitations and stop decision

The r4 direct AC-R4 forcing list does not bind protocol-wire or cold-archive.
Protocol wire has the separate exact same-code pair test. Cold archive has
code-path plus verified SQLite backup/reopen evidence, not a direct `nq-app`
archive create/verify pair. The CLI, daemon, and API ledger bindings reuse an
upstream timeout-mapping forcing test rather than launching those entry points.
These coverage limitations prevent a future passing closure, but they cannot
cure the independently demonstrated typed-to-`CollectionOutcome` collapses;
downstream status and operator adapters cannot reconstruct the erased dependent
fields. A rebuilt candidate still requires direct pairwise tests at every
actual testimonial entry point.

The refusal-preservation dependency is explicitly release-required, not
qualification-only and not archival provenance. The failures are compiled into
`nq-core` and `nq-store`, hence into packaged `nq` and `nqd`; repair necessarily
changes package bytes. A fresh VM run cannot cure those exact bytes, so no new
VM qualification directory was created and no historical pass was inherited.

Next admissible action: repair the product mappings and store contract, rebuild
the package, and execute the entire corrected qualification from a clean source
pin. Nothing was tagged, minted, published, pushed, or remotely configured.
