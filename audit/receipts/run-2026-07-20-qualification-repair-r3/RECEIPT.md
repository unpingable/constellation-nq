# Qualification-repair preflight and crosswalk-closure receipt (r3)

Date: 2026-07-20
Verdict: **BLOCKED — candidate rebuild required; VM qualification not started**

This is the final pre-commit correspondence attempt. The r1 and r2 attempts in
the sibling directories remain preserved as historical campaign evidence; r3
supersedes them after narrowing the direct AC-R4 surface bindings. It is a
candidate-specific crosswalk closure with verdict **fail**, not a passing gate
closure and not a mint qualification.

## Exact objects

- candidate: `dist/nq-ng_0.1.0_amd64.deb`
- candidate source: `06aa918b7b51cf165070d53215ee4e943192102e`
- repository baseline at campaign start:
  `dd0d23f6c1339d4dbce8a44ed4d8b4e715629f71`
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
- manifest entries: 50; every entry recomputed successfully
- corrected canonical inventory entries: 51
- sole path-set difference: `./guest-results/RESULT`, SHA-256
  `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2`

The original ambient-locale manifest and corrected `LC_ALL=C` manifest also
differ in line order. The release defect is independently the omitted mandatory
guest verdict. The run is cryptographically intact but insufficiently sealed
and not mint-sufficient; it is not corrupted. It was read only and was not
edited, replaced, or supplemented.

The pre-rename run
`/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-19-4abc478` has the same
basename-wide exclusion defect. Its 50-entry manifest SHA-256 is
`11eef8a74ddbb14f921c642d850de866a33688d9a0efeb0d7e9e12ae487c7237`;
all entries verify, but its mandatory guest verdict is likewise outside the
seal. It remains historical evidence, not a mint qualification.

## Verifier and evidence identities

- verifier executable:
  `/home/jbeck/git/audit/target/debug/admissibility-audit`
- verifier executable SHA-256:
  `56ef1f313a7b428487420557696afc053c35265b309371acbe76c6a34f9270ad`
- verifier 39-path source-list digest:
  `3b14e0b400c5889d25d95a0f7e71186d0b05582fe6ef366822adca80370b0caf`
- baseline control SHA-256:
  `2ad530769f8de10104b80b6aa90172eef3d12f354411161172a41c6a40865c30`
- AC-R4 control SHA-256:
  `f4369b7de1fa49009a80b99c41b62aaa4b50cab487f534f5e6dc8525d3ea2fcf`
- Lean revision/tree/release:
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9` /
  `72cba07e35588e9f67c252b0bd92cf0523ab178f` / `14.0.0`
- `audit/admissibility.toml` SHA-256:
  `b52bc8f99b5659bdbebb1fcccfb85f50a93845dc75e9d315cfd54d71cc1a051b`
- `audit/REFUSAL_PRESERVATION_CROSSWALK.md` SHA-256:
  `53cc13fb415df190ba4d036c853e5016909d511940b61109fde41bb7b46a8321`
- `hardening/run-noble-qemu.sh` SHA-256:
  `2360f9a0d975fe6762152494c84e2cd44331531cd9d033db2b3f73a1397e313c`
- `hardening/test-harness.sh` SHA-256:
  `9b05facf31de786af2e839718cc308b728a59ee11ede5967b3c9c8ffc1d4af84`
- `crates/nq-core/src/engine.rs` SHA-256:
  `20965a14f1808e4ecb8ee3388e529b0321ad047af6aaf0008dba8569a07031dd`
- `crates/nq-store/src/lib.rs` SHA-256:
  `eb37adb145d5efecd77318a72e2f688fe2fd5e348e6a112bf15bc24799914de1`
- `crates/nq-protocol/tests/conformance_corpus.rs` SHA-256:
  `0f56079441377e25e3439412f46d866f40b6ab82e7e1a420266882084debd843`

The verifier repository has no commit and all of its source is untracked, so
the executable digest plus the reproducible source-list digest identify it.
Recompute the latter from `/home/jbeck/git/audit` with:

```sh
rg --files -g '!target/**' -g '!.git/**' \
  | LC_ALL=C sort \
  | xargs sha256sum \
  | sha256sum
```

The r3 ledger pins
`git:dd0d23f6c1339d4dbce8a44ed4d8b4e715629f71 (dirty)`. Its own exact
identities are:

- `refusal-audit/ledger.json` SHA-256:
  `e809de2652bcdc0fd8e0bfce087ba840be38d0ba7da2d7ddc0013e7b6bc154ec`
- `refusal-audit/ledger.md` SHA-256:
  `b8ca8c7b39907cbe4f35282f8a8882a18cf620ab9635c30284ac857cd182bb6b`

The dirty marker denotes these target-owned campaign tests, correspondence
objects, and records. The test additions in `nq-core` and `nq-store` are below
`#[cfg(test)]`; their production portions still match source `06aa918`:

```text
nq-core engine production portion  e0fe928f4ec72496430039b4a362e92da9ffc6c3fe019313a24b70b2146d0b41
nq-store production portion        278618f16ddd57f49578ab1ce2f5343aeea7a72423553e6ab81114fe8106941e
```

## Commands and results

```text
sha256sum --strict --check ARTIFACTS.sha256
PASS: all 50 historical manifest entries recompute

hardening/run-noble-qemu.sh --check-guest-results \
  /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918/guest-results
PASS: independent guest admission, including all four required markers

hardening/run-noble-qemu.sh --check-evidence-seal \
  /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918
EXIT 1: manifest is not an exact canonical inventory of sealed evidence

bash -n hardening/run-noble-qemu.sh hardening/test-harness.sh
PASS

hardening/test-harness.sh
PASS: exact seal coverage and hostile omission, alteration, duplication,
      unsealed evidence, nested RESULT, symlink, special-entry, root-alias,
      completion-marker, guest admission, hash, and stale-output cases

cargo test --offline -p nq-protocol --test conformance_corpus \
  same_code_distinct_refusals_remain_distinct_on_wire -- --exact
PASS

cargo test --offline -p nq-core \
  engine::tests::status_store_and_backup_preserve_same_code_distinct_detail \
  -- --exact
PASS
```

Each release-forcing command below exits 101 against the preserved candidate
source and is deliberately ignored by the ordinary developer suite:

```text
cargo test --offline -p nq-core engine::tests::forcing_exchange_timeout_phase_survives_dry_and_status_surfaces -- --ignored --exact
cargo test --offline -p nq-core engine::tests::forcing_protocol_refusal_dependent_fields_survive_collection_status -- --ignored --exact
cargo test --offline -p nq-core engine::tests::forcing_profile_refusal_identity_survives_collection_status -- --ignored --exact
cargo test --offline -p nq-store tests::forcing_rejected_submission_requires_typed_refusal -- --ignored --exact
```

They demonstrate, respectively: exchange-timeout phase collapse; helper
`retriable`/structured-detail collapse; profile identity/boundary/detail
collapse; and rejected custody accepted without a typed refusal.

```text
/home/jbeck/git/audit/target/debug/admissibility-audit validate . --controls /home/jbeck/git/audit/controls
PASS: manifest valid against 8 families and 3 active controls

/home/jbeck/git/audit/target/debug/admissibility-audit census . --controls /home/jbeck/git/audit/controls
PASS: 5 candidates, 0 obstructions, all declared entry points present

/home/jbeck/git/audit/target/debug/admissibility-audit run . --controls /home/jbeck/git/audit/controls --out audit/receipts/run-2026-07-20-qualification-repair-r3/refusal-audit --as-of 2026-07-20
EXIT 1: gate Fail; AC-R4-001 Fail; AC-R4-002 Pass; AC-R4-003 Fail;
        0 unclassified projections; 0 obstructions; 0 expired waivers;
        v1 ledger records both declared mutation commands as biting
```

The v1 mutation ledger records only nonzero command exits and cannot establish
whether a mutant compiled and then failed its named assertion. Mutation is
auxiliary here. The blocked decision rests on the four directly rerunnable
forcing failures and the source-to-package path.

## Residual limitations and stop decision

The r3 AC-R4 surface binding intentionally omits protocol-wire and cold-archive
from its direct forcing list. Protocol wire has the separate exact pair test.
Cold archive has code-path plus verified SQLite backup/reopen evidence only.
The CLI, daemon, and API ledger entries are upstream proxy tests, not launched
entry-point tests. These limitations prevent a future passing closure but
cannot repair the upstream erasure that already blocks this candidate. A
rebuilt candidate requires direct pairwise tests at every testimonial entry
point before a passing closure can be issued.

The refusal-preservation crosswalk is release-required. Its gate failed on
behavior compiled into `nq-core` and `nq-store`, hence into the candidate's
`nq` and `nqd`. Repair changes package bytes. Starting QEMU cannot turn these
exact package bytes into a passing candidate, so no fresh VM run directory was
created and no old pass status was inherited.

The next admissible action is product repair, a rebuilt package, and the full
corrected qualification from a clean source pin. No tag, mint, publish, push,
or remote configuration is authorized by this receipt.
