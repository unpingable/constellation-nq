# Qualification-repair preflight and crosswalk-closure receipt

> Historical attempt. This receipt and its ledger are preserved as campaign
> evidence but were superseded by the narrower r3 manifest binding. They are
> not the authoritative blocked verdict and are not a mint qualification.

Date: 2026-07-20
Verdict: **BLOCKED — candidate rebuild required; VM qualification not started**

## Exact objects

- candidate: `dist/nq-ng_0.1.0_amd64.deb`
- candidate source: `06aa918b7b51cf165070d53215ee4e943192102e`
- candidate SHA-256 before audit:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`
- candidate SHA-256 after audit:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`
- Noble image SHA-256:
  `ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6`
- guest lifecycle driver SHA-256:
  `b1ff672343df21d22945ac4da4b08ff9fd7db46385f774e92e705133a3d32b7c`
- historical VM run:
  `/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918`
- historical manifest SHA-256:
  `7ede5edb25a7f80f4e2532b5bd7bd62ff3cb74f7d2ad51a5d7d41ebb6bc68b11`
- historical manifest entries: 50, all recomputed successfully
- corrected canonical inventory entries: 51
- sole path-set difference: `./guest-results/RESULT`, SHA-256
  `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2`

The old manifest used ambient-locale ordering; the repaired canonical stream
uses `LC_ALL=C`, so its line order also differs. The one release defect in the
inventory path set is independently the omitted mandatory guest verdict.

The old run is cryptographically intact but insufficiently sealed and is not
mint-sufficient. It is not corrupted. The external run was read only and was
not edited, replaced, or supplemented.

## Verifier identity

- executable:
  `/home/jbeck/git/audit/target/debug/admissibility-audit`
- executable SHA-256:
  `56ef1f313a7b428487420557696afc053c35265b309371acbe76c6a34f9270ad`
- framework source-list digest:
  `3b14e0b400c5889d25d95a0f7e71186d0b05582fe6ef366822adca80370b0caf`
- baseline control SHA-256:
  `2ad530769f8de10104b80b6aa90172eef3d12f354411161172a41c6a40865c30`
- AC-R4 control SHA-256:
  `f4369b7de1fa49009a80b99c41b62aaa4b50cab487f534f5e6dc8525d3ea2fcf`
- target manifest `audit/admissibility.toml` SHA-256:
  `09efbf29fbd68a2911db5487eb285d0559fa2707087feba2af31caa0990a03bb`
- target crosswalk `audit/REFUSAL_PRESERVATION_CROSSWALK.md` SHA-256:
  `85f4afc85ec9dd0a9520b8258beca500eb1da7c65c5f8fa7e7bb7787f7951617`
- repaired host harness `hardening/run-noble-qemu.sh` SHA-256:
  `ae7cf6886f3fad0f4a2a549b5c7fa822b0b9ac5ee91f6f574435353610034aaf`
- hostile harness tests `hardening/test-harness.sh` SHA-256:
  `7be236d5df930a1ee0788114d10c5b45a8bc09547c55778b1f7d1d1180d94ab3`
- forcing-test source `crates/nq-core/src/engine.rs` SHA-256:
  `20965a14f1808e4ecb8ee3388e529b0321ad047af6aaf0008dba8569a07031dd`
- forcing-test source `crates/nq-store/src/lib.rs` SHA-256:
  `eb37adb145d5efecd77318a72e2f688fe2fd5e348e6a112bf15bc24799914de1`
- Lean revision/tree/release:
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9` /
  `72cba07e35588e9f67c252b0bd92cf0523ab178f` / `14.0.0`

The framework repository has no commit and all of its source is untracked.
The executable byte digest and this reproducible 39-path source digest are
therefore the verifier identity. Recompute the latter from
`/home/jbeck/git/audit` with:

```sh
rg --files -g '!target/**' -g '!.git/**' \
  | LC_ALL=C sort \
  | xargs sha256sum \
  | sha256sum
```

The ledger's target pin is
`dd0d23f6c1339d4dbce8a44ed4d8b4e715629f71 (dirty)` because this sandbox
mounted the target `.git` metadata read-only at audit time and could not create
the requested local audit commits before running. Committing this receipt later
does not retroactively rewrite that pin. This is a reproducible blocked
preflight and failed crosswalk-closure receipt, not a mint qualification.

## Commands and results

```text
/home/jbeck/git/audit/target/debug/admissibility-audit validate . --controls /home/jbeck/git/audit/controls
PASS: manifest valid against 8 families and 3 active controls

/home/jbeck/git/audit/target/debug/admissibility-audit census . --controls /home/jbeck/git/audit/controls
PASS: 5 candidates, 0 obstructions, all declared entry points present

/home/jbeck/git/audit/target/debug/admissibility-audit run . --controls /home/jbeck/git/audit/controls --out audit/receipts/run-2026-07-20-qualification-repair-r2/refusal-audit --as-of 2026-07-20
EXIT 1: gate Fail; AC-R4-001 Fail; AC-R4-002 Pass; AC-R4-003 Fail
         census 0 unclassified; 0 obstructions; 0 expired waivers;
         v1 ledger records both declared mutation commands as biting
```

Ledger identities:

- `refusal-audit/ledger.json` SHA-256
  `680845659dcfee0836486bb958b8f1c5bd2cadb21496d4a58b4f3747af8dff6e`
- `refusal-audit/ledger.md` SHA-256
  `007f5f0f3105789fb0f41239a929a5f00ae5eda42b2a93d5429b9a1c1e3833a2`

The positive status-store test reaches the shared public DTO, verified SQLite
backup, reopen, and the same DTO after reopen. The four explicitly ignored
release-forcing tests each exit 101 and establish, respectively:

1. write- and read-phase exchange timeouts become identical outward evidence;
2. distinct helper `retriable/details` become identical status evidence;
3. distinct profile/boundary/details become identical status evidence; and
4. rejected custody without a typed refusal is accepted.

See `../../REFUSAL_PRESERVATION_CROSSWALK.md` for exact symbols, paths, test
commands, projection classifications, implementation boundaries, and the
explicit limitation that several per-surface bindings are upstream proxy tests
rather than direct CLI/daemon/API/archive invocations. Those limitations bar a
future passing closure but cannot repair the package defects demonstrated here.

The v1 mutation ledger records only nonzero command exits; it cannot prove from
the ledger alone whether a mutant compiled and then failed its named assertion.
The blocked decision rests on the four directly rerunnable forcing failures and
the source-to-package path, not on that auxiliary mutation classification.

## Stop decision

The refusal-preservation crosswalk is explicitly release-required. Its gate
failed on behavior compiled into `nq-core` and `nq-store`, hence into the
candidate's `nq` and `nqd`. Repair changes package bytes. Starting QEMU could
not turn this exact package into a passing candidate, so no fresh VM run
directory was created and no old pass status was inherited.

The next admissible action is to repair the product mappings and store
contract, rebuild a new package, then run the full corrected qualification from
a clean source pin. No tag, mint, publish, push, or remote configuration is
authorized by this receipt.
