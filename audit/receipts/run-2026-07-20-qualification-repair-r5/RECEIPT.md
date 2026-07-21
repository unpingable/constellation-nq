# Mint qualification receipt (r5)

Date: 2026-07-20

Verdict: **READY-FOR-MINT-RATIFICATION**

This receipt records a fresh clean-pinned refusal-preservation audit, a
reproducible rebuild, and a corrected Noble VM qualification. It does not mint,
tag, publish, push, or waive anything. The operator must ratify the mint before
any release action.

## Historical qualification retained without rewriting

The previous package and run remain separate historical objects:

- old package source:
  `06aa918b7b51cf165070d53215ee4e943192102e`;
- old package SHA-256:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`;
- old external run:
  `/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-06aa918`;
- old manifest SHA-256:
  `7ede5edb25a7f80f4e2532b5bd7bd62ff3cb74f7d2ad51a5d7d41ebb6bc68b11`;
- old manifest inventory: 50 entries, all cryptographically intact;
- exact defect: mandatory `./guest-results/RESULT` was excluded by the
  basename-wide `! -name RESULT` expression;
- old-run verdict: cryptographically intact, insufficiently sealed, not
  corrupt, and not mint-sufficient.

The r4 blocked receipt and ledger remain immutable at
`audit/receipts/run-2026-07-20-qualification-repair-r4`. Nothing in r5 inherits
their failed gate or upgrades facts that the old package/store did not retain.

## Repaired source and candidate identity

The rebuilt candidate is bound to the exact clean audited source pin:

- source commit:
  `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`;
- package: `dist/nq-ng_0.1.0_amd64.deb`;
- Debian identity: package `nq-ng`, version `0.1.0`, architecture `amd64`;
- old package SHA-256:
  `44e7bd1af43ac4d6f9543d2dc286610be43d86426334ca24ff1a05a45d24e2e0`;
- rebuilt package SHA-256 before and after the VM run:
  `24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`;
- rebuilt package size: 7,011,264 bytes;
- reproducible tar SHA-256:
  `25bd257a8322d5e3b2cf70103ee3f4962a0a9985972fffc08941b4830eb917da`;
- embedded 49-file release payload manifest SHA-256:
  `26ab4ad83302b88c05c3a1ef93a4a87f193463171f895e6714325d5ce2c22837`.

The package bytes changed, as required for a product-level repair. Assembly at
`SOURCE_DATE_EPOCH=0` reproduced the deb and tar exactly under perturbed
absolute paths, insertion order, umask, locale, timezone, and `TMPDIR`.
Release failure atomicity also passed for lock contention, injected failure,
and killed publication.

## Refusal-preservation closure

The authoritative r5 ledger is copied byte-for-byte under:

`audit/receipts/run-2026-07-20-qualification-repair-r5/refusal-audit`

- target and post-run pin:
  `git:2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`, clean;
- `ledger.json` SHA-256:
  `3c1d7988422c164ffa3df0e4b7c16e65b725076a20f5a624c2d59832067e4509`;
- `ledger.md` SHA-256:
  `1e2d97d63362d72391ce88f36882d930c80924b7d558e74edce33f0bd5f3e9f9`;
- gate: **Pass**;
- controls: AC-R4-001 Pass, AC-R4-002 Pass, AC-R4-003 Pass;
- census: five classified projections, ten present entry points, zero
  unclassified projections, zero serialization violations, zero missing entry
  points, and zero obstructions;
- waivers: none; expired waivers: zero;
- mutations: 2/2 executed and 2/2 bit, each with pristine green and compiled
  mutant red.

Verifier and control identity:

- verifier:
  `/home/jbeck/git/audit/target/debug/admissibility-audit`, SHA-256
  `4cef41d898e4ad770196a5709d1bcbcc5bd6757a3c63938f53824363aa68ede9`;
- verifier/source-list digest:
  `ad4ba700023ca3c0a4bd27e122b8a5c27616cd5e75bc68663b5031ae280b0a0d`;
- catalog digest recorded by the ledger:
  `ec7ffee1192d5411f4adab2569288d4bcd61581040d9c6b66473871c3999c3ef`;
- `controls/v14/BASELINE.toml` SHA-256:
  `a28c44cab85f22264f713084f91a700bbae196b047f777dfbd898578dbe5a7f9`;
- AC-R4 control SHA-256:
  `4d130b594a0804c2f8607638feff940167ed741939fcf96bc64e11a04a43e460`;
- Lean release/revision/tree: `14.0.0` /
  `ff491b808ebeab2a132d9ade46d234cf85dcfbe9` /
  `72cba07e35588e9f67c252b0bd92cf0523ab178f`.

Target evidence identity at the audited pin:

- `audit/admissibility.toml` SHA-256:
  `6d8203f2a5761cd31b31d67b572f602c38123f0a98fcb7ceb14fddce960ca890`;
- `audit/REFUSAL_PRESERVATION_CROSSWALK.md` SHA-256:
  `f8b101acc189d1b9168f8b8e814f687b36c74828da441d6a6d3b1ced7d331e65`;
- `audit/SEMANTIC_TRANSPORT_MAP.md` SHA-256:
  `186abf14e5631dfe666ed117194fe00e814982bcefdde881bd6b5b134cb10256`;
- `crates/nq-core/src/engine.rs` SHA-256:
  `2cf83e27c4ca7261499343f6c604d0b83c10fe8de774d68e90655a9090cd7775`;
- `crates/nq-store/src/lib.rs` SHA-256:
  `8652038886c7dfa2ec775bf91106041544b47c540bb0a907d598f5e693c0a32a`;
- `crates/nq-app/src/transport.rs` SHA-256:
  `b360e14a85821b1ee2821ea2a235e209a076204c9e7dd175fca9b4096b2a2fa5`.

The exact audit command was:

```text
/home/jbeck/git/audit/target/debug/admissibility-audit run . \
  --controls /home/jbeck/git/audit/controls/v14 \
  --out /tmp/nq-audit-r5-2c41b0a/refusal-audit \
  --as-of 2026-07-20
```

The first mutation removed exchange-timeout phase and its command turned red.
The second reconstructed status detail from a coarse code and its command also
turned red. The ledger establishes executable correspondence only; it records
exit status rather than separately proving compilation or naming the failed
assertion. The Lean declarations remain specification evidence and are not
runtime authority.

## Fresh Noble VM qualification

- run identity:
  `/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-2c41b0a`;
- started: `2026-07-20T19:53:57-04:00`;
- completed: `2026-07-20T19:56:21-04:00`;
- top-level result: `pass`;
- acceleration: KVM, CPU `host`;
- Ubuntu Noble image SHA-256:
  `ffe6203da54deeb6db5d2a98a83f9ec8e55f149d3f7ba622e1abe5fa966ee3d6`;
- staged package SHA-256:
  `24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`;
- guest lifecycle driver SHA-256:
  `b1ff672343df21d22945ac4da4b08ff9fd7db46385f774e92e705133a3d32b7c`;
- evidence manifest SHA-256:
  `8ab1dc1a39b348f7a6a34cab72d2d178f0451557c5caca6fa88f686e57a5f4a3`;
- sealed inventory: 51 files, all 51 recomputed successfully;
- sealed guest verdict: `./guest-results/RESULT`, SHA-256
  `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2`;
- intentionally unsealed post-seal file: only top-level `./RESULT` (plus
  `./seal.log` and the manifest itself under the documented sealing law).

Independent reopening passed both:

```text
hardening/run-noble-qemu.sh --check-guest-results \
  /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-2c41b0a/guest-results
hardening/run-noble-qemu.sh --check-evidence-seal \
  /home/jbeck/nqlab/nq-ng-hardening/run-2026-07-20-2c41b0a
```

All mandatory markers passed:

- `AF_UNIX_CROSS_UID`;
- `BYTE_TAMPER_REFUSAL`;
- `HELPER_DRIFT_REFUSAL`;
- `SOCKET_CONTRACT_REFUSAL`.

The installed guest package was exactly `nq-ng 0.1.0 amd64`. Build-info probes
for `nq`, `nqd`, and `nq-host-helper` reported release builds and the production
separate-identity policy. The live Unix carrier used `nq-helper` UID 987 and
daemon UID 988. Admitted-report counts advanced after service starts, restart,
and reboot; remove, purge, reinstall, profile/system-contract tamper, helper
byte drift, and hostile socket refusal behaved as required.

## Residual scope and operator gate

The qualification is intentionally bounded to the declared Linux amd64 /
Ubuntu 24.04 / KVM package and the published four-marker lifecycle. It does not
claim FreeBSD qualification, portable historical migration, or unlisted
post-beta surfaces. The documented live lexical-ID paging limitation does not
affect immutable backup/archive enumeration and is not a release blocker.

The release-required refusal-preservation dependency is closed for this exact
source and package. No waiver or inherited pass is used. The remaining action
is operator mint ratification. If ratified, the source tag is `v0.1.0` at
`2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`, releasing only the exact deb SHA
`24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`.
Remote publication or push remains a separate explicit operator action.

Nothing was pushed, tagged, minted, published, or remotely configured during
this campaign.
