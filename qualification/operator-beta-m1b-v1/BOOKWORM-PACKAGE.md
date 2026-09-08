# Debian 12 package compatibility and reproducibility evidence

**Status:** `CORRECTION CANDIDATE / INDEPENDENT REVIEW REQUIRED`
**Rejected package-evidence checkpoint:** `9aa09b35d08b3f52602a30f3079efb9194b8fcc1`
**Source subject:** `5c064f06d8bcae2fce9dfdb9598167c2343ff706`
**Source tree:** `c820ea0fc19b065289d9e966926b2ab7a8374b5f`
**Prior package qualification:** `8865dcad23f17a1f26716161554530237e04bb9e`
**Authority effect:** exact package-build and local qualification evidence only;
no source semantics, deployment, production, provider, VM effect, AG authority,
or Docket custody.

## Preserved refusal and rejected artifact

The host-built package used by `operator-beta-m1b-run-003` required
`GLIBC_2.39`. Its first NQ invocation on Debian 12 refused. Run-003 remains
`REFUSED / NO_EFFECT_ATTEMPTED` with null effect custody; it is not retried or
relabeled.

The first Bookworm-compatible candidate, package SHA-256 `e4908984...`, ran on
Bookworm but was rejected at checkpoint `9aa09b35...`: its prose recipe did not
reproduce exact binaries under independent review. Those bytes remain separate
under `bookworm-package-001` and are not accepted by the current harness.

## Closed build inputs and wrapper

`build_bookworm_package.py` is a qualification-only builder/verifier. It
requires the exact clean source head/tree above and a physical campaign-owned
vendor directory. The vendor snapshot was produced from the exact lockfile;
fetching missing lockfile-pinned crates was a separate networked input-acquisition
step. The admitted builds themselves use no network.

The wrapper hashes every regular vendor file with framed relative path, mode,
length, and content; it refuses symlinks and other entry types. The admitted
snapshot contains 11,506 regular files and has tree SHA-256
`8b0298cc690c2c662cbda5bd931380656775b1caa38aed4d7d8f2c517d384ebe`.
It resides at:
`/data/git/.campaign-artifacts/nq-ng-operator-beta-m1b-20260908/operator-beta-m1b-v1/bookworm-build-inputs-002/vendor`.

Both clean builds use:

- image ID
  `sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379`;
- repository digest
  `rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f`;
- fixed container paths `/src`, `/vendor`, `/cargo-home`, and `/build`;
- read-only source and vendor mounts, fresh build/Cargo-home directories,
  `--pull never`, `--network none`, and fixed hostname/user identity;
- Rust/Cargo `1.94.0`, `--locked --offline`, four bounded Cargo workers, one
  release codegen unit, no incremental state, and fixed path remapping;
- `LC_ALL`, `TZ`, `HOME`, `USER`, `SOURCE_DATE_EPOCH=1700000000`, and the
  complete remaining build environment fixed by the wrapper; and
- the unchanged source-owned release assembler and exact profile catalog.

The machine receipt records exact source and selected input digests, vendor
identity, builder identity, environment and complete normalized container argv
including mount modes and fixed uid/gid, four binary identities/ABI bounds,
five artifact identities, two build/assemble log identities, exact
qualification builder/test byte identities, and equality of the independent
builds. `verify` recomputes every field rather than accepting it from the
receipt. Unit cases cover vendor content mutation, symlink refusal,
network/mount/argument boundaries, source/image/binary/artifact/qualification
substitutions, and unknown receipt fields.

## Exact retained result

Campaign-owned directory:
`/data/git/.campaign-artifacts/nq-ng-operator-beta-m1b-20260908/operator-beta-m1b-v1/bookworm-package-003`.

- receipt schema `constellation.operator_beta.nq_bookworm_package_build.v1`;
- Debian package `nq-ng_0.1.0_amd64.deb`, 8,694,038 bytes, SHA-256
  `0e3ab6307b41e9d80a6bdd503324895b5c46d49aef57e9421abb0e294dbc9fca`;
- release tar `nq-ng-0.1.0-linux-amd64.tar.gz`, 11,961,977 bytes, SHA-256
  `ea055f7b890032ed84eaf5eb7b10625b7e5237d9c91e3dddcb0a7f75120c12b6`;
- `SHA256SUMS`, SHA-256
  `8060a8e0881761a18388f01a413ce82aff1e968a2f420b98a111c47a0e157930`.
- qualification builder SHA-256
  `cd1561056e4c5ff95185be3e71110c0f7fecafeacd563cfd80addeb617a4c1fc`;
- qualification test SHA-256
  `fa9c00821969ce70f5cf2c53b09f2876e759063ceb3645dfdb220bdc1435a5cf`.

The two clean builds produced byte-identical binaries and all five release
artifacts. Exact packaged binary SHA-256 identities are:

- `/usr/bin/nq`: `03778e0e9ea19366c920c98d041436d30f92b83abf0745766ef446c811e65cd9`;
- `/usr/bin/nqd`: `54efcb4d7fc0671db869e3cfe21f6148d5141dd4632c3c41eab3391b70610c72`;
- `/usr/lib/nq/helpers/nq-host-helper`:
  `6fe3a7ae25da7bc7cf43a9ab67812c5ed64f389d7cee8cabd1746c3fc3146881`;
- `/usr/lib/nq/helpers/nq-operator-beta-helper`:
  `5613b1a75c2eec1846a47ce6c740632cc0f009114a1bb615c7b7f885a34740dc`.

All four require no glibc symbol newer than `GLIBC_2.34`, within Debian 12's
glibc 2.36. `build` completed two clean source-to-artifact paths and `verify`
reopened the retained receipt successfully. This qualifies only these exact
package bytes and their provenance/compatibility; the live M1B exercise remains
unqualified until a fresh occurrence completes and is independently reviewed.
