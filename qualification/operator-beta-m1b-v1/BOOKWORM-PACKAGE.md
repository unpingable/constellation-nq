# Debian 12 package compatibility evidence

**Status:** `CANDIDATE / INDEPENDENT REVIEW REQUIRED`
**Source subject:** `5c064f06d8bcae2fce9dfdb9598167c2343ff706`
**Source tree:** `c820ea0fc19b065289d9e966926b2ab7a8374b5f`
**Prior package qualification:** `8865dcad23f17a1f26716161554530237e04bb9e`
**Authority effect:** exact package-build and local qualification evidence only;
no source semantics, deployment, production, provider, VM effect, AG authority,
or Docket custody.

## Why this artifact exists

The package used by `operator-beta-m1b-run-003` was assembled from binaries
built on the host. Its first `/usr/bin/nq` invocation on Debian 12 refused
because that binary required `GLIBC_2.39`. Run-003 is retained unchanged as
`REFUSED / NO_EFFECT_ATTEMPTED`; this artifact does not repair or relabel it.

The same exact clean source was mounted read-only at `/src` and rebuilt with
networking disabled in local image:

- image ID
  `sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379`;
- repository digest
  `rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f`;
- declared base/toolchain `rust:1.94.0-bookworm`, Rust/Cargo `1.94.0`;
- `--network none`, `RUSTUP_TOOLCHAIN=1.94.0`, `--locked --offline`;
- disposable build output `/tmp/nq-ng-bookworm-build-90fd1a6`;
- unchanged release assembler, version `0.1.0`, architecture `amd64`, and
  `SOURCE_DATE_EPOCH=1700000000`.

An initial invocation attempted a rustup channel refresh and stopped before
compilation because networking was disabled. The admitted invocation fixed the
already-installed toolchain explicitly; it completed the release build without
network access or source mutation.

## Exact retained result

Campaign-owned directory:
`/data/git/.campaign-artifacts/nq-ng-operator-beta-m1b-20260908/operator-beta-m1b-v1/bookworm-package-001`.

- Debian package: `nq-ng_0.1.0_amd64.deb`, 9,197,848 bytes, SHA-256
  `e49089844c2b0eb56226cb8abe7b8313dc24b8c9838eae7283733bbab78b609d`;
- release tar: `nq-ng-0.1.0-linux-amd64.tar.gz`, 12,881,223 bytes, SHA-256
  `08dc36314559781b439a0926479b3e3fa0197635de9a1f419b12a46ce0a63320`;
- `SHA256SUMS`, SHA-256
  `350a7c7ee32bd9ecbbd0e9139d76d341607da091b5f3e3fda486c8af196d35b4`.

Package metadata is exactly `Package: nq-ng`, `Version: 0.1.0`, and
`Architecture: amd64`. Extracted executable identities are:

- `/usr/bin/nq`: `72219ab38b6ab152b0b3d9c852e6a27e873d554e9f5990f43e594d583bf3b882`;
- `/usr/bin/nqd`: `d8d59e7abd8bb61507b1ab6e7dda2af7966bc33dc6e1543d7d3945d8923d339a`;
- `/usr/lib/nq/helpers/nq-host-helper`:
  `750f8e18672421d38b9cc05e99ba60aeaa7d60f4c3a7c5748ccf98035e085d25`;
- `/usr/lib/nq/helpers/nq-operator-beta-helper`:
  `23edbdff90d1db9484caf5d1e67bc323f6231b5eb7d47f5d0430a15c957def8c`.

All four extracted package binaries returned their exact `nq.build_info.v1`
component/version record when executed inside the same immutable network-disabled
Bookworm image. `readelf --version-info` reports `GLIBC_2.34` as the newest
required glibc symbol version for each binary, within Debian 12's glibc 2.36.
This establishes compatibility evidence for these exact bytes; it does not
qualify the remaining two-VM exercise or generalize to later package builds.
