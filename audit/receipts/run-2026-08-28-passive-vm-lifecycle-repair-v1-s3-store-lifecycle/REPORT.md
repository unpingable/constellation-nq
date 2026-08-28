# SOCKETWRENCH S3 — generation-store lifecycle

Campaign: `SOCKETWRENCH`
Slug: `passive-vm-lifecycle-repair-v1`
Classification: `PASSIVE-GENERATION-STORE-LIFECYCLE-QUALIFIED-WITH-RELEASE-LIMITATION`

Independent subresults:

- lifecycle law/source: `PASSIVE-GENERATION-STORE-LIFECYCLE-QUALIFIED`;
- release reproducibility: `PASSIVE-S3-RELEASE-REPRODUCIBILITY-NOT-QUALIFIED`.

Source custody:

- branch: `campaign/passive-vm-lifecycle-repair-v1`;
- authoritative campaign base: `675e247e85d8e2e1f2801c06445bf863f82b3a5b`;
- S3 source commit: `7a6b7c02acbd8c5de0bb92ebda77ebb905828bf5`.

The prior S2 `FIRST SAMPLE STORE ABSENT` receipt remains unchanged historical evidence. S3 does not rewrite or reinterpret it.

## Lifecycle decision

Package installation owns only the shared parent `/var/lib/nq-passive-load/samples`, created as `nq-passive-load-observer:nq-passive-load-reader` mode `2750`. Before materializing any G, deployment/charter preparation owns creation of one unique pristine generation directory as observer:reader mode `0750`, plus its free-space proof. Generation, provider, H, activation, and succession objects bind that pathname but do not create it. Runtime opens, locks, and appends within the already-prepared directory; absence remains an ENOENT fail-closed defense. The provider reads it.

The new bounded `generation-store-readiness GENERATION` operator surface reopens exact canonical generation bytes, requires a real non-world-writable root, reports numeric UID/GID/mode, checks the immutable free-space floor with statvfs, and performs no retained-history traversal or mutation. It is run under the intended observer context after materialization and before H/G/E issuance. Activation repeats the same library validation before timer exposure.

The store root is mutable append custody. The exact generation manifest, signed samples, and append-only events are canonical immutable records. Selection entries/manifests and the current locator are content-bound reconstructible derived state.

Exactly five source files changed: the public readiness projection/API and CLI, activation prerequisite recheck, focused tests, and the operational doctrine. No runtime directory creation was added.

## Qualification

- focused readiness tests: 2/2 PASS (valid 0750/capacity, absent, world-writable, and insufficient-capacity cases);
- first parallel workspace run: one unchanged nq-core scheduling-sensitive `stderr_has_independent_bound` failure; immediate isolated rerun 1/1 PASS;
- full serial locked workspace: PASS (nq-app 86/86; nq-core 204 pass and 1 maintainer-ignore; passive helper 34 pass and 1 explicit performance-ignore; passive process tests 3/3; nq-store 79/79; remaining integration and doc tests PASS);
- locked workspace all-target Clippy with warnings denied: PASS;
- formatting and `git diff --check`: PASS;
- passive boundary, operational continuity, H surface, and bounded-selection structural checks: PASS;
- compiled protocol corpus 12/12, Python conformance 6/6, profile catalog, protocol assets, system contract, release verifier 21/21: PASS;
- publication failure atomicity: PASS (`lock=1`, `failure=97`, `killed=137`).

Static build invocation:

`env CC_x86_64_unknown_linux_musl=/tmp/socketwrench-musl.oJzYiu/x86_64-linux-musl-gcc CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/socketwrench-musl.oJzYiu/x86_64-linux-musl-gcc cargo build --workspace --bins --locked --release --target x86_64-unknown-linux-musl`

Toolchain: rustc 1.94.0 (commit prefix `4a4ef`), cargo 1.94.0. The build used the campaign's exact compiler wrapper/specs; provenance digests are in `result.json`.

Release artifacts:

- Debian package: `caa373d50f14d930d04a9b02b27655eea8685be220eda2c957bc6254b990c30a`;
- tar archive: `6afb6a3b7f5661a9d38972ce58c312dc3a371b7a8235317a56cb2f54bcde620f`;
- `nq`: `fd841a7acaacff978df793b3fe676017030e5f0328987e0591778a141ad963e9`;
- `nqd`: `25558e3710d33c4a61d25cf9b6ad2c08910559e1776c065e4b400c974c18f731`;
- host helper: `cd12ed5620a34fae531cbb5d451fd5b3519395ce2f3402a12d3fd4e7d3a87494`;
- Linode origin helper: `6f54053238de79cccd4d2cd540a844c4955e960c9179472a38c872f5daed2bf7`;
- passive helper: `29256592dbc963a9aa3c3d6886c15afbb8114d5d143c4fdd859849d09ef8045c`.

Bundle payload and release verification passed. Static unit, sysusers, tmpfiles, and Debian-control digests are recorded in `result.json`.

## Reproducibility limitation

The repository's hard aggregate scratch guard refused every bounded attempt before reproducibility certification:

- 393216 KiB ceiling: measured 579648 KiB;
- 600000 KiB ceiling: measured 620008 KiB, followed by an ephemeral cleanup missing-path line for case A;
- 700000 KiB ceiling: measured 701644 KiB, followed by an ephemeral cleanup missing-debroot line for case B;
- final 750000 KiB ceiling: both case A and case B tar/deb/SHA256SUMS creation completed, then the sole terminal refusal was `793384 KiB > 750000 KiB`.

All exited 1. Cleanup-race secondary lines are not artifact mismatches, but no byte equality is inferred because the harness did not certify it. The final finite bound was not raised again.

No S3 VM, H, G, E, watcher, admission, activation, sample, recurrence, acquisition, handoff, or fence was created. The repaired early validation is shared source law, but GLASSHOPPER's existing canonical samples factually prove its bound stores exist; its live evidence is not misleading. No Linode access or mutation occurred.
