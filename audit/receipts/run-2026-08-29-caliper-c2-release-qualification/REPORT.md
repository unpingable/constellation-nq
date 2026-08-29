# CALIPER C2 release qualification

Campaign: `CALIPER`  
Slug: `passive-vm-release-reproducibility-and-lifecycle-v1`  
Parent: `SOCKETWRENCH` terminal receipt commit `183e95cd2766c80c720e275a8042a6b4349aad4a`  
Qualified source/lifecycle-law ancestor: `7a6b7c02acbd8c5de0bb92ebda77ebb905828bf5`  
Exact qualified CALIPER source commit: `e06a7b85699d23bbc0637fd4a1288f8c15afcbc8`

Classification: `PASSIVE-VM-RELEASE-REPRODUCIBILITY-QUALIFIED`

The predecessor result
`PASSIVE-GENERATION-STORE-LIFECYCLE-QUALIFIED-WITH-RELEASE-LIMITATION`
remains historical evidence. This is a new independent result.

## Clean compiler reproduction

Two complete musl release builds began after removal of CALIPER's
`x86_64-unknown-linux-musl` target output. Both used:

```text
env CC_x86_64_unknown_linux_musl=/tmp/socketwrench-musl.oJzYiu/x86_64-linux-musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/socketwrench-musl.oJzYiu/x86_64-linux-musl-gcc \
  cargo build --workspace --bins --locked --release \
  --target x86_64-unknown-linux-musl
```

The temporary wrapper pathname is not durable custody; its content identity is
recorded below. Rust and Cargo were version 1.94.0.

Build A and build B produced the same executable SHA-256 values, which also
equal the qualified SOCKETWRENCH cohort:

- `nq`: `fd841a7acaacff978df793b3fe676017030e5f0328987e0591778a141ad963e9`
- `nqd`: `25558e3710d33c4a61d25cf9b6ad2c08910559e1776c065e4b400c974c18f731`
- `nq-host-helper`: `cd12ed5620a34fae531cbb5d451fd5b3519395ce2f3402a12d3fd4e7d3a87494`
- `nq-linode-origin-helper`: `6f54053238de79cccd4d2cd540a844c4955e960c9179472a38c872f5daed2bf7`
- `nq-passive-load-helper`: `29256592dbc963a9aa3c3d6886c15afbb8114d5d143c4fdd859849d09ef8045c`

## Bundle reproduction and contents

The exact-source final reproducibility harness completed under the unchanged
393216-KiB default scratch guard. Peak aggregate scratch allocation was
316628 KiB, leaving 76588 KiB headroom. Its two independently assembled cases
matched byte for byte across archives, extracted trees, embedded manifests,
checksum sidecars, absolute paths, insertion order, umask, locale, timezone,
and `TMPDIR` differences.

Published campaign-local release custody:

- tar SHA-256: `fc693876484d77a31adbf521ce12e968b7277848674915dc540988867b86a99f`
- Debian SHA-256: `7690816a1e574e32eb6606619bbed980ee3e6ea2469a745d685b065693c6566d`
- embedded manifest SHA-256: `c752cbd45aafe3d18532bf5f49a3f719058bd5094b3b3be543cc5b299c75b143`
- embedded manifest entries: 84

`SHA256SUMS` verified both published artifacts. The tar and Debian extracted
payloads were compared exactly by the reproducibility harness; package
allowlist, embedded manifest, Debian md5sums, and archive listings all passed.

## Toolchain custody

- compiler wrapper SHA-256: `617611c69a08d772298ffe2358fdc9b7a53eb9a389a9590281108dcaa6f58820`
- musl GCC specs SHA-256: `00591912cc91feb41f498f31a6d1843c9b326564a4a779e450cfb8fb8a1f4452`
- musl package SHA-256: `9f0883c20b4b746e05e947bafd99cb933f5494ffaaa6fcd360cbe1fbcf264883`
- musl-dev package SHA-256: `4b451ecb6a0f8469883058cf22a807f3bd9cc16d115cc08b7efc35fe8eb44db2`
- musl-tools package SHA-256: `46c01d212d3eb3a1322693089037f0a5c92383a089d39c392db3c86c19ffb229`

## Package material custody

- `nqd.service`: `cdb3990e6420102ac04ce189af3f9266bee2a0f919118f2609895dd371da199d`
- passive observer service: `69ddc31daa0f238c315707b1c204769887ac5c700e42e35570e59701a974d542`
- recurrence service: `fa41bf306b91e0a106856a12e2f23cfeb5f67ae321e45d0e7324debb3f590b09`
- recurrence timer: `8c8b6a3a3faff48519b779fc29b2f61d3bbb457dc2c27310c7d011b490421dd3`
- sysusers: `18d926bb7fd1c2fd512f2bed2c3dec08826236556dd9ad306fac67f5e5c72d08`
- tmpfiles: `b675c201ac3e26297841eedc489b8662bd55d942274f197b9b406b9262c43ab6`
- Debian `postinst`: `5498795712898361910ee1f5b1d578dd481c8a002ed7f7893aca5e77411b35e6`
- Debian `prerm`: `44ba4af4cb9d14781519dcf3e991c3c3d4c95901028a3719ddc4b47870b654a1`
- Debian `postrm`: `73428bb638cf05b2c19148e2f44e63f1c0d4e45bdc35aad8498892ed9137900d`
- Debian control template: `5444f3ab45691c32cb88e3657551782814c2cc299673e0293a8d1e55263570fa`

## Qualification gates

All required gates passed:

- focused AF_UNIX `O_PATH` kernel-flag, non-read, invalid-target, pathname
  substitution, and separate-process cases;
- exact enrollment lifetime boundary cases, including the prior invalid E2
  construction and the corrected full-horizon construction;
- generation-store absence, unsafe mode, capacity, and bounded-readiness cases;
- passive-helper real process-boundary suite, 3/3;
- locked workspace/all-target suite, zero failures;
- Clippy over the locked workspace/all targets with warnings denied;
- Rust formatting;
- passive load, operational continuity, operating-grant, and bounded-selection
  structural checks;
- independent Python helper, profile catalog, protocol, system-contract, and
  release-verifier cases;
- release publication failure atomicity (`lock=1`, `failure=97`, `killed=137`);
- `git diff --check` and clean exact source custody.

C2 creates no H, G, E, enrollment, admission, activation, sample, recurrence,
acquisition, handoff, or fence. C3 may now construct one genuinely fresh local
VM entry gate using this exact release. It may not patch through authority after
activation.
