# SOCKETWRENCH S0/S1 — AF_UNIX custody and enrollment-fixture repair

Date: 2026-08-28
Campaign: SOCKETWRENCH
Slug: `passive-vm-lifecycle-repair-v1`

## Classification

- S0: `PASSIVE-VM-AF-UNIX-CUSTODY-REPAIRED-AND-QUALIFIED`
- S1: `PASSIVE-VM-E2-LIFETIME-FIXTURE-QUALIFIED`

## Source custody

- Base: `675e247e85d8e2e1f2801c06445bf863f82b3a5b`
- Branch: `campaign/passive-vm-lifecycle-repair-v1`
- Qualified repair commit: `4e109f889330b876e7c1776b27fcde697ef77f21`
- Commit changes exactly `crates/nq-helper-sandbox/src/lib.rs` and
  `crates/nq-store/src/recurrence.rs`.

Prior terminal receipts remain unchanged. This campaign does not derive
authority from their failed charter objects.

## S0 finding and repair

`docs/DEVELOPMENT.md` and `packaging/systemd/README.md` require the helper
socket custody sequence to pin the helper-owned AF_UNIX socket with
`O_PATH|O_NOFOLLOW|O_CLOEXEC`, apply descriptor-relative
`fchownat(AT_EMPTY_PATH)`, and recheck exact inode, owner, and mode before
connect and `SO_PEERCRED`.

The old implementation composed `OpenOptions::read(true)` with custom
`O_PATH`. Native GNU emitted `O_PATH`, but the exact
`x86_64-unknown-linux-musl` build emitted
`O_RDONLY|O_LARGEFILE|O_NOFOLLOW|O_CLOEXEC`; opening an AF_UNIX pathname
therefore refused with `ENXIO`. This open-mode defect was the first causal
refusal on the actual packaged path and occurred before `fchownat`.

The repair uses `nix::fcntl::open` with exactly
`O_PATH|O_NOFOLLOW|O_CLOEXEC`, transfers the newly owned descriptor once
into `File`, and preserves every existing before/pinned/after custody check.
The corrected musl syscall contains `O_PATH`. The distinct later
`fchownat` permission boundary still requires `CAP_CHOWN`; the qualified
packaged service grants that narrow capability and its real descriptor-based
case passes.

OS-boundary regressions prove:

- kernel `F_GETFL` contains `O_PATH`;
- `F_GETFD` contains `FD_CLOEXEC`;
- descriptor metadata is a socket and content read refuses with `EBADF`;
- regular-file and symlink substitution fixtures refuse without mutation;
- a separate process completes the actual socket-custody path;
- pathname replacement is reached after the descriptor pin and fails closed.

## S1 finding and correction

Enrollment lifetime is correctly measured from enrollment creation to expiry,
inclusive at the deployment-policy maximum. The prior fixture pre-created E2
before G1, gave E2 expiry at the end of a two-generation horizon, but declared
only a 120-second maximum. Its `lifetime_exceeds_policy` refusal was correct.
It was fixture-policy construction, not a portability law.

The regression reconstructs the old invalid E2 and preserves its refusal. It
also proves the exact 120-second equality boundary succeeds, one millisecond
over refuses, expiry at creation refuses `invalid_expiry`, and an explicit
180-second fixture ceiling admits the bounded two-generation pre-created E2.

## Qualification

All completed successfully:

- `cargo test --workspace --locked`;
- `cargo clippy --workspace --all-targets --locked -- -D warnings`;
- `cargo fmt --all -- --check`;
- `git diff --check`;
- full native and musl `nq-helper-sandbox` tests;
- musl helper Clippy with warnings denied;
- compiled protocol/profile/system-contract checks;
- Python conformance checks;
- passive boundary and continuity structural checks;
- release verifiers and exact payload allowlist;
- failure atomicity;
- reproducible release verification.

The complete helper suite reports 14 passed and one deliberately ignored
subprocess probe (the non-ignored parent test invokes it). The new recurrence
boundary regression passes inside the 79-test `nq-store` suite.

## Qualified private release

- Debian package:
  `dist/socketwrench-4e109f8/nq-ng_0.1.0_amd64.deb`
- package SHA-256:
  `821c8f7f5dc536c46222c514f9d3b0114efd23a9045bf946d1eb76cd0ddcf0a8`
- `nq` SHA-256:
  `686f6928767a9896e359b1b9a6cf054ee4759fd586586977330c54ab32b68f1c`
- passive helper SHA-256:
  `901272c1a54ca10e8ba610ce706bc54d455f17602398bc5c13e65b68e4073134`
- origin helper SHA-256:
  `087febe3831c9eb4a6ce0ef31bde18bf923bab43ac58367db6b675b6c5ff5c3c`

The artifact is static PIE for `x86_64-unknown-linux-musl`. A disposable
extracted Noble musl toolchain was used because the host had no installed
musl compiler; no host package or privilege-model change was made.
