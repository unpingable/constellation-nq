# M3 native package owner result

Observed2026-09-09: two clean offline Bookworm builds and owner receipt reopening
passed. This is a package result, not M3/M4 VM, deployment or production acceptance.

Runtime: `920dc7621f5cdf768473cef26311294fdf6cf61c`,
tree `9a7cc5e9a654496ee6655f0f6fd2706cc4ad3686`.
Builder: `40968b77faf3fcf905d0b3a95be019cc99ea9dba`, based on earlier retained-log
builder7886222 with exact runtime pin and two-job budget. Builder source SHA256:
`5423bc5fd5c207a339eef28a88b3a5f0c139bbf7845a7900b656c152b927ac39`.
Docker image `sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379`,
Rust1.94, networknone/pullnever. Exact source archive worktree is frozen separately;
documentation descendants do not change the runtime package subject.

Evidence directory:
`/data/git/.campaign-artifacts/operator-beta-completion-20260908/m3-nq-package-001`.
Package `nq-ng_0.1.0_amd64.deb` SHA256:
`bb9b89fbe87d2b9b720de497c8a8f96e00aabfeadb0a7598fe0acc8c4fed76ca`.
Tarball SHA256:
`7ba3412cc85c3891dc0a100872d8d07a1cd9d9892d4ab857b0ac3baa8d51767f`.
Receipt `bookworm-build-receipt.v1.json` SHA256:
`601304c5f27d525d1da0ccde08be73ca54d72fac1122afad89013c651dcd27d8`.
Packaged nq binary SHA256:
`370c4fdff391886460a56747c9b894ba4bd53a2f37b796bfb7f7966d1229bd82`.
All four packaged binaries have maximum observed GLIBC2.34 requirements, distinct
from the host-debug binaryfb1e used for earlier app qualification.

Both build and assembly exit records are0; independent clean binary and package
bytes compare equal. Durable service invocation0b4f115280b34ae2af4f451109806a31
terminatedsuccess/exit0; outer marker M3_NQ_PACKAGE_001_PASSED. Original packages
and failed earlier occurrences are preserved. See M3-BOOKWORM-PACKAGE-RECOVERY.md
in the same campaign artifact root for exact producer and supervision commands.

Independent reviewer reopened the exact package with verifyexit0 and accepted
this bounded build scope in `M3-NQ-PACKAGE-001-INDEPENDENT-ACCEPTANCE.md` under
the campaign artifact root above. That disposition is separate from the owner
result and applies to the exact runtime/package/receipt identities recorded here.
VM cold-cohort restore and M3 finite maintenance
showing must each consume this exact package and establish their own evidence.
No authority, service installation, production backup durability or live ingestion
guarantee follows from reproducible package bytes.
