# CALIPER C0-C1 release reproducibility boundary

Campaign: `CALIPER`  
Slug: `passive-vm-release-reproducibility-and-lifecycle-v1`  
Parent campaign: `SOCKETWRENCH`  
Parent receipt commit: `183e95cd2766c80c720e275a8042a6b4349aad4a`  
Qualified lifecycle-law ancestor: `7a6b7c02acbd8c5de0bb92ebda77ebb905828bf5`

Classification: `PASSIVE-VM-RELEASE-REPRODUCIBILITY-BOUNDARY-QUALIFIED`

## C0 finding

The `NQ_REPRO_SCRATCH_KIB` quantity is the peak allocation reported by
`du -sk` for the complete temporary reproducibility harness. It is a temporary
workspace regression tripwire, not an executable-size, package-size, runtime
capacity, or semantic authority invariant.

The harness contains two source copies, two copies of all five static release
executables, two independently assembled tar/deb output sets, and four
extracted payload trees. The default hard budget remains 393216 KiB.

`source_files()` reads the worktree filesystem and excludes `.git`, `.agents`,
`.codex`, `target`, and `dist`. At the SOCKETWRENCH terminal worktree it
therefore included the untracked `.campaign-local/` VM custody directory. That
directory occupied 237756 KiB. Because the harness creates two source copies,
it contributed approximately 475512 KiB to the aggregate scratch quantity.
The clean CALIPER peak plus that duplicated allocation is 792116 KiB, within
1268 KiB of SOCKETWRENCH's observed 793384 KiB peak. The small remainder is
consistent with the differing receipt/source inventory and harness metadata.

The excess was therefore stale campaign-owned VM workspace state duplicated as
source input. It was not product growth, package content, debug output,
nondeterministic tooling, or a changed executable cohort.

## Clean reproduction

CALIPER was created as a distinct clean worktree from exact parent commit
`183e95cd2766c80c720e275a8042a6b4349aad4a`. The static release was rebuilt with
Rust/Cargo 1.94.0 and the same preserved x86_64 musl compiler wrapper used by
SOCKETWRENCH.

All five rebuilt executable SHA-256 values equal the SOCKETWRENCH receipt:

- `nq`: `fd841a7acaacff978df793b3fe676017030e5f0328987e0591778a141ad963e9`
- `nqd`: `25558e3710d33c4a61d25cf9b6ad2c08910559e1776c065e4b400c974c18f731`
- `nq-host-helper`: `cd12ed5620a34fae531cbb5d451fd5b3519395ce2f3402a12d3fd4e7d3a87494`
- `nq-linode-origin-helper`: `6f54053238de79cccd4d2cd540a844c4955e960c9179472a38c872f5daed2bf7`
- `nq-passive-load-helper`: `29256592dbc963a9aa3c3d6886c15afbb8114d5d143c4fdd859849d09ef8045c`

Two independent clean harness executions completed:

1. 316604 KiB peak under an unchanged explicit 750000-KiB ceiling;
2. 316604 KiB peak under the unchanged repository-default 393216-KiB ceiling.

Both executions produced identical results:

- tar SHA-256: `fc693876484d77a31adbf521ce12e968b7277848674915dc540988867b86a99f`
- Debian SHA-256: `7690816a1e574e32eb6606619bbed980ee3e6ea2469a745d685b065693c6566d`
- embedded manifest SHA-256: `c752cbd45aafe3d18532bf5f49a3f719058bd5094b3b3be543cc5b299c75b143`
- embedded payload entries: 84

## C1 resolution

No threshold or source change was necessary. The narrow resolution is an
isolated clean campaign worktree with non-source VM custody outside that
worktree. The existing 393216-KiB tripwire retains 76612 KiB (19.5 percent)
headroom over the repeated clean peak.

This receipt does not infer C2 release qualification or authorize C3 VM
construction. SOCKETWRENCH's prior release limitation remains canonical
historical evidence.
