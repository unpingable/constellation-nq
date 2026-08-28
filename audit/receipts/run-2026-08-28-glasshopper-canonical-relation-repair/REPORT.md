# GLASSHOPPER canonical watcher-relation repair

## Classification

`PASSIVE-CANONICAL-RELATION-PRODUCER-QUALIFIED`

Campaign slug: `passive-linode-canonical-relation-relaunch-v1`.

The worktree was created from exact qualified source
`675e247e85d8e2e1f2801c06445bf863f82b3a5b`. Before source repair, the prior
failed Linode launch and terminal receipts were copied byte-for-byte from the
central worktree and committed as `e0d7039`. Their source/destination SHA-256
values were identical and their checksum manifests and JSON parsed cleanly.

## Defect and repair

`OperatingCommand::BuildWatcherSuccession` used a shared canonical-output
helper whose `println!` appended LF. The strict file reader correctly refused
those bytes. Typed watcher diagnostic output is separately newline-framed and
has an existing one-LF contract, so the producer repair split the helper into:

* an exact canonical byte writer for succession relation files; and
* an explicit canonical-line writer for typed diagnostic output.

No verifier, normalization rule, relation schema, digest law, authority law,
or timeout was weakened. The strict file reader is unchanged.

The regression invokes the real shipped CLI and proves that relation stdout
equals exact canonical JSON bytes, does not end in LF, has the canonical
semantic digest, crosses the strict file reader, and that the deterministic
same bytes plus LF still refuse. Existing semantic-surface tests prove typed
watcher refusals retain exactly one LF.

Repaired source commit:
`241af7cef6a8ce2c980e20cc3c467710318200bf`.

## Qualification

The exact committed tree passed:

* `cargo test --workspace --all-targets --locked`;
* `cargo clippy --workspace --all-targets --locked -- -D warnings`;
* `cargo fmt --all -- --check`;
* all six `scripts/check_*_surface.sh` structural checks;
* passive-load boundary and passive operational-continuity verifiers;
* protocol asset verification against `target/debug/nq`;
* provider-operation noninterference verification;
* all 21 release-verifier tests; and
* `git diff --check`.

The full locked test suite was run twice; both runs passed. Repository-declared
explicit benchmark/fixture-generation tests remained ignored as intended.

## Fresh release

The release was built as x86-64 static PIE with Rust/Cargo 1.94.0 and the
already-downloaded Debian musl 1.2.4-2 toolchain packages. An inert adjusted
compiler-spec copy supplied their extracted `/tmp` paths; no host package was
installed. Release payload, profile, protocol, system-contract, diagnostic,
passive-boundary, and continuity verifiers passed.

```text
package  4f7625c029cc5efb090d292581deb2e6c014114813f675a1f21857ab6deb1886
tarball  b652bc136a1d0560f68bbcb2c05d95990ad02a2d8f0eb8ff57dfcf7c3ad9344d
nq       d12ee481cec6d149d634f7b3a349398eb4d271a767d9b6178636b60ef9d33d69
nqd      3a922f61a6fd7c9310b264d40d431f2f53d984b29e22966351b37bbe6a2a40af
host     cd12ed5620a34fae531cbb5d451fd5b3519395ce2f3402a12d3fd4e7d3a87494
origin   ff5c3ab94e423484cc2698623cf1efb81f3394dc2df7d3f1ce479b30c0e193e6
passive  a966ad1a36a8c61a75fe866a115a3531446ca2bbf3a7795e8af406af4182fc08
```

The Linode launch is classified independently in its own receipt.
