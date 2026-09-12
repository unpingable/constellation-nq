# Constellation NQ public-preview release guide

## Release pin

The proposed public-preview source pin is
`e0151d0c090be7ce56e00f7d293440dbe43bf4a4`
(`campaign/operator-beta-nq-release-integration-20260909`; also
`beta-m4-harness-20260909`). It descends from the remote default branch
`main` at `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`.

The required Nightshift diagnostic-admission repair is present as
`d20efb1dcda2e53c78fcbbdd6a666fab277b6a2e`. Its stable patch ID and affected
file delta are identical to the separately named repair
`7ba57cbdb913673190f7385ae054d54fc317280e`; no merge or duplicate repair is
required. The source release adds only mechanical formatting and this public
guide to that candidate, using the normal default-branch publication workflow.
The fixed source tag is `constellation-public-source-20260912`. Do not move that
tag or `v0.1.0`, force-push, or rewrite history.

This is a source-only developer preview; it supplies no binary package or
installation artifact. Publication does not authorize a
production deployment, classic-NQ authority transfer, or a claim of complete
host coverage.

## Source preview

After the release owner has completed the repository rename and public
visibility transition, use a clean checkout at the verified release pin and
Rust 1.94. Until then, `https://github.com/unpingable/constellation-nq.git` is
the intended destination, not an available public-source claim. Source builds
are for developer preview and qualification; a completed package gate is
required before presenting a package as an installation artifact.

```sh
git clone https://github.com/unpingable/constellation-nq.git
cd constellation-nq
git checkout --detach constellation-public-source-20260912
cargo build --workspace
target/debug/nq --help
target/debug/nqd --help
```

The package and operational walkthrough is in [OPERATIONS.md](OPERATIONS.md).
It deliberately requires explicit configuration, initialization, and helper
admission; installation alone does not start or enable NQ.

## Focused release gate

Run this gate from the exact candidate checkout before creating a release tag.
The first two commands are source-only checks; the remaining Rust tests/build
steps must run under the release owner's recorded resource envelope.

```sh
cargo fmt --all --check
python3 -B scripts/test_release_verifiers.py
cargo test -p nq-core --lib
cargo test -p nq-profiles --test profile_validation
cargo test -p nq-system-contract --all-targets
cargo test -p nq-store --lib
cargo test -p nq-app --test admin_lifecycle
python3 -B helpers/python-conformance/test_helper.py
cargo build --workspace
target/debug/nq protocol check
python3 -B profiles/verify_catalog.py target/debug/nq
python3 -B scripts/verify_protocol_assets.py protocol target/debug/nq 0.1.0
```

Before publishing a package, additionally run the existing reproducibility and
failure-atomicity checks against the exact staged release payload. Record the
candidate commit, toolchain, command results, artifact digests, and any
environmental limitation. A passing source gate does not turn a local build
into a published package.

## Trust and limits

NQ is a scoped deterministic diagnostic engine and recursive evidence fabric.
It retains bounded evidence and returns a supported diagnostic disposition or a
typed refusal. It does not grant authorization, initiate actions, provide a
general remote-provider service, or own estate-wide recurrence; Nightshift
owns recurrence and the operational portrait.

The preview has explicit limits. Four compiled descriptors are covered:
`nq.host/v1` (one host snapshot), `nq.conformance/v1` (local fixture echo),
`nq.http_endpoint/v1` (one bounded controller-vantage HTTP response), and
`nq.systemd_unit/v1` (one target-local systemd snapshot). Each has its own exact
scope, vantage, size and freshness limits. This does not establish an aggregate
host or service-health claim. Classic NQ remains authoritative pending a separate switch;
the current host-portrait subjects are not complete; persistent helper resource
limits are bounded controls rather than a per-instance quota; and runtime
qualification does not inventory later dynamic/plugin/module loading. See
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and
[OPERATIONS.md](OPERATIONS.md) for the exact boundaries.
