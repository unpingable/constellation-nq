# Constellation NQ public-preview release guide

## Release pin

The frozen public source tag `constellation-public-source-20260912` resolves to
`f6b734db2e97ed4ca0c568ec9fccf5223fdecb40`. The retained synthetic-cache
result profile is a later local release candidate at
`23d9a1962136bc976c33e014ac0439377198c643`; a successor pin and tag must be
recorded after its final gate. Do not move the frozen public tag.

The earlier source candidate `e0151d0c090be7ce56e00f7d293440dbe43bf4a4`
and its Nightshift admission repair are historical inputs to the frozen public
pin, not the current release target. Do not move `constellation-public-source-20260912`
or `v0.1.0`, force-push, or rewrite history.

This is a source-only developer preview; it supplies no binary package or
installation artifact. Publication does not authorize a
production deployment, classic-NQ authority transfer, or a claim of complete
host coverage.

## Source preview

Use the public repository at `https://github.com/unpingable/constellation-nq.git`
and a clean checkout at the verified release pin with Rust 1.94. Source builds
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

The successor candidate has five compiled descriptors:
`nq.host/v1` (one host snapshot), `nq.conformance/v1` (local fixture echo),
`nq.http_endpoint/v1` (one bounded controller-vantage HTTP response), and
`nq.systemd_unit/v1` (one target-local systemd snapshot), and
`nq.synthetic_cache_executor_result/v1` (one exact past Docket-bound cache
attempt). The fifth profile remains a candidate until its helper, diagnostic
history, consumer pins, and release gate are verified; its presence in source
does not claim that workflow is already qualified. Each profile has its own exact
scope, vantage, size and freshness limits. This does not establish an aggregate
host or service-health claim. Classic NQ remains authoritative pending a separate switch;
the current host-portrait subjects are not complete; persistent helper resource
limits are bounded controls rather than a per-instance quota; and runtime
qualification does not inventory later dynamic/plugin/module loading. See
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and
[OPERATIONS.md](OPERATIONS.md) for the exact boundaries.
