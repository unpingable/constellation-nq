# Constellation NQ public-preview release guide

Use the published [integration profiles](https://unpingable.com/constellation/integration.html)
for reproducible combinations: saved-check attention (alpha.2) and objective
saved-check read (alpha.3) both pin NQ
`e259852ed58b8c0bf65a629b3c494afba28d9ce9`. Their manifests record companion
components, toolchains and qualification. The cache pin below belongs to a
different, narrower retained-result profile; it is not the current source for
every capability. Component versions remain independent.

The saved-check/maintenance and notification additions are documented in
[Saved checks](SAVED_CHECKS.md) and [Notifications](NOTIFICATIONS.md). Build
those capabilities from the public commit containing these guides; the older
cache pin below does not contain them. Their source integration is recorded in
[SOURCE-PROJECTION.json](../SOURCE-PROJECTION.json). Public schema5 upgrades
explicitly to12, then through a separately verified backup to13; other
development schema lines are not silently imported. Current source includes
the [bounded local-successor profile](LOCAL_SUCCESSOR.md). Its component tests
do not by themselves qualify a new connected integration release.
These additions do not move a release tag or establish a complete consumer
monitoring migration. Local-file notification delivery has a qualified disposable
four-component example; live Slack/Discord delivery remains unverified.
The additive [sealed configuration interface](SEALED-CONFIGURATION.md) supports
the Nightshift saved-check caller on Linux. It does not change ordinary named
configuration handling. Qualification of the multi-component profiles above is
separate from that interface's component tests.

The [historical-read guide](HISTORICAL_READS.md) separately pins an archiver with
typed saved-check, maintenance and notification history validation. It was
exercised against a copy of the saved-check profile's populated store. The
related [operator-controlled rollover](ROLLOVER.md) was separately exercised for
an explicit schema-12 backup upgrade to 13, verified archive, eligibility scan,
and inactive successor preparation. Neither procedure creates a new suite
release, upgrades an active profile in place, activates the successor, provides
transparent cross-store lookup, or transfers classic-NQ authority.

## Release pin

The frozen public source tag `constellation-public-source-20260912` resolves to
`f6b734db2e97ed4ca0c568ec9fccf5223fdecb40` and remains unchanged. The retained
cache-result developer-preview runtime pin is
`ce0a04a175b6d87ac17395f08fd7bc70ddf1e7b3`. Its retained synthetic-cache-result
profile is documented in [SYNTHETIC_CACHE_RESULT.md](SYNTHETIC_CACHE_RESULT.md).
That profile retains one already settled Docket result; it is not a completed
consumer cache workflow or a new release tag.

The earlier source candidate `e0151d0c090be7ce56e00f7d293440dbe43bf4a4`
and its Nightshift admission repair are historical inputs to the frozen public
pin, not the current release target. The cache pin above is profile-specific;
it is not the latest source for saved checks or notifications. For the tested
local-inbox implementation use `1ef98c9c9934ea9dac481d3dcdc42fb7dd2bd073` and
the exact companion pins in its notification guide. Do not move `constellation-public-source-20260912`
or `v0.1.0`, force-push, or rewrite history.

This is a source-only developer preview; it supplies no binary package or
installation artifact. Publication does not authorize a
production deployment, classic-NQ authority transfer, or a claim of complete
host coverage.

## Source preview

Use the public repository at `https://github.com/unpingable/constellation-nq.git`
and a clean checkout at the current developer-preview pin with Rust 1.94. Source builds
are for developer preview and qualification; a completed package gate is
required before presenting a package as an installation artifact.

```sh
git clone https://github.com/unpingable/constellation-nq.git
cd constellation-nq
git checkout --detach ce0a04a175b6d87ac17395f08fd7bc70ddf1e7b3
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
attempt). The fifth profile's retained-result behavior has been qualified
separately; it does not establish a connected current-state or successor
workflow. Each profile has its own exact
scope, vantage, size and freshness limits. This does not establish an aggregate
host or service-health claim. Classic NQ remains authoritative pending a separate switch;
the current host-portrait subjects are not complete; persistent helper resource
limits are bounded controls rather than a per-instance quota; and runtime
qualification does not inventory later dynamic/plugin/module loading. See
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and
[OPERATIONS.md](OPERATIONS.md) for the exact boundaries.
