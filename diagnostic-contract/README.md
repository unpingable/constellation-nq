# NQ diagnostic-execution contract v1

This directory is the repository-native, language-neutral distribution surface
for `nq.diagnostic_execution.v1`. The Rust implementation in
`crates/nq-core/src/diagnostic_execution.rs` remains the executable semantic
validator; Rust source is not the wire distribution mechanism.

`manifest.json` closes and hashes the public schema and corpus. The three
fixtures under `fixtures/valid` are exact canonical artifacts accepted by the
v1 implementation. The two fixtures under `fixtures/hostile` are canonical,
self-identified candidate artifacts that the v1 semantic validator rejects
because an exported claim requires a distinction erased by its projection.
Their distinct raw evidence roots collapse to one projected evidence identity.

The checked-in copies must remain byte-identical to the frozen source corpus
under `audit/nq-nightshift-stage6-foundation/vectors`. `verify_assets.py`
enforces that equality in a source checkout, in addition to manifest hashes,
strict JSON decoding, the closed Draft 2020-12 schema, canonical bytes, and
artifact self-identities.

Release assembly publishes only this README, the manifest, schema, and corpus
under:

```text
share/nq/diagnostic-contract/
```

The outer release `share/nq/MANIFEST.sha256` commits to those installed bytes.
A cross-repository consumer must bind the outer release/package digest, this
asset manifest's digest, the exact NQ source/release identity, and the exact
artifact bytes independently. This inner manifest is intentionally
repository-agnostic and does not pretend to identify the package containing it.

Schema validity is structural conformance, not NQ admission, producer
authentication, consumer reliance, standing, authorization, or action. A
consumer must use the NQ-owned bounded result surface and must not reinterpret
raw observations or infer compatibility across contract versions.
