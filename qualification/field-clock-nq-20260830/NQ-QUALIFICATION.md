# FIELD-CLOCK NQ qualification

- Campaign: `FIELD-CLOCK`
- Canonical slug: `monitor-nq-nightshift-operational-evidence-spine-v1`
- Repository: `github-unpingable:unpingable/nq-ng.git`
- Starting head: `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`
- Qualified subject: `feaded2c31ff93c99638409c093502ee9564335b`
- Branch: `campaign/field-clock-monitor-nq-nightshift-operational-evidence-spine-v1-20260829`
- Packet: `sha256:1df7f47bb3ea70d0f987e756f34aaa62f7187a659ef0bcc8d7c8aa2e645431fc`
- Exact Monitor result dependency: `0569a7dcfdcd500c118fd209d5676bb902d089b3` (`SOLE-LOCAL`; publication reviewer refusal retained)
- Independent classification: `QUALIFIED`

## Exact claims qualified

NQ reopens the exact closed Monitor record, strict Ed25519 signature, producer
and subject identities, acquisition/lineage/coverage structure, exact payload
bytes, producer time, and separate receiver custody time. A closed profile
then emits input-local claim support, cannot-testify statements, and refusals.
Incompatible exact values remain a contradiction relating two retained inputs.

The implementation is additive beside diagnostic execution V2. It does not
change the frozen V2 schema, corpus, refusal law, or supported-version dispatch.
It has no aggregate disposition.

The temporal handoff freezes exact supported claim IDs. A Nightshift consumer
may retain a subset but is refused if it adds a claim. NQ establishes neither
currentness nor remediation, authority, or target effect.

## Commands

- `cargo fmt --all -- --check` — pass.
- `cargo test --locked --workspace --all-targets` — pass, no failure.
- `cargo test -p nq-core operational_qualification --lib` — 3 passed.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` — pass, no warning.
- `python3 diagnostic-contract-v2/verify_assets.py --asset-root diagnostic-contract-v2` — exact schema, manifest, and 16 canonical fixtures verified; manifest `sha256:706aab7a5a71472a5dda6f1514f1748b460c06d606df6af7620a66b6574053e8`.
- `bash scripts/check_operational_qualification_boundary.sh` — pass.
- `bash scripts/check_operational_qualification_boundary.sh --negative-control` — injected aggregate field detected.

## Qualification cases

- exact payload produces only profile-bounded claim support;
- payload, subject, and producer substitutions refuse;
- acquisition no-response produces cannot-testify and no world claim;
- unknown payload schema stays raw-only and cannot testify;
- contradictory exact values remain linked to both inputs;
- agent-authored and instrumented producers use identical claim law;
- Nightshift claim-set widening refuses;
- closed Monitor lineage, timestamp, coverage, subject, and authority laws are
  independently reopened by NQ;
- diagnostic execution V2 assets remain exact.

## Custody and limitations

No listener, service, timer, provider session, credential, secret, private key,
or target mutation was created. Test signing keys were deterministic in-memory
fixtures and are not operational secrets. Monitor remains sole-local because
the execution reviewer rejected its authorized branch publication; no indirect
publication was attempted. DISTANT-BELL may begin only from these exact local
FIELD-CLOCK subjects and must retain the limitation.

Successor base policy: exact NQ FIELD-CLOCK result-head ancestry plus exact
addressability of Monitor result `0569a7d...`; content equivalence alone does
not inherit either qualification.

