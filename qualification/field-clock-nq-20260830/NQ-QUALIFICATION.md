# FIELD-CLOCK NQ qualification

- Campaign: `FIELD-CLOCK`
- Canonical slug: `monitor-nq-nightshift-operational-evidence-spine-v1`
- Repository: `github-unpingable:unpingable/nq-ng.git`
- Starting head: `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`
- Qualified subject: `470b5c6b809f336a60d84d43fc83855bc0403f79`
- Branch: `campaign/field-clock-monitor-nq-nightshift-operational-evidence-spine-v1-20260829`
- Packet: `sha256:1df7f47bb3ea70d0f987e756f34aaa62f7187a659ef0bcc8d7c8aa2e645431fc`
- Exact Monitor result dependency: `b2d52fe34f146774cbf5601819982c267c7fb082` (`REMOTE-VERIFIED-EXACT`)
- Independent classification: `QUALIFIED`

This non-rewriting correction descends from rejected sole-local NQ result
`a61395bca9a73051f0a9149a4f29adfd31bd43e9`. That head remains historical
evidence but is not an admitted successor base.

## Exact claims qualified

NQ reopens the exact closed Monitor record, strict Ed25519 signature, exact
producer principal/key identity, subject family and versioned owner basis
contract, acquisition/lineage/exact-coverage structure, exact payload bytes,
producer time, and separate ordered receiver/evaluation times. A closed profile
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
- `cargo test -p nq-core operational_qualification --lib` — 5 passed.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` — pass, no warning.
- `python3 diagnostic-contract-v2/verify_assets.py --asset-root diagnostic-contract-v2` — exact schema, manifest, and 16 canonical fixtures verified; manifest `sha256:706aab7a5a71472a5dda6f1514f1748b460c06d606df6af7620a66b6574053e8`.
- `bash scripts/check_operational_qualification_boundary.sh` — pass.
- `bash scripts/check_operational_qualification_boundary.sh --negative-control` — injected aggregate field detected.

## Qualification cases

- exact payload produces only profile-bounded claim support;
- payload and subject substitutions refuse;
- another Ed25519 key using the same accepted producer principal label refuses;
- exact producer principal, principal digest, and public-key digest must all
  match one admitted profile identity;
- locator strings cannot populate typed subject bases; kind/basis mismatch and
  unsupported, including locator-derived, basis contracts refuse;
- incomplete or overlapping expected/observed/omitted coverage refuses;
- malformed/non-UTC and inverted acquisition/producer times refuse;
- receiver custody before acquisition completion and evaluation before
  receiver custody refuse;
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
fixtures and are not operational secrets. The exact corrected Monitor result
is remote verified. DISTANT-BELL may begin only after independent acceptance of
the exact corrected Monitor and NQ results.

Successor base policy: exact NQ FIELD-CLOCK result-head ancestry plus exact
addressability of remote-verified Monitor result `b2d52fe...`; content
equivalence alone does not inherit either qualification.
