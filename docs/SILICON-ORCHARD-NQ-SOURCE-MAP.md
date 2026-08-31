# SILICON-ORCHARD NQ source map

Campaign: `SILICON-ORCHARD`
Track: `ecad-operational-qualification`
Canonical slug: `ecad-operational-golden-journey-v1`

This NQ owner slice qualifies exact Monitor testimony. It does not establish an
ECAD result, operational currentness, aggregate health, remediation, or
target-effect authority.

## Exact admitted owners

- FIELD-CLOCK Monitor result: `b2d52fe34f146774cbf5601819982c267c7fb082`
- accepted SILICON Monitor fixture head:
  `bb75c4325f903f2c544e9758b5ea8d30c8bbc773`
- accepted DISTANT-BELL result:
  `8a1adaae27a5da70398b445c152cd4e7548b0289`
- exact Monitor fixture bundle:
  `sha256:fa51387ed569064281f63576e46de44628e2833bfbec2955fc7d990209ae173f`
- immutable NQ claim deck:
  `sha256:7f9ba67910df6962e4e02cb2e1fa75562a59889e16cef3c9133c90aa090cea0d`

The earlier local NQ head
`019cc169e2204b901c8777a8cb552d6a994f1a67` remains an immutable historical
predecessor; this correction does not rewrite it.

## Owner surfaces

- `crates/nq-core/src/ecad_qualification.rs`: exact profile, immutable deck,
  retained input/custody validation, qualification recomputation, and
  evidence-eligibility classification.
- `crates/nq-core/src/operational_qualification.rs`: FIELD-compatible Monitor
  reopening and the shared domain-separated identity law.
- `crates/nq-core/tests/fixtures/silicon-orchard/monitor-bundle.v1.json`: exact
  accepted Monitor and DISTANT bytes.
- `operational-contract/schemas/nq.ecad-qualification-profile.v1.schema.json`:
  exact compiled profile.
- `operational-contract/schemas/nq.ecad-claim-deck.v1.schema.json`: exact 27
  claim/value deck.
- `crates/nq-core/tests/silicon_orchard_v2.rs`: positive journeys and direct
  substitution cases.
- `scripts/check_ecad_qualification_boundary.sh`: structural owner gate and
  deterministic negative control.

## Eligibility law

Evidence eligibility is computed only after NQ:

1. admits the exact accepted Monitor fixture head and raw bundle digest;
2. validates every typed/raw entry and its subject/producer provenance;
3. validates the exact DISTANT message, admission/custody receipts, duplicate
   convergence, retained inbox, lineage, three attempt records, and delivered
   record;
4. derives the selected input group and receiver custody from those exact
   retained bytes;
5. reruns `qualify_operational_observations` under the compiled SILICON
   profile and fixed qualification time;
6. requires full equality with the supplied qualification artifact; and
7. compares the selected input with the immutable 27-claim value deck.

Process exit is mechanics only. Unknown or failed testimony remains
cannot-testify or refused. Contradiction remains distinct. The checker grants
no authority and creates no aggregate classification.

