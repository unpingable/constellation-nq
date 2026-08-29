# AMBER-COMPASS reported-host binding successor

Campaign: `AMBER-COMPASS`
Slug: `reported-host-binding-successor-v1`
Classification time: `2026-08-29T17:39:12Z`
Canonical NQ base: `59abd3bcb2d0cc30657a659b3ebc57b981289d9f`

## Predecessor boundary

Classic LANTERNWAKE remains frozen at its published campaign head. This
successor does not copy Classic's puller, database identity, source
configuration, or collector-row architecture.

The reusable LANTERNWAKE law is that an exact expected source identity must be
compared with the identity in a decoded versioned observation envelope before
derived observations are admitted. A mismatch is a source-boundary refusal,
not a negative observation about the target.

## Canonical successor mapping

NQ-NG already implements a stricter native equivalent:

1. NQ constructs `HelperRequest.binding`, including the exact subject, scope,
   and vantage.
2. The helper response must echo that complete request binding.
3. A decoded report's `EvidenceReport.binding` must equal the NQ-owned request
   binding.
4. `interpret_response` classifies any mismatch as
   `ProtocolRejected/Validation/EchoMismatch` before profile admission.
5. Exact raw response bytes remain in provider-intake custody, but no report
   observations can enter profile evaluation or durable admitted-observation
   custody.

Unlike Classic's compatibility option, the NQ-NG provider route never omits
the expected subject binding. Blank subject identities are outside the typed
`SubjectId` contract. Adding `expected_reported_host` to successor config
would create a second, weaker identity architecture and is therefore not the
native port.

## Qualification

A focused provider-intake qualification case now constructs a structurally
valid response whose decoded report carries an alternate subject. It verifies
that the exact refusal field is `outcome.report.binding`, the interpretation
is `protocol_rejected`, and only rejected raw intake custody is produced.

Local qualification:

- `cargo test -p nq-core alternate_reported_subject_is_protocol_refused_before_report_admission --locked`: passed;
- `cargo fmt --check`: passed;
- `git diff --check`: passed.

## Classification and stop

Classification:
`native_identity_boundary_qualified_local_fixture_live_route_unqualified`.

No separate authorized live successor-NQ route was present. GLASSHOPPER was
not used. No service, deployment, default route, Classic NQ state, or
production authority changed. Live qualification requires a distinct
authorized route and a new campaign occurrence.
