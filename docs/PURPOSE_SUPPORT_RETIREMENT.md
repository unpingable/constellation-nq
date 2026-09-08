# Native diagnostic purpose support — scoped R4 candidate

`nq --config C diagnostics purpose-support --request R` opens the configured
store read-only, requalifies complete LOCAL admission/provenance history, and
reopens exact v2 diagnostic bytes. Imported custody is refused. Request JSON
binds artifact, consumer, purpose, exact subject/scope digest, claim, evaluation
time, artifact-age limit (1..900 seconds), source-currentness requirement and
up to 16 distinct supporting artifact identities. Duplicate/primary support
cannot satisfy an independent prerequisite. No arbitrary evidence file can
be promoted to local source authority through this command.

Two explicitly different roles exist:

* `historical_readonly`: supports consideration of an established retained
  claim under bounded artifact age. Source-world currentness remains explicitly
  NOT_ESTABLISHED. It is not a renamed current operational-health guarantee.
* `continue_observing`: current-source role; returns `cannot_testify` until a
  source/consumer clock-comparison contract is actually qualified. Current NQ
  engine histories explicitly disclose unqualified clocks. Replacing that
  disclosure with completion-time freshness is forbidden.

The continuity-gated consumer additionally requires separately identified
`continuity_rely_eligible` support for the exact same subject/scope. Mere
nonempty support or a favorable unrelated claim cannot satisfy it. The current
compiled registry has no such producer; missing support remains a residual
blocker, not evidence that continuity holds. Thus this increment replaces the
read-only modern adapter and establishes native historical consideration, but
does NOT claim full equivalence for the old current/continuity role.

Remaining concrete prerequisite: a native source-clock comparison/reliance
contract, then a compiled continuity qualification producing the exact named
claim from admitted continuity evidence and independent supporting occurrence.
Those must earn positive/refusal/unknown/stale/wrong-subject controls before the
current-role retirement gate closes. Source and resolver honesty remain an
environmental assumption; receipts are integrity-addressed, not authentication
of arbitrary caller-supplied data. AG authorization and Docket custody unchanged.

Qualification uses an actual native CollectionEngine diagnostic, locally
committed artifact and admission history, plus imported-custody negative control.
Fixture exports are generated mechanically from that real store test with
`NQ_PURPOSE_FIXTURE_OUTPUT`, then consumed by Nightshift's native request-bound
parser. No classic regeneration is needed; archived classic vectors remain
explicit historical projection regressions only.
