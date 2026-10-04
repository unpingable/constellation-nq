# Boot-bound systemd observation v3 and exact observation reads

`nq.systemd_unit/v3` is a new compiled profile, not a replacement of the current
v2 profile. It reuses the v2 closed systemd manager state vocabularies, subject
rules, exact manager acquisition, and required-active judgment. A report names
the boot in which its manager snapshot was acquired. It does not establish that
this boot remains current at a later consumer decision.

The stable logical subject is `systemd-unit:<machine_id>/<unit_name>`. The scope
is exactly `{ "schema": "nq.systemd_unit_scope.v3", "machine_id": "…",
"unit_name": "…" }`, with empty local vantage. No enrollment field pins the
boot: enrolled machine/unit identity survives a machine reboot. The observation
adds exactly `boot_id` to the v2 native unit payload. It must be a nonzero,
canonical lowercase UUID. Manager load/active/sub states and evidence basis
remain separate native fields; no consumer should parse summary prose.

The ordinary `nq-host-resource-helper` reads the bounded native Linux boot file
before and after the bounded system-manager query. Unavailable, malformed, or
changed identity produces respectively `boot_identity_unavailable`,
`boot_identity_malformed`, or `boot_identity_changed`. Manager failures keep their
owner codes. Failed acquisition is not a healthy observation and cannot be
shadowed by older success. The helper's existing outer request deadline bounds
execution; the manager query retains its existing explicit operation budget.
Two equal reads establish only this acquisition cut. A concurrent later reboot
requires a new consumer currentness comparison, not a stronger NQ assertion.

The detector retains NQ's existing polarity: loaded + active means the required
active condition is explicitly absent; other admitted manager states mean that
condition is present. Current report freshness remains the profile's inclusive
60-second NQ evaluation window. A reliance consumer may impose a stricter
boundary, such as Monitor's expiry at 60 seconds. Neither polarity nor freshness
establishes HTTP health, effect causation, standing, or execution authority.

## Exact query-only read

An operator may export an observation linked from a frozen detector result:

```sh
nq --config /path/to/nq.toml observations export --reference /path/to/reference.json
```

The reference is exactly the existing evidence fields `report_id`,
`report_sequence`, `report_digest`, `observation_ordinal`, and `observed_at`.
Unknown fields and duplicate JSON keys refuse; the reference file is bounded to
64 KiB. The ordinal is required, so a report-only claim cannot silently become an
observation. The command opens the ordinary store read-only and verifies the
recorded admission snapshot, canonical source report, digest, sequence, ordinal,
and the declared exact observation time relation before returning native bytes.
The response is bounded to
1 MiB. Missing, substituted, unbound, noncanonical, or oversized evidence refuses.

`nq.admitted-observation-export/v1` returns these fields:

- `schema`, exact supplied `evidence`, `reference_time_basis`, `instance_id`, and
  historical `received_at`;
- native protocol `profile` (version is a string), `binding`, `report_observed_at`,
  `report_status`, `backend`, and `used_capabilities`;
- the exact native `observation` including boot identity and raw manager states;
- `standing: "historical_custody_only"`.

Timestamp precision has two **named exact forms**, not a tolerance interval.
`native_observation_time` means the supplied reference equals the full native
observation DateTime. `evaluation_millisecond_projection` means it equals
exactly the millisecond projection already sealed by the ordinary frozen
evaluation carrier in `engine.rs::prepare_evaluations`. Equal forms choose the
native label. The existing index must equal the canonical millisecond string
of the native source observation. The response retains the full native timestamp
and the exact supplied reference unchanged. A different fractional value in
the same millisecond refuses; consumers validate the named relation explicitly.
This accommodates the current named evaluation consumer without mutating its
frozen carrier or discarding native source precision. It does not invent a new
freshness allowance.

Export is custody, not currentness. It does not invoke a helper, collect,
reevaluate, refresh a timestamp, grant effects, require a still-admitted watcher,
or alter a frozen `DetectorResult` or `EvaluationResultV1`. A live consumer must
join **all five** evidence fields to its evaluation and independently validate
profile digest, instance, stable subject/scope, provenance, age, and current boot
before present reliance. Historical retained evidence remains historical even
when the read occurs during a live campaign. Absence of a report or current
observation is not evidence of health.

## Shared vectors and qualification scope

The normative cross-component fixture is
[`observation-export-vectors.v1.json`](../operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json).
It contains the descriptor, native canonical-digest report, exact export shape,
and consumer cases for current state, old boot, expiry, altered subject/profile/
reference, malformed boot, future evidence, and sub-millisecond reference forms.
The fractional cases retain native source reports and cover exact native,
exact evaluation projection, changed fraction, and substituted time-basis label. NQ tests the positive native
report and descriptor; Monitor owns reliance outcomes and consumes the same
fixture bytes. Negative cases are deliberate substitutions, not valid admission
claims. Fixture backend version is an assertion of the fixture, not proof of a
running installed binary. Live qualification must retain actual binary identities.

The profile descriptor digest is
`sha256:25fbbdd320248701b79b3e5f6c3109667b6aa9388ed113678ee0e6ba3c04a853`.
A profile revision does not rewrite historical v2 receipts. HTTP v1 remains its
existing closed operator-beta scope; this change does not claim a generic HTTP
profile, restore retired M2 support, or add a remediation authority owner.

## Formalization consideration

Decision owner: the NQ lane implementer, subject to independent acceptance.
Starting source: `fd143a48268f0a8cdd33fb2854c2db5ed45966bc`; final source and test
result identities are recorded in the lane completion notice and build receipts.

Propositions: (1) stable enrollment identity does not imply current boot identity;
(2) equal boot reads bracket only an acquisition, not later reliance; (3) exact
historical export never creates currentness or effect authority; (4) each of the
five evidence coordinates is necessary for the linked read; (5) a new failed cut
cannot be replaced by an older healthy report. Counterexamples include reboot
after the second boot read, fresh timestamps on old-boot evidence, replaced
reference coordinates, missing payload boot, and a newer acquisition failure.
Focused tests and shared golden vectors establish these finite wire/boundary
properties; existing authenticated admission custody is reused rather than
reimplemented. No claim of atomic manager state across arbitrary reboot,
filesystem snapshot linearizability, generic health, or proof of effect causation
is made. A bounded consumer-currentness transition model is a useful future
formalization, owned with the component that grants present reliance.

The first black-box observation export exposed the index/native precision seam:
the admission index stores canonical milliseconds while the native helper report
retains nanoseconds. The current evaluation producer deliberately projects its
reference timestamp to milliseconds (`engine.rs` preparation), and the current
history validator matches that projection. This is a named lossy transformation,
not an evaluator-history defect. Its scope is one timestamp coordinate; source
digest, sequence, ordinal, and report identity remain exact. Formalization
consideration: the permitted relation is `r = t` or `r = millis(t)`, with the
export declaring which relation holds and preserving `t`. Practical shared
vectors plus actual black-box export establish this finite boundary; no claim
of lossless inversion from `millis(t)` is made. A fractional substitution distinct
from both forms is the retained negative control. Failed producer evidence and
successor checks remain separate immutable campaign receipts.
