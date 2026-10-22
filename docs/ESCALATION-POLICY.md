# Declared escalation policy

NQ separates condition identity, escalation authorization and delivery. An
operator can add `remediation-journal-critical`, or change an anchor's allowed
response classes, by installing policy bytes and their approval pin. No provider
adapter change is needed. This implements the bounded source repair for
constellation-nq #30 and cartography #95; it does not establish deployment.

## Document and approval

`nq.escalation_policy.v1` is a strict JSON document with `schema`, `anchors` and
`routes`. Each anchor declares `rule`, `components` and `response_classes`.
Each route declares `reference`, `anchors`, `response_classes` and `handler`.
Lists are explicit, nonempty and unique, except that an estate with no routes
can have an empty routes list. There are no wildcards, inherited permissions or
implicit promotion to page. Components and anchors are stable bounded tokens.
Schema markers and enum values must be strings. Response classes are the closed
enum `informational`, `attention`, `page`.

Handlers are a closed tagged enum. `slack` and `discord` declare `timeout_ms`
and `max_response_bytes`; `pagerduty` additionally declares `max_details_bytes`;
`local_file` declares `max_message_bytes`. A route's kind must match its NQ
route configuration. Configured network bounds must fit the policy ceilings.
Timeout ceilings are 100..60000 ms, response ceilings 1..32768 bytes, PagerDuty
details 1..4096 bytes, and local messages 1..4096 bytes. Slack/Discord response
bodies remain unread: their response ceiling preserves the existing setting,
not a new transfer-budget guarantee. Local bounds do not impose a sync deadline.
Unknown fields, schemas and enum variants refuse. The document is at most
128 KiB, with at most 256 anchors, 64 routes and 32 components per anchor.
These declaration bounds apply to installed documents; fallback route binding
preserves the existing configuration's route count.
Every route names existing anchors and exactly one configured route; configured
routes missing from an installed document also refuse.

For example, this fragment authorizes the new page on one route. A complete
document must also declare every other configured route and the anchors it
uses. Start from the effective policy export when preserving existing grants.

```json
{
  "schema": "nq.escalation_policy.v1",
  "anchors": [{"rule": "remediation-journal-critical", "components": ["service"], "response_classes": ["page"]}],
  "routes": [{"reference": "pagerduty-ops", "anchors": ["remediation-journal-critical"], "response_classes": ["page"], "handler": {"kind": "pagerduty", "timeout_ms": 10000, "max_response_bytes": 4096, "max_details_bytes": 4096}}]
}
```

Install a regular JSON file beside the operator-owned routes configuration,
readable by the NQ account and writable only by the operator. Add this top-level
table to that configuration (the digest below is a placeholder):

```toml
[escalation_policy]
path = "/etc/nq/escalation-policy.json"
sha256 = "sha256:<64 lowercase hex characters>"
```

The pin is SHA-256 of the exact file bytes, including whitespace and any final
newline. It is outside the document; a document cannot approve itself. NQ reads
one bounded regular-file descriptor, hashes those bytes, validates them and
uses the resulting in-memory snapshot. Symlinks, FIFOs and devices refuse.
The pin binds content, not its author. Protecting the operator configuration
and reviewing its changes remain the authorization boundary.

NQ checks policy during daemon startup, `config check/diff/apply`, and each
notification admission (submit, resubmit and deliver-local), before delivery
effects. A configured missing, malformed, oversized, mismatched or unsupported
document fails the command or daemon startup. It never falls back on error:
that could restore permissions intentionally removed by a newer policy.
Historical notification inspection remains independent of current policy.

With no `escalation_policy` table, the binary uses its bundled default document.
It retains exactly the former 17-anchor by six-component Cartesian permission
set, permitting all three classes at the anchor level. The default binds the
existing route configuration to handler declarations, allowing all classes on
Slack/Discord/local routes and only page on PagerDuty. Legacy payload bytes,
outcomes, errors for unlisted conditions, dedup keys and refusals are preserved.
The default grants no permission to `remediation-journal-critical`.

## Delivery boundary and inspection

`nq --config FILE --json notification policy` reports the effective document,
its digest and whether it came from the compiled default or an installed file.
It requires no database, secret resolution or network access. The installed
digest is the raw-file pin; the generated default digest hashes the canonical
effective document, including configured route bindings.

Authorization precedes provider dispatch. V2 conditions must name an authorized
anchor/component, an allowed anchor class and a route explicitly carrying that
anchor and class. Policy denials are command errors before custody, as unknown
anchors were previously. PagerDuty's non-page or absent-class check remains the
retained `response_class_not_page` refusal before replay, keys or network; a
policy cannot weaken it. Severity never grants paging permission. Nightshift
replay, explicit network enablement, routing-key redaction, retained provider
failures and one-attempt custody remain in force.

Existing v1 messages have no condition and keep their operator/Nightshift
authorization; policy gates their route and class only. NQ does not infer an
anchor from prose or a policy ID. V2 remains PagerDuty's existing wire envelope;
other current handlers still accept v1 only. This repair does not add a shared
condition envelope to those handlers. A future handler must join the same
validated route/class/condition authorization path before rendering, key access
or I/O, declare its closed kind and bounded fields, and retain its own failure
semantics. There is no dynamic plugin loader or automatic fan-out.

## Estate and attention reconciliation

The operator reviews the policy with the managed definitions, installs it and
pins the same exact digest in a separate estate file entry, for example
`nq.labelwatch.escalation-policy`, alongside `attention.labelwatch.policy` and
`attention.phlogiston.policy`. Those existing entries pin attention's own
effective policy; their digests are not interchangeable with this document.
Reconciliation must compare the estate pin, NQ configuration pin and effective
`notification policy` digest. NQ does not fetch or mutate the estate registry.

Attention's current `NQ_V2_RULES`/`NQ_V2_COMPONENTS` mirror is not an independent
authority. Before deployment its page-capable rule/component/class tuples and
selected routes must be checked against the same installed document, using the
effective policy export. `notification policy --check-registry FILE` validates
a bounded `nq.escalation_registry.v1` JSON export with `anchors` in the same
shape as this document. Every exported tuple must be permitted by the policy;
the export must include all page-capable rules, including disabled ones. A
subset is allowed because NQ's legacy default has anchors no current evaluator
uses. Attention must generate that export from its registry rather than copy
another manually maintained list. Its consumer change and estate deployment
are separate work; this lane changes neither repository. Today's 18-rule
mirror must fail against the 17-rule default and pass only with an approved
document adding the new anchor. No check turns a notice into a page.

## Rollout, rollback and acceptance

Review and install the document, compute its exact digest, pin it in the routes
configuration and estate, run `config check` and `notification policy` plus the
attention registry check, then restart the affected daemon and submitting
units. There is no hot reload. Preserve cartography #51 routing: production
`operations`, `operations-discord`, `pagerduty-ops`; qualification
`attention-test`, `pagerduty-test`. The document must list only routes configured
for that NQ instance. It does not rename routes or activate a service.

Rollback restores the previous document and pin together and restarts. To
return to the compiled default, remove the document binding from configuration
and remove the installed document, then restart and reconcile the reported
default digest. Deleting a still-pinned file fails closed. Reconcile open
conditions before removing their authorization; rollback does not resolve or
resend an existing incident.

Acceptance covers every legacy 17-by-six combination and response-class
refusal, admitting the added remediation page only with a matching document,
unknown rule/component/class and route denials, malformed enums, duplicate
entries, missing pins, mismatch and size refusal before effects, effective CLI
inspection without a database, attention mirror compatibility, and unchanged
rendered bytes, redaction, deduplication, retries and retained history. Run
`cargo test -p nq-app` and then the workspace suite under `umask 022`.

Dedup semantics, provider behavior, incident lifecycle, new authority paths,
automatic activation and additional providers are out of scope.

## Deployment note

After owner acceptance and a separately authorized NQ binary release, use the
existing verified deb procedure for labelwatch-host: verify package checksums,
stop the affected services, install the deb, install and reconcile the approved
document and pins, re-rotate ops-watcher admissions for the changed evaluator
bytes, re-enroll host-posture against those bytes, run the existing checks and
explicitly restart. The profile-identity closure is unchanged, so this repair
does not require a store rollover. Package installation remains inert. This
lane builds and stages no package and performs no host operation.
