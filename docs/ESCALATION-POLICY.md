# Declared escalation policy

NQ separates condition identity, escalation authorization and delivery. An
operator can add `remediation-journal-critical`, or change an anchor's allowed
response classes, by installing policy bytes and their approval pin. No provider
adapter change is needed. This implements the bounded source repair for
constellation-nq #30 and cartography #95; it does not establish deployment.

## Scope of this repair

The declared policy removes the provider adapter's compiled anchor list as the
source of authorization. Anchor gating currently applies in effect only to
v2/PagerDuty: only v2 carries a condition and only PagerDuty accepts v2.
Slack, Discord and local delivery receive route and response-class gating.
This repair does not complete provider independence across all handlers.

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
Every route names existing anchors and exactly one configured route; configured
routes missing from an installed document also refuse.

For example, this fragment authorizes the new page on one route. A complete
document must also declare every other configured route and the anchors it
uses. Start from the packaged example or an installed policy export.

```json
{
  "schema": "nq.escalation_policy.v1",
  "anchors": [{"rule": "remediation-journal-critical", "components": ["service"], "response_classes": ["page"]}],
  "routes": [{"reference": "pagerduty-ops", "anchors": ["remediation-journal-critical"], "response_classes": ["page"], "handler": {"kind": "pagerduty", "timeout_ms": 10000, "max_response_bytes": 4096, "max_details_bytes": 4096}}]
}
```

Each deployed instance pins its own document. Shared source documents are
allowed, but each instance has its own configuration and estate pin, and its
document must cover exactly its configured routes. The operator-installed
configuration is authoritative for permitted identities and classes; there is
no compiled identity ceiling or fallback. Compiled code enforces schema,
bounds, protocol invariants and authorization checks.

The package ships today's 17 anchors × six components only as
`/usr/share/doc/nq-ng/examples/escalation-policy.example.json` (source:
`examples/escalation-policy.example.json`). It is never loaded automatically.
The example declares production routes `operations`, `operations-discord` and
`pagerduty-ops`; review its grants and adapt route references, handler bounds
and route membership to the selected instance before installing it. It does
not grant `remediation-journal-critical`.

Install the reviewed regular JSON file beside the operator-owned routes
configuration, readable by the NQ account and writable only by the operator:

```sh
sudo install -o root -g nq -m 0640 escalation-policy.reviewed.json /etc/nq/escalation-policy.json
sudo sha256sum /etc/nq/escalation-policy.json
```

For unchanged production routes, the reviewed file may be a copy of the
packaged example. Add this top-level table to that instance's configuration,
replacing the placeholder with `sha256:` followed by the exact hash above:

```toml
[escalation_policy]
path = "/etc/nq/escalation-policy.json"
sha256 = "sha256:<64 lowercase hex characters>"
```

Pin the same digest in that instance's estate entry, then verify before an
explicit restart:

```sh
sudo -u nq nq --config /etc/nq/nq.toml config check
sudo -u nq nq --config /etc/nq/nq.toml --json notification policy
sudo -u nq nq --config /etc/nq/nq.toml notification policy --check-registry registry.json --route pagerduty-ops
```

The pin is SHA-256 of the exact file bytes, including whitespace and any final
newline. It is outside the document; a document cannot approve itself. NQ reads
one bounded regular-file descriptor, hashes those bytes, validates them and
uses the resulting in-memory snapshot. Symlinks, FIFOs and devices refuse.
The pin binds content, not its author. Protecting the operator configuration
and reviewing its changes remain the authorization boundary.

NQ enforces policy in `config check/diff/apply`, effective-policy inspection,
and each notification admission (submit, resubmit and deliver-local), before
delivery effects. A configured missing, malformed, oversized, mismatched or
unsupported document refuses those operations. It never falls back on error:
that could restore permissions intentionally removed by a newer policy.
Daemon startup (including `--once`) validates and logs the result without
stopping observation. Doctor reports an `escalation_policy` finding without
failing solely because of that finding; its `healthy` result describes its
existing observation diagnostics. Initialization also reports policy status
without failing solely for a missing or invalid policy. Watcher inspection does
not load the policy. Policy path and digest validation belong to the notification
boundary too. The containing TOML must still have a valid configuration shape.
Historical notification inspection remains independent of current policy.

With no `escalation_policy` table, there is no policy document or digest.
V2 page intents receive a retained `escalation_policy_missing` refusal before
Nightshift replay, credential access or dispatch. The refusal uses the existing
one-attempt retention and redaction path; retaining its intent, payload and
refusal evidence does not admit it for delivery. Notice-class v1 intents
continue through the existing routes configuration, including Slack, Discord
and local inboxes. No code path can authorize a page from compiled identities.
`nqd`, `doctor` and `init` continue and report the missing document.
`config check` and `notification policy --check-registry` fail explicitly with
"missing escalation policy document". A still-pinned file that disappears is
an invalid installed policy and refuses notification admission, as before.

## Delivery boundary and inspection

`nq --config FILE --json notification policy` reports the installed document
and its digest, or `source: missing` with the missing-policy diagnostic and no
document or digest. It requires no database, secret resolution or network
access. The installed digest is SHA-256 of the document's exact file bytes.
The separate configuration digest covers the document binding and routes.

Authorization precedes provider dispatch. V2 conditions must name an authorized
anchor/component, an allowed anchor class and a route explicitly carrying that
anchor and class. Policy denials are command errors before custody, as unknown
anchors were previously. PagerDuty's non-page or absent-class check remains the
retained `response_class_not_page` refusal before replay, keys or network; a
policy cannot weaken it. Severity never grants paging permission. Nightshift
replay, explicit network enablement, routing-key redaction, retained provider
failures and one-attempt custody remain in force.

Existing v1 messages have no condition and keep their operator/Nightshift
authorization; an installed policy gates their route and class only. With no
policy, notices continue through the routes configuration; page authorization
requires an installed document. NQ does not infer an
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
The estate collector reconciles the estate pin, NQ configuration pin and
effective `notification policy` digest. The estate pin is not enforced by NQ:
NQ checks only its own configuration's pin and does not fetch or mutate the
estate registry.

Attention's current `NQ_V2_RULES`/`NQ_V2_COMPONENTS` mirror is not an independent
authority. Before deployment its page-capable rule/component/class tuples and
selected routes must be checked against the same installed document, using the
effective policy export. `notification policy --check-registry FILE` validates
a bounded `nq.escalation_registry.v1` JSON export with `anchors` in the same
shape as this document. Every exported tuple must be permitted by the policy.
Each page tuple must also have at least one configured handler that accepts
condition-bearing pages (currently PagerDuty) carrying its anchor and page
class. `--route REFERENCE` requires that delivery path on the named route.
An anchor-only grant with no deliverable page route fails this check, even
though the document can pass `config check`. The export must include all
page-capable rules, including disabled ones. A subset is allowed because the
example has anchors no current evaluator uses. Attention must generate that export from its registry rather than copy
another manually maintained list. Its consumer change and estate deployment
are separate work; this lane changes neither repository. Today's 18-rule
mirror must fail against the installed 17-rule example and pass only with an
approved document adding the new anchor. No check turns a notice into a page.

## Rollout, rollback and acceptance

Review and install the document, compute its exact digest, pin it in the routes
configuration and estate, run `config check` and `notification policy` plus the
attention registry check, then restart the affected daemon and submitting
units. There is no hot reload. Preserve cartography #51 routing: production
`operations`, `operations-discord`, `pagerduty-ops`; qualification
`attention-test`, `pagerduty-test`. The document must list only routes configured
for that NQ instance. It does not rename routes or activate a service.

Rollback restores the previous document and pin together and restarts. Before
or with any binary downgrade, remove `[escalation_policy]` from the
configuration: `NqConfig` uses `deny_unknown_fields`, so older binaries without
this binding (including `50ef404`) refuse the new table. Adding or
removing the table changes the configuration digest; reconcile that pin too.
Removing the document binding disables page authorization; it never restores
a compiled policy. Restore the previous document and pin together to restore
paging. Deleting a still-pinned file refuses notification admission;
observation continues. Reconcile open conditions before removing their
authorization; rollback does not resolve or resend an existing incident.

Acceptance covers every installed-example 17-by-six combination and
response-class refusal, admitting the added remediation page only with a
matching document, unknown rule/component/class and route denials, malformed
enums, duplicate entries, missing pins, mismatch and size refusal before
effects, CLI inspection without a database, attention mirror deliverability,
observation continuing with missing or broken policy, retained missing-policy
page refusals, notice delivery without a document, and unchanged rendered
bytes, redaction, deduplication, retries and retained history. Run
`cargo test -p nq-app` and then the workspace suite under `umask 022`.

Dedup semantics, provider behavior, incident lifecycle, new authority paths,
automatic activation and additional providers are out of scope.

## Deployment note

After owner acceptance and a separately authorized NQ binary release, follow
the verified labelwatch-host procedure recorded on 2026-10-19 and the NQ
operations runbook. First roll out the bounded ops-runtime side-install to the
seven ops watchers and verify it before installing the deb. Verify package
checksums, stop the affected services and submitting units, and install the
deb and, in the same operator-controlled step while units remain stopped,
install and pin the reviewed example as the production escalation document for
each instance. Adapt each document to exactly its configured routes; use
per-instance configuration and estate pins even when source bytes are shared.
This installation is an explicit operator action, not a deb maintainer-script
action. Re-rotate all seven ops watchers again after the deb because packaged
helper binaries drift; admissions pin the `nq` binary and helper digests.
Rotate the main instance's `fs-data-capacity` and phlogiston's
`svc-phlogiston-pds` admissions too. Bump host-posture `policy_generation` and
re-enroll with a new-evaluator initial artifact obtained via
`acquire-next-local`. Update the admission pins in `estate.json`, reconcile
the escalation document and per-instance configuration/estate pins,
run config, registry, doctor and collector checks, then explicitly restart the
affected services, including phlogiston's nqd. Each deployed instance pins its
own document, including route-free instances (with an empty routes list). Preserve the production and qualification
route split above. The profile-identity closure is unchanged: no store rollover.
Package installation remains inert. This lane builds and stages no package and
performs no host operation.

## Follow-up for full provider independence

A shared condition envelope for every handler would let anchor authorization
apply uniformly before rendering, key access or I/O. That requires a separate
wire-compatibility change for Slack, Discord and local delivery and tests of
each handler's refusal and retention behavior. The owner must decide whether
that work is required before cartography #95's acceptance item closes.

## Owner decisions (2026-10-22)

Each deployed instance has its own pin; shared sources are allowed. The
operator-installed configuration is authoritative. Compiled code enforces
schema, bounds, protocol invariants and authorization checks, without a
compiled list of permitted alert identities.
