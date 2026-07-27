# NQ operational north star

Status: ratified product and architecture direction, 2026-07-27.

This record supersedes the 2026-07-26 operator direction that limited NQ-NG
to an experimental mechanism donor. It does not erase that decision or the
evidence produced under it. NQ-NG is now the selected successor development
line. Classic remains the operationally authoritative NQ until the replacement
gates in [`SEQUENCING.md`](SEQUENCING.md) are earned and an explicit authority
switch occurs.

This is a direction and acceptance record. It does not claim that the
capabilities described below are already implemented, released, deployed, or
publicly available. Current implementation boundaries remain recorded in
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

## Product objective

NQ is a scoped, bounded, recursive diagnostic fabric.

The stable product stack is:

```text
witnesses and providers
  acquire bounded observations
        ↓
one NQ diagnostic
  selects the evidence required by one bounded profile and subject
  checks custody, admission, coverage, and state applicability
  returns a diagnostic disposition or typed refusal
        ↓
Nightshift diagnostic operations
  owns recurrence, expiry, campaigns, and multi-diagnostic posture
        ↓
monitoring · alerting · operator portraits · reporting · proposed automation
        ↓
human or AG authorization
        ↓
Docket execution
```

Diagnostics are what monitoring is built on. Monitoring is the continuing
operational view over recurrent diagnostic obligations and results, not the
semantic substrate from which a diagnostic must be reconstructed.

Maude and other frontends render the typed NQ and Nightshift surfaces; they do
not acquire evidence or create diagnostic or operational law.

An NQ node takes custody of bounded observations and child dispositions,
validates them against one exact compiled profile, preserves their provenance
and state boundaries, and derives only the profile-local conclusion supported
by the evidence actually available. A parent NQ may compose child testimony
when that testimony is evidence for the same exact diagnostic question.
NQ-to-NQ recursion does not turn a higher NQ node into an open-ended
operational composer. A receiving node must retain the child's claim surface,
evidence dependencies, state frontier, omissions, contradictions, and
unresolved uncertainty.

The constellation-level objective is not merely to prove one narrow detector.
The first complete operational role must answer:

> What is going on with this host, from this declared vantage, and what can the
> system not currently establish?

Bounded implementation campaigns are delivery units. They do not redefine a
passing slice as a complete operational product.

## Operational product claim

The product is computer-assisted operations through deterministic diagnostics.
It is not primarily an SRE telemetry, dashboard, alert-expression, or query
product.

The primary operator question is:

> Something is wrong. What is actually established, what remains unknown, and
> which bounded observation would change the decision?

An operator portrait is for the person doing operations. It must support
situation assessment, uncertainty, decision prerequisites, and the next useful
diagnostic. A consumer status page, trend dashboard, or telemetry query surface
may be useful downstream, but none is the canonical operational view.

The underlying mix of native witnesses, Prometheus, remote providers, and child
NQ nodes must remain inspectable for provenance and failure analysis. It is not
the primary interface. The ordinary operator journey should begin from a
subject and operational question, invoke declared diagnostics, and receive a
Nightshift portrait whose conclusions factor through exact NQ dispositions and
refusals.

The useful product-category analogy is **electronic design automation for
operations**. EDA does not replace the engineer or grant a simulator
fabrication authority. It gives the engineer deterministic analyses, rule
checks, counterexamples, provenance, and inspectable intermediate artifacts
before a consequential action.

The diagnostic profile and declared operational model are the engineered
artifacts; the live system is the changing, partially observable subject on
the bench. Witnesses and providers are instruments and test fixtures. NQ is
the deterministic verification and analysis engine. Nightshift is the flow
orchestrator and operations workbench. Dispositions, refusals, contradictions,
and coverage records are inspectable check results. Docket performs separately
authorized execution.

The live subject's open-world character is not where the analogy fails. It is
why the tooling must return coverage-narrowed, state-incompatible,
contradictory, insufficient-projection, or refused results instead of
fabricating conformance. Those outcomes are the operational equivalents of an
unconstrained, indeterminate, unroutable, or failed verification result.

The constellation is therefore an engineering analysis environment for live
operational systems, not one universal health solver. Different diagnostic
questions may require different bounded calculi for attribution, grounding,
admissibility, reliance, realizability, or projection sufficiency. Like
distinct EDA analysis engines, each compiled diagnostic profile has its own
required premises, derivation, refusal conditions, and claim surface.

The shared NQ substrate supplies exact custody, identity, admission,
deterministic execution, evidence history, and typed results across those
profiles. It does not flatten their logics into a generic score or allow one
profile's conclusion to answer another profile's question.

Prior formal-calculus work is architectural lineage, not an operator or runtime
dependency. A reader need not inspect an external proof repository to
understand a profile's installed contract. No executable profile is described
as formally verified unless correspondence between the formal object and the
shipped implementation has separately been established.

Nightshift may report whether exact NQ dispositions and refusals satisfy the
declared prerequisites for an operational proposal, and it may propose a next
diagnostic or action. It does not re-evaluate the underlying evidence and
cannot authorize that action. Human or AG authorization and Docket execution
remain separate even when the operator interface presents the whole chain.

## Agent boundary

NQ completes its scoped deterministic diagnostic derivation before a
probabilistic model enters the path. An agent consumes exact NQ dispositions
and refusals plus Nightshift's declared campaign context; it is not the
diagnostic engine over raw metrics, dashboards, Kubernetes state, or shell
output.

Agent output must retain:

- the exact diagnostic inputs it cites;
- model, prompt or policy, and derivation identity;
- its scope, time, and stated uncertainty;
- separation from direct observation and deterministic derivation; and
- replayability against the same immutable diagnostic corpus.

An agent may summarize, rank hypotheses, explain disagreement, or propose a
deeper declared diagnostic. It may be wrong about operator intent or what
should happen next. Its prose cannot fill a missing evidence slot, erase a
refusal, overwrite an NQ result, become child NQ testimony, or authorize an
action.

The enforceable goal is not that an AI can never state something false. It is
that an agent interpretation cannot silently become diagnostic fact or
operational authority.

## Stable ownership boundaries

The following vocabulary is normative:

| Term | Owner and meaning |
|---|---|
| **Witness** | An independently installable acquisition product for one bounded domain. |
| **Helper** | A bounded local executable and transport implementation used by a witness. |
| **Provider** | The NQ-admitted runtime source and custody identity for one acquisition path. |
| **Profile** | NQ-owned compiled validation, projection, coverage, freshness, correlation, and detector semantics. |

NQ-NG owns:

- request, provider-attempt, and provider identity;
- exact raw custody and durable intake acknowledgment;
- protocol and compiled-profile admission or typed refusal;
- semantic projection and deterministic evaluation for one exact diagnostic
  profile, subject, scope, and vantage;
- diagnostic evidence and disposition history, including profile-local
  coverage, state applicability, contradiction, and coherence;
- recursive testimony admission, projection-limit preservation, and typed
  refusal;
- application of the consuming jurisdiction's exact declared reliance policy
  at each NQ evidence boundary, without producer-minted reliance; and
- a stable machine-facing read and export contract for individual diagnostic
  executions.

A witness owns bounded acquisition and native facts. It does not own NQ
standing, reliance, diagnostic disposition, operational posture, or action
authority. A provider identity or ordinary-looking endpoint does not bypass NQ
admission.

Nightshift owns recurrence and campaign policy for diagnostics, composition
across diagnostic profiles, subjects, vantages, and time, custody and
attribution of agent or human interpretation artifacts, and read-only
operational posture. Humans and agents remain the authors of their
interpretations; Nightshift does not make those interpretations true. It may
choose or propose the next declared diagnostic. It does not rewrite NQ
evidence, mint an NQ disposition, or authorize repair.

Operational acknowledgment, escalation, suppression, notification intent, and
remediation decisions do not belong to the NQ diagnostic finding lifecycle.
Delivery software may transport an exact intent and record attempts, but it
does not infer operational meaning from an ordinary-looking NQ result.

The existing `nq.witness.v0` specification is a donor, not a second canonical
wire. Useful observation, error, coverage, and privilege concepts must be
reconciled into NQ-NG's existing helper and `EvidenceReport` path. Its
producer-declared `authoritative_for` standing is not promoted.

## Role-oriented deployment

NQ core does not assume that the node serves a conventional host diagnostic
role. A parent fabric node, a Kubernetes-oriented node, and an ordinary Linux
host have different jurisdictions and coverage obligations.

Deployment therefore uses explicit role bundles:

- a core or fabric node may run with no local host acquisition;
- a host-role bundle installs core plus the complete ordinary-host witness
  set;
- future Kubernetes and other role bundles carry their own inventories,
  state identities, and coverage assumptions; and
- optional infrastructure, storage, application, and remote-vantage witnesses
  attach through the same NQ boundary.

The source and package boundaries remain independent even when a role bundle
installs them together. A small core is an implementation boundary, not an
excuse to make the normal host installation operationally empty.

## Host Operational Portrait

The first role-complete constellation milestone is **Host Operational Portrait
v1** for both `sushi-k` and the Linode. It is not an NQ-alone product claim. Its
exact required-capability manifest is ratified only after the
deployed-capability census in `SEQUENCING.md`; repository fixtures alone cannot
establish the live requirements.

The portrait must cover at least:

- observation currency, NQ self-observation, and expected coverage;
- host identity, boot epoch, kernel, uptime, and relevant time basis;
- CPU/load/pressure and memory/swap/pressure;
- in-scope filesystems, mounts, byte capacity, inode capacity, and read-only
  state;
- required services, containers, or process lifecycles and recent changes;
- local interfaces, routes, listeners, and explicitly bounded reachability;
- storage or device state where the declared host inventory requires it;
- important bounded logs and events;
- configured application progression and application-owned state testimony;
- contradictions, shared failure domains, missing evidence, and useful safe
  next checks; and
- governed recurrence and campaign state, an operational console view, and
  notification delivery state.

Completeness does not mean omniscience or a green score. Every required domain
must be present with separate acquisition/coverage and domain-condition state.
Current, partial, stale, refused, missing, unsupported, intentionally excluded,
not configured, condition-present, and explicitly absent outcomes must remain
distinguishable. An empty configuration, absent series, or silent witness does
not establish health.

## Witness ecosystem

The `nq-witness` repository is the home for authoring/conformance support and
selected reusable host, storage, network, and service witnesses. NQ-NG remains
the owner of the canonical runtime protocol and semantic border; the witness
repository must not create another evaluator, scheduler, database, decision
engine, or canonical report envelope.

Domain applications own their direct testimony:

- Labelwatch owns a private Labelwatch witness package and its native phase,
  progress, publication, database, and coverage facts;
- Driftwatch owns a private Driftwatch witness package and its native ingest,
  lag, reconnect, loss, queue, storage, export, and gate facts; and
- later application witnesses follow the same ownership rule.

Application health endpoints, generic systemd/Docker observations, and remote
reachability are distinct perspectives. Agreement is composition, not
substitution. Labelwatch and Driftwatch commonly share host, disk, network,
proxy, and clock failure domains; their agreement is not automatically
independent corroboration. Missing or stale bridge data narrows coverage and
does not by itself establish failure of either application.

## Static profile cohorts

The profile registry remains static and compiled.

General semantics belong in the upstream compiled registry. Truly private or
domain-specific semantics use a private compiled cohort and an explicitly
identified private NQ build or node. Every cohort must seal:

- NQ core source and build identity;
- the complete compiled profile catalog and semantic identities;
- the exact evaluator artifact and complete detector catalog/suite semantic
  identities;
- compatible protocol and store versions;
- its qualification result;
- supported upgrade and rollback relationships; and
- lifecycle state such as candidate, admitted, retired, or promoted.

Private targets, credentials, and operational locators remain outside profile
identity and product defaults. A threshold, phase map, or other input that
changes verdict meaning must be bound into the detector semantic identity and
private cohort; it cannot remain mutable unbound configuration. Private cohort
nodes emit standard bounded NQ testimony outward; the receiving diagnostic
applies its own reliance policy and may derive only the conclusion authorized
by its exact profile.

Profiles that prove generally reusable may be promoted into the upstream
registry through an explicit campaign. A runtime plugin ABI is not authorized.
It may be reconsidered only after multiple independent cohorts demonstrate a
recurring need that static compilation cannot reasonably satisfy. An earned
extension mechanism need not involve dynamic code loading.

## Prometheus posture

Prometheus is a powerful, potentially lossy provider under qualification. It
is neither NQ's epistemic substrate nor a forbidden dependency.

Two directions are supported:

```text
existing exporter -> Prometheus -> qualified NQ provider

NQ-native witness -> rich NQ evidence -> optional metric projection -> Prometheus
```

An initial Prometheus provider is deliberately narrow: fixed endpoint
identity, compiled query templates, typed bounded parameters, exact API
response custody, explicit evaluation and sample times, retained warnings and
partial-result state, structurally checked dimensions, and independent
coverage inventory. Arbitrary PromQL and unadmitted recording-rule lineage do
not become NQ facts. Missing series means not observed unless an independent
closed-world coverage basis supports a stronger conclusion.

Prometheus crosses the same canonical boundary as every other acquisition
path:

```text
exact Prometheus API bytes as raw intake
    -> request-correlated candidate EvidenceReport
    -> compiled profile admission or refusal
    -> detector evaluation or refusal
```

Raw query results are not a second sample or detector lane. A local adapter may
use the admitted local-helper provider kind; a remotely submitting Prometheus
provider requires a separately defined and admitted provider subtype rather
than impersonating a local helper.

Prometheus may supply collection, discovery, storage, dashboards, and ordinary
trend queries. NQ remains responsible for whether a query projection retains
the dimensions required by the intended conclusion.

## Diagnostic, operational, and presentation surfaces

The required NQ surface is an instrument-grade view of one execution. It must
show the declared profile, subject, scope, and vantage; the evidence and state
frontiers; coverage and admissibility; the diagnostic disposition or refusal;
and the limitations of that result. A thin NQ inspector may render this
contract, but NQ does not own the unified operations dashboard.

The required Nightshift enterprise-console surface is the estate-level
operational read model. It must answer which diagnostic profiles exist, which
subjects and vantages they cover, when and why they run, their campaign or
recurrence state, and the last known diagnostic result. A last result must
retain its evaluation time, state applicability, coverage, and
current-reliance status; it must not masquerade as present truth merely because
it is the most recent row.

Nightshift may run diagnostics recurrently. This is governed temporal
orchestration rather than plain cron: a recurrence can depend on declared
profiles, expected check-ins, prior results, backoff, escalation, campaign
completion, and operator or agent intent. Acquisition products may maintain
their own signal-gathering cadence, but neither that cadence nor a missed run
creates an NQ conclusion.

Nightshift may compose multiple diagnostic dispositions and refusals into a
read-only operational posture, preserve disagreement across vantages, and
choose or propose the next declared diagnostic. Probabilistic interpretation
may summarize or propose further diagnostics, but it is never a source of
direct observation and cannot mutate the evidence it cites. Diagnostic depth,
operational posture, notification, authorization, and repair remain separate.

Maude or another frontend may present both the NQ execution-detail contract
and Nightshift's enterprise-console contract. Presentation must keep three
layers visible rather than flattening them:

1. acquired signals and their coverage;
2. the scoped NQ diagnostic disposition or refusal; and
3. Nightshift's operational posture, recurrence, and proposed next step.

A supported critical diagnostic condition must not coexist with a misleading
no-action presentation, while unknown must not be promoted to failure or
health. Frontend convenience never grants permission to reconstruct a stronger
claim than the underlying contract exported.

## Classic and cutover

Classic is a broad deployed product and donor corpus. NQ-NG is the cleaner but
narrower successor foundation. The selected transition remains:

```text
NQ-NG-native functional equivalence
    -> isolated parallel qualification
    -> clean replacement
    -> later public-repository transition
```

Classic acquisition algorithms, specimens, and operator failure evidence may
be adapted manually. Classic's schema-64 database, all-collectors runtime,
pack framework, dashboard implementation, and mixed ownership are not the
target architecture. The Classic database is archived at cutover and is not
migrated into NQ-NG current state.

## Explicit non-goals

This direction does not authorize:

- a generic telemetry lake or Prometheus replacement;
- arbitrary shell execution or a runtime semantic-plugin system;
- producer-owned standing, reliance, disposition, or repair authority;
- automatic conversion of `zab2nq` definitions into live observations or
  detectors;
- a Classic database adapter or permanent compatibility service;
- one universal host model for Kubernetes, fabric, and application nodes;
- collapsing direct observation, derived projection, child disposition,
  agent assessment, and operator assertion;
- open-ended cross-diagnostic operational composition inside NQ;
- a unified operations dashboard or notification-policy engine inside NQ;
- treating Nightshift scheduling, posture, or agent interpretation as NQ
  testimony; or
- release, deployment, public promotion, or authority switch without their
  separately earned gates.
