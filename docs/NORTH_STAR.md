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

NQ is a recursive, vantage-indexed diagnostic composition system.

An NQ node takes custody of bounded observations and child dispositions,
validates them against exact compiled profiles, preserves their provenance and
state boundaries, and derives only conclusions supported by the evidence
actually available. A higher node may consume a lower node's disposition, but
the higher node must retain the child's claim surface, evidence dependencies,
state frontier, omissions, contradictions, and unresolved uncertainty.

The operator-facing objective is not merely to prove one narrow detector. The
first complete operational role must answer:

> What is going on with this host, from this declared vantage, and what can the
> system not currently establish?

Bounded implementation campaigns are delivery units. They do not redefine a
passing slice as a complete operational product.

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
- semantic projection, detector evaluation, and finding lifecycle;
- evidence history, coverage and coherence;
- recursive disposition and consumer-owned reliance; and
- the generic read model used by operator surfaces.

A witness owns bounded acquisition and native facts. It does not own NQ
standing, reliance, disposition, or action authority. A provider identity or
ordinary-looking endpoint does not bypass NQ admission.

The existing `nq.witness.v0` specification is a donor, not a second canonical
wire. Useful observation, error, coverage, and privilege concepts must be
reconciled into NQ-NG's existing helper and `EvidenceReport` path. Its
producer-declared `authoritative_for` standing is not promoted.

## Role-oriented deployment

NQ core does not assume that the node is a conventional host monitor. A parent
fabric node, a Kubernetes-oriented node, and an ordinary Linux host have
different jurisdictions and coverage obligations.

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

The first role-complete milestone is **Host Operational Portrait v1** for both
`sushi-k` and the Linode. Its exact required-capability manifest is ratified
only after the deployed-capability census in `SEQUENCING.md`; repository
fixtures alone cannot establish the live requirements.

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
- scheduling, a usable Monitor view, and notification delivery state.

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
nodes emit the standard recursive NQ disposition outward; the consuming node
applies its own reliance policy.

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

## Operator and coordination surfaces

`nq-monitor` is a presentation client over NQ's generic read model. It owns no
detector law. It must display the declared subject and vantage, evidence and
state frontiers, established conditions, contradictions, missing or stale
coverage, limitations, and safe next checks. A critical supported condition
must not coexist with a no-action headline, while unknown must not be promoted
to failure or health.

Routine local cadence remains within NQ's resident scheduler. Nightshift may
later coordinate deeper, remote, or multi-node diagnostic campaigns. It does
not own NQ disposition or turn diagnostic depth into repair authority.

Probabilistic interpretation may summarize or propose further declared
diagnostics, but it is never a source of direct observation and cannot mutate
the evidence it cites.

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
  agent assessment, and operator assertion; or
- release, deployment, public promotion, or authority switch without their
  separately earned gates.
