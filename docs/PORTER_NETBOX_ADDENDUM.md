# Governing design addendum: Porter, NetBox, and system cuts

Status: implemented contract rebar and future live-delivery boundary. This
addendum does not claim a live Porter, NetBox, or AG integration in the current
nq-ng developer preview. It supplements the governing plan in
[`PLAN.md`](PLAN.md) without changing that plan's v1 operational-core scope or
authority model.

## Keep the two deployment specimens separate

The deployment program has two deliberately different specimens:

| Specimen | Claim it is intended to prove | What it does not need to prove |
|---|---|---|
| APT-in-QEMU v0 | Porter can deliver the exact nq-ng Debian package to a disposable Ubuntu Noble QEMU guest under a bounded plan, preserve installation receipts, and verify the shipped protocol and profile catalog. | Persistent application custody, upgrades, backups, production authority, or long-lived host reconciliation. |
| NetBox on `sushi-k` | Porter can deploy and maintain a persistent application on an admitted development host without losing state or widening effects. | The minimal APT mechanism or a general container orchestrator. |

NetBox must not expand the APT-in-QEMU specimen into a multi-service
application exercise. The QEMU specimen remains small enough to isolate the
governed-installation claim. NetBox is the separate persistent-state specimen.

## Specimen one: nq-ng Debian package in QEMU

The first specimen will use an nq-ng release `.deb` after that artifact has
been assembled and verified. The final package, its checksum, and its release
cohort metadata must live under the ignored workspace `dist/` directory.
`/tmp` may be used for disposable build scratch, but it is not the final
artifact bank and must not be cited as durable artifact custody.

Porter's plan binds the exact Ubuntu Noble base-image digest and VM
configuration, the disposable target class, the nq-ng package digest,
architecture and version, the fixed `dpkg` operation, the effects permitted by
the package contract, and the required checks. AG displays and decides those
exact plan bytes before Porter starts the guest or installs the package.

Porter then:

1. boots a clean admitted QEMU guest from the bound Noble image;
2. preflights architecture, available space, package-manager state, and the
   conflicting Debian `nq` package without mutation;
3. stages the exact `.deb` from `dist/` and verifies its digest in the guest;
4. invokes the bound `dpkg` installation without adding unplanned packages;
5. preserves bounded command output, package status and file identities, and
   the service accounts, directories, and unit state created by installation;
6. checks the installed binary build information, runs `nq protocol check`,
   and compares the compiled profile IDs/digests with the packaged descriptor
   catalog and manifest; and
7. records the result and discards the guest rather than promoting its state.

The package's non-mutation rules remain part of the postcondition: installation
must not initialize or migrate a database, overwrite configuration, start the
daemon, or purge prior data. A successful `dpkg` exit is actuator testimony,
not the verification result.

The claim earned in this repository is intentionally narrower: nq-ng can
validate and deterministically compile bounded descriptive system contracts,
and it can package its current evidence spine reproducibly. The QEMU specimen
is designed to earn the governed-installation claim; it has not been run here.
Neither claim establishes production readiness, production host admission,
general AG governance, authority, or a persistent service lifecycle. Those
require separate evidence and later specimens.

## Persistent target admission

Before the first NetBox deployment, Porter must consume a small bootstrap
target admission checked into the deployment source cohort:

```text
bootstrap-targets/sushi-k.yaml
```

That document must bind an exact host identity, the `persistent-dev` target
class, permitted privilege, stable storage locations, the backup requirement,
and explicit upgrade and teardown policies. Destructive replacement is denied
by default. The target contract is distinct from `disposable-qemu` and must
not inherit the disposable target's replacement assumptions.

That checked-in admission will break the bootstrap cycle. NetBox is not
required to provide the target record needed to install NetBox. Once NetBox is
operating, its corresponding device, interface, address, role, and target-class
records may be created there.

> NetBox describes the target. It does not authorize execution against it.

A later Porter plan may consume a bounded, identified NetBox inventory
snapshot. It must not treat a live query or an edited NetBox role as an
authority grant.

## Governed NetBox deployment plan

The approved plan binds at least the following facts:

```text
target: sushi-k
target_class: persistent-dev
application: netbox
native_executor: docker-compose

netbox_docker_commit: <exact commit>
compose_tree_digest: <digest>
container_images:
  netbox: <image digest>
  postgres: <image digest>
  redis: <image digest>

paths:
  application: /srv/netbox
  persistent_data: /srv/netbox-data
  backups: /srv/backups/netbox

network:
  listen_address: <explicit>
  port: 8000

allowed_effects:
  - create application directories
  - create named volumes or bound data directories
  - pull approved image digests
  - create/start NetBox containers
  - run NetBox database migrations

forbidden_effects:
  - delete existing volumes
  - replace unrelated containers
  - open additional ports
  - install unplanned host packages
  - silently advance image tags
```

AG displays and approves the exact serialized plan bytes. Any change to the
target, native artifact, image identity, path, network binding, effect set, or
postconditions produces different plan bytes and requires a new decision.

`netbox-docker` is the native deployment artifact. Porter governs that artifact
and invokes its normal ecosystem; it does not reimplement Compose or become a
container orchestrator.

## Porter execution contract

### Preflight without mutation

Porter checks Docker and Compose availability, target-directory existence and
ownership, free space, port conflicts, existing NetBox state, and conflicting
containers or volumes. An upgrade also requires a current database backup
under the admitted backup policy. A failed preflight performs no deployment
mutation.

### Bank the native artifact

The banked material includes:

- the `netbox-docker` tree at an exact commit;
- local override files and their hashes;
- the environment schema and bound non-secret configuration identities;
- resolved container image digests;
- the backup unit or script; and
- the exact output of `docker compose config`, produced with an identified
  Compose implementation.

The rendered Compose document, not merely its editable YAML sources, is the
native plan artifact bound to execution. Banking and receipts must not expose
secret values; the eventual implementation needs a separate explicit secret
custody and redaction contract.

### Apply through Compose

Within the admitted effect boundary, Porter invokes the native operations:

```text
docker compose pull
docker compose up -d
```

It does not issue destructive volume removal, replace unrelated containers,
install undeclared host packages, or widen the network bindings. Upgrade and
teardown are separate plan types with separately authorized effects; neither
is inferred from an install or maintenance grant.

### Preserve actuator receipts

Receipts retain staged-file hashes, resolved image digests, bounded Compose
command outputs, containers and volumes created or changed, migration output,
resulting health/status, and unexpected additions or restarts. Partial failure
and outcome-unknown states remain visible.

A zero Compose exit status and a Porter receipt are actuator testimony. They
do not establish the postconditions, change the published system cut, or
authorize a later operation.

### Verify independently

NQ, or a narrower admitted verifier where appropriate, checks that:

- exactly the expected containers are running with the approved image digests;
- the NetBox health endpoint or login page is reachable at the approved bind;
- PostgreSQL accepts the expected bounded check and migrations are current;
- persistent storage is mounted at the approved location; and
- the backup procedure produces a restorable-looking dump at the approved
  destination.

It also reports unexpected containers, ports, restarts, or storage placement.
Observation establishes bounded evidence, not authority and not automatic
declared-state mutation.

## The nq-ng joining model

NetBox, Porter, AG, and NQ each own a different plane:

```text
NetBox
  declared substrate facts
  devices, interfaces, addresses, sites, roles
          |
          v
nq-ng
  ratified system theory
  boundaries, membership, relationships,
  expected properties, observation obligations
          |
       ScopeCut
       /      \
      v        v
  Porter       NQ
  actuation    observation
       \        /
        v      v
      reconciliation
```

NetBox says what inventory objects exist. A published nq-ng cut says what
versioned system those objects constitute. The future `home-netbox` theory
should state that the web and worker components, PostgreSQL, and Redis form one
system, are hosted on `sushi-k`, expose the approved TCP endpoint, require
persistent database and backup capabilities, and have named observation and
actuation projections. Endpoint, storage, backup, and actuation-surface
properties are not present in the current contract.

NetBox contributes only a bounded source snapshot with digest and provenance.
In the future shared model, relationships that NetBox cannot establish—system
boundary, required versus incidental dependencies, operational observation
obligations, affected scope, and admitted actuation surface—will be authored
and ratified in nq-ng.

The future shared model preserves at least:

```text
SystemSpec
  -> TargetCut
  -> SystemScopeCut
  -> DependencyCut
  -> NQObservationProjection
  -> PorterActuationProjection
```

The projections derive from the same exact published cut but contain only the
facts needed by their consumers. Neither projection grants authority. AG can
bind a grant to the plan digest, target identity, published cut digest, system
boundary, permitted effects, and required postconditions:

```text
run plan P against target H
as a member of published system cut S
within boundary B
subject to postconditions O
```

This gives authorization and verification a common, versioned object without
making nq-ng an authority.

### Delivery order

The two Porter specimens do not need to wait for live shared-model integration.
They will use checked-in bootstrap target admissions and AG-bound plan bytes.
The current authority-free Porter projection type is structural rebar only;
no Porter or AG consumer contract is implemented here.

The contract compiler can derive an `NQObservationProjection` first and a
narrowing-only `PorterActuationProjection` from the same cut. Neither is yet
consumed by NQ or Porter. Stable target identity, system membership, dependency
relationships, source provenance, and the exact published cut are present now
so that live Porter integration does not require an ontology redesign. That
integration begins only with an explicit Porter/AG consumer contract.

## Ratification and anti-circularity

The operational workflow must enforce a human ratification boundary:

```text
new NetBox facts / Porter receipts / NQ findings
                  |
                  v
           proposed nq-ng draft
                  |
                  v
              ratification
                  |
                  v
          new governing ScopeCut
```

The following separations are invariants:

- NetBox records do not confer authority.
- nq-ng drafts, publications, cuts, and projections do not confer authority.
- Porter receipts do not mutate the governing cut.
- NQ evidence and findings do not automatically rewrite declared state.
- Draft edits invalidate only projections derived from that draft, not the
  currently published cut.
- AG binds authority to an exact published cut digest; it does not authorize
  “the current draft” or “whatever NetBox says now.”
- Reconciliation proposes a draft. Only ratification publishes a replacement
  cut.

The first deployment will therefore use the bootstrap target admission. After
NetBox is established, its declared facts can contribute to a proposed cut.
Only the ratification-bound cut becomes a stable input to future Porter and NQ
projections. The current local ratification record is self-consistent custody
metadata; it does not authenticate a human decision.

## Current implementation boundary

The developer preview described in
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) implements NQ's local
operational evidence spine and an isolated authority-free system-contract
compiler. `nq-system-contract` strictly validates bounded `SystemSpecV1`
documents, closes target/component/dependency/source membership, records an
exact schema-domain-separated proposal for display, requires a self-consistent
ratification record that cites that proposal digest, computes canonical
`ScopeCut` identity, and derives separately digested NQ and future Porter
projections. Publication also resolves every observation obligation against
the compiled NQ profile catalog, exact descriptor digest, complete coverage
vocabulary, capability vocabulary, and profile-owned binding rules. Mutation
creates a new cut; an old projection refuses a changed cut. The Porter shape
separates direct actuation scope from dependency-derived affected components
and their complete NQ verification obligations; it never contains commands,
effects, grants, or approval. A verification obligation requires fresh
testimony but does not prescribe a detector result: a valid failed report is
still testimony, not a satisfied health postcondition. Actual transition
postconditions require separately compiled detector/evaluation semantics in a
later consumer contract. The local ratifier identity and record digest are
custody assertions, not cryptographic identity or authority proofs.

Immutable artifact verification is deliberately distinct from current-profile
qualification. A historical cut can still prove its exact bytes, closure, and
ratification linkage after a profile version leaves a newer binary; it simply
cannot qualify for current NQ consumption there. Any future cut store must
retain the exact profile descriptor snapshots, fixtures, and a compatible
frozen verifier needed to interpret old semantics. Compiling one selected
system qualifies only that closed system's obligations, not unrelated draft
systems.

It does **not** currently implement:

- daemon storage, a CLI/API publication workflow, or a live NQ consumer for
  system cuts and projections;
- typed endpoint/exposure, persistent-storage, backup-capability, or
  descriptive actuation-surface properties in the cut, and no compiled
  expected detector/result semantics for transition postconditions;
- NetBox inventory import, snapshot custody, or reconciliation;
- Porter plan generation, banking, execution, or receipts;
- AG plan display, authorization, or cut-digest binding;
- the `sushi-k` bootstrap admission or a NetBox deployment; or
- any automatic feedback from observations or receipts into declared state.

The implemented rebar preserves stable target identity, exact source
provenance, ratification-bound versioned cuts, consumer-specific projections,
independent witness obligations, and strict separation from authority.
Live Porter/NetBox/AG integration is later work and must not be smuggled into
the v1 helper protocol, profile semantics, findings, or admission locks.
