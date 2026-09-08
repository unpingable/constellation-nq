# Evidence-derived NQ-NG successor and cutover plan

## Active consumer-retirement prerequisite, 2026-09-08

The newly authorized bounded consumer migrations are distinct from this
historical host-cutover survey. Track the Codex repository-state prerequisite
and acceptance order in [REPOSITORY_STATE_PREREQUISITE.md](REPOSITORY_STATE_PREREQUISITE.md).
It does not reopen M2, switch fleet authority, or authorize a classic port.
Consumer retirement is incomplete while classic executable/build/test/fixture
generation remains required; named historical archives may remain.

## Selected model

Use **isolated parallel observation as qualification**, ending in a **clean
replacement**.

Do not:

- merge repositories;
- import the Classic database;
- run NQ-NG against Classic tables;
- create a permanent Classic compatibility service;
- treat the undeployed Classic rewrite as deployed state;
- share config/state/socket/service identities during parallel operation; or
- make NQ-NG authoritative merely because it emits similar-looking findings.

The intended end state supplied by the operator is:

```text
NQ-NG successor architecture
    + required Classic operational behavior
    + selected immutable donor tests/specimens
        -> functional-equivalence qualification
        -> explicit authority switch
        -> successor becomes the public NQ line
```

Moving the successor into the public repository is a later repository/promotion
operation. It follows functional equivalence; it is not how equivalence is
created.

## Why this model

### Clean database replacement

Classic and NQ-NG records do not have equal authority or identity:

- Classic rows lack NQ-NG provider attempts, trusted provider identities,
  exact request context, profile-semantic admission, evaluator source closure,
  and durable intake acknowledgment.
- Assigning those fields during migration would create evidence that was not
  captured.
- NQ-NG already documents that an optional legacy-manifest digest is a
  historical link, not imported current standing.

A Classic backup/archive is therefore the honest preservation boundary.

### Parallel observation

NQ-NG needs comparison against real acquisition behavior without sharing
Classic state. Parallel observation can expose missing dimensions, different
freshness/refusal behavior, and operator gaps while Classic remains the
operational authority.

The comparison is between underlying observations and supported conclusions,
not finding IDs, severity labels, database rows, or generation numbers.

### No permanent compatibility producer

A Classic-side exporter is not selected. The current evidence does not show a
required live artifact that can be exported without turning Classic's private
database/runtime into a permanent API. A narrowly versioned exporter may be
reconsidered for one named immutable artifact only; it is not the default
cutover bridge.

## Gates

### G0 — deployed capability declaration

Before more parity implementation, recover and approve a bounded inventory of:

- per-host confirmation of the operator-reported
  `361c5cdfa49163c96b550e8a0f38165b49305994` / schema-64 identity;
- enabled collectors/checks and actual targets;
- thresholds and baseline ownership;
- notification transports and recipients;
- required Labelwatch, Driftwatch, storage, Docket, Continuity, and reliance
  workflows;
- durable evidence retention/access obligations;
- acceptable parallel-run and rollback windows; and
- the definition of “functionally equivalent.”

This local-only survey intentionally does not contact production. Unknowns stay
unknown.

Deliverable: a signed required-capability matrix that distinguishes
“currently exists,” “must survive cutover,” and “may retire.”

### G1 — successor candidate identity

Choose an exact descendant of the provider-intake implementation and give it a
new, unambiguous candidate version. `v0.1.0` cannot identify current code:

- the tag contains schema v3 and predates provider intake;
- the qualified provider artifact contains schema v4;
- both local package specimens currently say version `0.1.0` but have different
  bytes.

Run the repository-native source, protocol, profile, store, package,
reproducibility, and VM gates. Record adverse results; do not reuse the old tag
or mint a release during an implementation campaign.

### G2 — isolated qualification environment

Use a separate VM/host, or explicitly distinct:

- configuration root;
- database and state directory;
- admission history;
- helper runtime directory;
- Unix socket;
- systemd unit and service identities;
- console port; and
- backup/archive destination.

Classic and NQ-NG examples currently collide at `/etc/nq` and
`/var/lib/nq/nq.db`. Parallel operation with shared paths is forbidden.

Record hashes of Classic configuration/state before and after qualification to
prove that NQ-NG did not mutate them.

### G3 — implement required replacement verticals

For each G0-required capability:

1. define one bounded compiled profile version;
2. implement one bounded helper/provider path;
3. bind exact subject, scope, vantage, capabilities, observation time and
   coverage;
4. add profile-owned detectors or typed refusal where a conclusion is not
   supported;
5. publish through the existing atomic NQ-NG intake/store path;
6. render through generic DTOs;
7. add deterministic hostile and live bounded tests; and
8. prove that the feature is absent unless explicitly configured and admitted.

Suggested sequencing after G0, not pre-authorized work:

1. minimum host/filesystem coverage required for first useful operation;
2. notification replacement or explicit temporary manual alert coverage;
3. actually deployed storage/application profiles;
4. consumer reliance only for named live consumers;
5. external/static artifact access if archives alone are insufficient;
6. operator surface needed to explain the required results.

Do not add a pack registry, suite planner, all-collectors envelope, generic
plugin ABI, or Classic database adapter.

### G4 — semantic parallel qualification

Observe bounded identical targets independently. For every required capability:

- compare raw source facts and intervals;
- explain expected semantic differences;
- ensure stale, missing, partial, malformed and refused evidence cannot display
  as healthy;
- verify exact profile/helper/evaluator identities;
- prove restart/checkpoint behavior;
- verify that disabled profiles do not execute;
- verify no private Classic value enters product defaults;
- measure operator identification of subject, change, freshness, evidence,
  unknowns and safe next step;
- require a critical observed finding to prevent any no-action headline while
  retaining the existing anti-overclaim boundaries; and
- verify notification delivery or the explicit manual substitute.

Classic remains alert and operational authority during this window. NQ-NG is
qualification-only.

### G5 — Classic freeze point

At the approved cut time:

1. stop Classic collection cleanly;
2. record exact binary, unit, configuration and package identities;
3. take a verified SQLite backup including committed WAL state;
4. retain relevant logs and local evidence files;
5. create a content-digest manifest over the frozen material;
6. record last Classic observation and notification times; and
7. verify that the archive is readable with the retained Classic tooling.

The manifest may be referenced by NQ-NG initialization. Its digest establishes
which archive was named, not that Classic findings were admitted into NQ-NG.

### G6 — authority switch

1. initialize a fresh NQ-NG store;
2. admit exact qualified helpers/profiles;
3. perform an explicit current collection;
4. verify current freshness, coverage and notification/manual path;
5. obtain operator signoff on the exact candidate and configuration;
6. stop/disable Classic;
7. start the qualified NQ-NG service; and
8. record the authority-switch time and the historical boundary.

No NQ-NG “empty findings” state may be described as universal health.

### Upgrade lifecycle ownership

NQ-NG, not an external deployment folklore document, must own the supported
binary/schema upgrade sequence.

The Classic trial supplied a concrete failure mode: direct `cp` over a running
binary has now produced `ETXTBSY` on three occasions. It failed without
swapping bytes, and staging a sibling followed by rename succeeded. NQ-NG's
Debian path already embodies the safer contract:

- `prerm upgrade` stops `nqd.service`;
- it verifies the service is inactive before allowing package replacement;
- `dpkg` replaces package files instead of overwriting the running inode;
- `postinst` does not initialize, migrate or restart;
- `nq admin upgrade` performs the explicit backup-first schema step; and
- the operator explicitly verifies and starts the daemon.

Direct in-place copying to an installed executable is unsupported. A manual
artifact path, if one is retained, must stage a complete verified sibling tree
and activate it only after the service is inactive.

The remaining evidence gap is a true different-version package
upgrade/rollback in the VM, including version identity, pre-upgrade backup,
schema refusal/migration, helper admission drift/rotation, manifest validation,
explicit restart and rollback. Reinstalling identical `0.1.0` bytes is not
that test.

### G7 — rollback and retirement

Rollback means restoring the preserved Classic binary/config/database and
restarting Classic. NQ-NG observations cannot be backported as Classic
observations; any NQ-NG-only interval must be disclosed.

Retire Classic only after:

- the qualification window passes;
- freeze/archive verification passes;
- required profiles and alerts pass;
- backup/restore and rollback drills pass;
- operator signoff passes;
- the rollback window expires; and
- the public-repository transition has its own reviewed history/package plan.

## Data policy

### Retain

- exact Classic database plus WAL-consistent backup;
- exact Classic binary, package, unit and config;
- immutable external witness packet sets and manifests;
- relevant action/reliance receipts;
- qualification comparison results;
- explicit first/last observation and authority-switch times.

### Do not migrate as current NQ-NG state

- Classic findings, generations, detector rows, notification status,
  coordination state or mutable current pointers;
- inferred provider identity;
- inferred profile admission;
- inferred evaluator identity/source closure;
- Classic “healthy” or resolved status;
- static external projections as runtime observations.

### Optional bounded import later

Only immutable historical artifacts with:

- a new versioned import schema;
- source commit/path/digest/license;
- exact original bytes;
- transformation code identity;
- semantic-loss/unknown fields;
- non-current historical classification; and
- typed unsupported/refusal behavior.

## Public repository transition

Once functional equivalence is earned, choose the repository-history strategy
separately. The product line should expose NQ-NG architecture and history
honestly; it should not copy the Classic `.git` database, hide the lineage
behind a squashed “refactor,” or retain Classic crates as permanent
compatibility ballast.

No remote exists for NQ-NG today, and this campaign may not configure one,
push, tag, publish, deploy, or rewrite the public repository.

## Survey implementation gate

No implementation slice is selected in this campaign.

The survey found plausible bounded work—most notably a separately versioned
filesystem-capacity profile/helper/detector or an authority-free Classic freeze
manifest verifier—but neither is yet the uniquely justified cutover blocker:

- the actual deployed capability set and notification/reliance obligations are
  unresolved;
- a broad host-resources port would risk changing `nq.host/v1` under an
  existing version;
- the Classic host implementation uses Classic DTOs and unsafe libc, while
  NQ-NG denies unsafe code outside its sandbox boundary;
- a freeze manifest needs an approved retained-asset contract; and
- current NQ-NG package identity/versioning is itself a promotion gate.

The later `ETXTBSY` evidence does not justify inventing another installer:
NQ-NG's Debian hooks already stop and verify inactivity before package
replacement, and the release-verifier suite exercises those refusal paths. The
missing proof requires two honestly distinct package versions and a VM
upgrade/rollback run. Fabricating that with two packages both called `0.1.0`
would weaken, not strengthen, the evidence.

Inventing a slice now would optimize against an assumed deployment. The
authorized outcome is therefore the committed survey only. After G0, select
exactly one required NQ-NG-native vertical; if root filesystem capacity is in
the minimum, prefer a new `nq.filesystem/v1` profile over changing
`nq.host/v1`.
