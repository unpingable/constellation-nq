# Finite passive operating grant and transactional activation V1

Standing: **QUALIFIED — LIVE OFFICE CLOSED AND DORMANT**

The passive office uses four separately auditable objects:

```text
deployment safety policy
        ↓
finite operating grant H
        ↓
ordinary finite observer generations G
        +
ordinary finite recurrence enrollments E

office activation manifest
        ↓
staging → validated → armed → closing → closed
```

H delegates a finite number of exact child issuances. It is not a sample,
admission, acquisition, recurrence slot, or Nightshift authority. H cannot
issue H, cannot extend itself, and cannot turn a semantic change into a
renewal. Child records remain ordinary finite G and E records.

## Exact watcher continuity

Watcher identities remain distinct across observer generations. H may consume
only its closed set of issued `nq.passive_watcher_succession.v1` relations.
Each directed relation compares the full predecessor and successor watcher and
provider custody records and permits only the closed delta documented in
`PASSIVE_WATCHER_SUCCESSION_V1.md`. The watcher admission boundary then creates
a fresh successor admission. The relation itself grants nothing.

## Child accounting and exhaustion

H records finite child counts, finite aggregate sample/acquisition ceilings,
exclusive start/expiry, an exact semantic envelope, and a maximum succession
edge count. Issuance is append-only, deterministic, and idempotent. A child
must fit both H and the current deployment policy.

Exhausting an issuance budget means that H cannot issue another child. It does
not retroactively revoke a child already issued under H. Retirement, expiry,
or a policy/context refusal prevents future runtime exposure. This distinction
is executable protocol law, not a deployment option.

V1 permits H to delegate execution of a pre-reviewed successor handoff for
each exact succession edge in its closed set. All G/E children, watcher
relations, admission IDs, genesis IDs, and activation manifests are
materialized before unattended operation. The handoff invokes the ordinary
admission and diagnostic owners; it cannot choose their outcomes. H never
issues H, recursively renews itself, or infers authority from a timer or
service restart. Every G, watcher, admission, relation, E, and handoff remains
independently inspectable.

The handoff protocol is specified in
`PASSIVE_LOAD_SUCCESSOR_HANDOFF_V1.md`.

## Transactional activation

An immutable activation manifest binds the exact H, G, watcher semantic digest,
admission, completed genesis acquisition, E, passive provider/store, capacity
context, and installed recurrence service path and byte digest.

`staging` and `validated` are deliberately inert. A recurrence wakeup in either
state returns `attempts_consumed = 0`, creates no occurrence, and contacts no
provider. Only the durable `armed` transition exposes E to the recurrence
evaluator. Readiness is recomputed at arm time; process presence and systemd
ordering are never readiness evidence.

Closeout appends `closing` and then `closed`, making wakeups inert before
mechanical services are stopped. Restart reconstructs the durable state and
cannot arm, renew, or extend anything.

Admission publication is part of deployment custody. `watcher admit-successor`
must run through the documented capability-bounded `nq:nq` maintenance unit.
Running it from a root shell does not add authority; it instead leaves a
mode-`0600` materialization that the unprivileged recurrence service cannot
read, so the provider remains untouched and the occurrence fails pre-provider.

> A higher-level operating grant reduces renewal toil by permitting a finite
> number of exact successor grants. It does not remove the child grants or make
> authority continuous by implication.

> The timer may wake a staged office. It cannot spend recurrence authority
> until the office is canonically armed.

> If operating semantics change, bounded renewal stops and human review
> resumes.

## Reviewed operating-profile candidate

Deterministic boundary qualification and the prior enabled pilot support this
deployment candidate:

```text
sampling cadence                 15 seconds
diagnostic acquisition cadence    5 minutes
one G                             6 hours / 1,440 samples maximum
one E                             6 hours / 72 acquisitions maximum
one H                            24 hours
H child ceilings                  4 G / 4 E / 3 directed succession edges
H aggregate ceilings              5,760 samples / 288 acquisitions
```

The half-open child windows are contiguous at renewal boundaries, so one exact
owner exists at equality. These are reviewed deployment defaults, not protocol
constants. The measured approximately 26 MiB/day combined growth leaves the
24-hour candidate comfortably inside the 10 GiB required-free-space guard;
archive custody is not required for this horizon.

The 24-hour charter is not enabled by qualification. Enabling an unattended
real charter remains a separate human decision. At close, the live H was
retired, its activation was closed, the observer and recurrence units were
inactive, and the timer was disabled.
