# Finite operating-grant campaign — exact watcher succession blocker

Standing: **LIVE RENEWAL BLOCKED — GENERATION-BOUND WATCHER SEMANTICS REQUIRE A NEW SUCCESSION RULE**

The enabled pilot justified two narrow mechanisms:

1. a finite higher-level grant `H` that delegates only a bounded number of
   ordinary finite observer generations and recurrence enrollments; and
2. a transactional office activation gate that makes service-manager wakeups
   inert until exact durable prerequisites are canonically Armed.

The executable candidate implements both mechanisms fail-closed, but this
campaign stops before deployment because the existing passive provider
contract cannot satisfy the requested exact-watcher-sameness law across a real
observer-generation renewal.

## Authority model retained

```text
protocol invariants
        ↓
deployment safety policy
        ↓
finite operating grant H
        ↓
ordinary finite G and E children
```

`H` is content-addressed, has exclusive start/expiry, finite child counts, and
finite aggregate sample/acquisition ceilings. It cannot issue another `H`.
Child issuance is append-only and idempotent. Retirement and expiry fail
closed. Policy broadening cannot enlarge an existing `H`; a child must fit the
policy snapshot and the exact H bounds.

The candidate 24-hour arithmetic is internally exact:

```text
sampling                  15 seconds
one G                     6 hours / 1,440 sample slots
diagnostic recurrence      5 minutes
one E                     6 hours / 72 acquisition slots
one H                    24 hours / at most four G and four E
aggregate ceiling                  5,760 samples / 288 acquisitions
```

These values are not activated deployment policy by this campaign.

## Transactional activation retained

The activation ledger uses:

```text
staging → validated → armed → closing → closed
```

A service-manager wakeup consults this durable state first. In `staging`,
`validated`, `closing`, and `closed`, it returns an exact inert result with
zero recurrence attempts consumed. Only `armed` exposes the exact bound E,
and the CLI revalidates H, G, E, watcher admission, completed genesis,
provider selector, capacity context, and current deployment policy before
calling the existing recurrence evaluator.

Closeout appends `closing` before `closed`; the ledger lock serializes closeout
against ticks. Systemd is not an authority source.

> The timer may wake a staged office. It cannot spend recurrence authority
> until the office is canonically armed.

## Exact blocking fact

Every `nq.passive_load_observer_generation.v1` has:

* a new content-derived generation identity;
* a generation-dedicated sample store (successor reuse is refused); and
* immutable exact generation configuration bytes.

The NQ passive selector and `WatcherConfig` bind:

* `observer_config_digest` (the exact G identity);
* observer artifact/profile;
* producer key/issuer;
* capacity context; and
* a provider configuration selecting that generation's sample store.

`WatcherConfig` is itself semantically hashed. Therefore changing G changes
the passive selector's `observer_config_digest`, which changes the exact
watcher semantic digest. The executable regression
`passive_generation_rotation_changes_exact_watcher_semantics` pins this fact.

The real pilot independently witnessed the same result:

```text
G5 watcher semantic digest
  sha256:71f90576660b8f8866eb464fbca6da71d9bbcde114b34099be63288c55b36931

G6 watcher semantic digest
  sha256:d6875944c36d428d6af998415443db3aead74608a947964fc11693053abb2512
```

The prior pilot consequently admitted a distinct generation-bound watcher for
G5 and G6. That was not merely operator inconvenience.

## Why H cannot bridge this today

The requested H law binds one exact watcher semantic identity and refuses
semantic drift. A real `G1 → G2` transition necessarily changes the current
watcher digest under the existing selector contract. Therefore an H that
accepts G2/E2 would need one of these new rules:

1. define an exact succession/equivalence law relating multiple
   generation-bound watcher semantic identities;
2. redesign passive selector custody so one stable watcher can consume a
   closed sequence of generation stores without mutable-latest authority; or
3. predeclare every exact generation-bound watcher/admission/E child in H and
   establish that this enumerated succession preserves the governed watcher
   meaning.

None is already canonical. Choosing among them changes watcher succession and
equivalence semantics. The campaign instructions explicitly require stopping
at this point rather than inferring equivalence.

The current candidate therefore refuses an E child whose watcher semantic
digest differs from H. This is the correct fail-closed behavior.

## Deployment standing

No operating grant, activation, G, E, timer, or service was installed or
enabled on the Linode in this campaign. The previous office remains dormant.
A4 remains outside this boundary and unchanged.

No 24-hour H is ratified. Retain-all storage would remain sufficient at the
measured approximately 26 MiB/day, so archive custody is not the blocker.

## Required decision before continuation

The next campaign must govern **passive generation-bound watcher succession**:

> Does a closed sequence of exact generation-bound selector configurations
> represent successive custody epochs of one watcher semantic identity, and if
> so, what exact non-mutable rule relates them?

Until that question is answered, manual finite G/E renewal remains the
qualified path, and transactional activation may be evaluated only within one
generation-bound watcher epoch.

> A higher-level operating grant may reduce finite renewal toil. It may not
> invent equivalence between watcher semantics.
