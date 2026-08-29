# GRANITE-FENCE durable standalone NQ claim/fence prerequisite receipt

Campaign: `GRANITE-FENCE`

Slug: `durable-nq-claim-fence-prerequisite-v1`

Classification:
`QUALIFIED-PREREQUISITE-DURABLE-STANDALONE-NQ-CLAIM-FENCE-V1`

This result qualifies only a durable standalone NQ claim/fence interface. It
does not grant AG or NQ authority, run mechanics, create a Kubernetes object,
change a live route, or qualify the BEDROCK first-live-occurrence successor.

## Custody and lineage

* BEDROCK refusal predecessor:
  `5fc7cc8212eb182bba54a2c92b7b37bd44b0cf69`;
* retained canonical NQ source:
  `7c361a9b43c6eb25645dcde5fa5222ae5a70ac28`;
* implementation commit:
  `a73edb188ac4d9746a720432f5b9cfc3b9110e6e`;
* branch:
  `campaign/granite-fence-durable-nq-claim-fence-prerequisite-v1`;
* implementation crate: `crates/nq-standalone-claim-fence`.

## Qualified law

One canonical closed claim request binds a fresh occurrence identity, exact
coordination domain, qualified mechanics digest, upstream authorization
receipt digest, runtime identity digest, and fresh claim nonce. The
authorization receipt is immutable identity input only; this interface does
not interpret it as authority.

The private SQLite store serializes concurrent writers with an immediate
transaction and retains one active claim per coordination domain. Claim and
transition identities use explicit domain-separated, length-framed canonical
JSON preimages. An exact replay is read-only and reported separately from a
new durable append.

The only accepted transition histories are:

```text
claimed -> fenced -> released -> terminal
claimed -> fenced -> released -> outcome_unknown -> terminal
```

Every transition binds the exact claim, occurrence, domain, mechanics,
evidence digest, transition kind, and globally one-use transition nonce.
Skipped edges, substituted identities, alternate transition histories, nonce
reuse, and concurrent duplicate writers refuse closed or return the exact
retained replay without a second release.

State custody requires a private nonsymlink parent and a private regular
SQLite pathname. Open-time pathname identity is rechecked. Durable mutations
use `BEGIN IMMEDIATE`, `synchronous=FULL`, exact affected-row cardinality, and
append-only transition events.

The interface is standalone: it is not coupled to a recurring tick and has no
mechanics runner. RIVER-CLERK's Docket process adapter remains a distinct
campaign and is not implemented or qualified by this record.

## Qualification

Commands completed at sealed implementation custody:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p nq-standalone-claim-fence --all-targets
cargo test --workspace
git diff --check
```

The focused crate result was 10 library cases and one real CLI integration
case passed, zero failed. The full workspace suite and documentation tests
passed with zero failures. Strict formatting, warnings-as-errors Clippy, and
diff checks passed.

Focused qualification covers exact claim replay and substitution refusal;
domain exclusivity and terminal successor admission; exact fence, release,
completion, outcome-unknown, and reconciliation order; alternate transition
history refusal; one-use release replay after terminal state; deterministic
concurrent release writers; restart durability; cross-transition nonce reuse;
state pathname and parent permission boundaries; closed-model unknown-field
refusal; and a real CLI claim, restart replay, fence, and malformed-request
empty-stdout case.

## Live-effect and teardown counts

AG authorizations, NQ authority objects, live NQ claims, live NQ fences, live
NQ releases, mechanics invocations, Docket attempts, Kubernetes workloads,
provider starts, VMs, listeners, live-route changes, recurrence attempts,
samples, and acquisitions: all zero.

All exercised state was campaign-owned local test-fixture state and was
removed by the test harness. No process, listener, VM, credential, secret,
temporary artifact, or teardown obligation remains. GLASSHOPPER and its live
route were not accessed.
