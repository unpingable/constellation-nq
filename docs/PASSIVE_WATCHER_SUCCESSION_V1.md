# Passive watcher succession V1

`nq.passive_watcher_succession.v1` is an immutable, directed, content-derived
relation from one exact passive-load `WatcherConfig` to a distinct successor
`WatcherConfig`. It records bounded semantic continuity across an observer
generation and custody transition. It is not identity equivalence, watcher
admission, sampling authority, recurrence authority, acquisition authority, or
diagnostic standing.

## Field archaeology and the closed delta

The live G5/G6 watcher records and provider configurations showed three direct
watcher changes: the watcher `instance_id`, the sole `serve-stdio` provider
configuration argument, and `passive_host_load_sample.observer_config_digest`.
The exact provider configuration changed its path/digest, immutable sample-store
generation, and matching observer-generation digest. Earlier qualified rotation
also showed that `producer_key_id` and `producer_public_key_hex` may change
together under a bounded key-generation transition.

Those are the complete V1 delta set:

* distinct watcher instance;
* passive provider configuration path and byte digest;
* immutable sample-store generation;
* observer generation/configuration digest;
* optional paired signing-key ID and public-key bytes.

Full watcher/config/execution/admission digests change as derived identities.
They are recomputed results, not wildcard delta fields. The relation compares
both configurations field-by-field. Profile/evaluator, proposition, subject,
scope, vantage, capabilities, command executable/runtime, cadence/deadline,
resources, checkpoint policy, eligibility age, observer implementation,
producer issuer, and capacity context must be exactly equal. Coordination
semantics remain one stable deployment-declared passive-office domain; a new
domain string is not treated as a derived generation identity.

New `WatcherConfig` fields cause the exhaustive comparison code to require an
explicit review. A digest-shaped field is never accepted merely because its
name looks derived.

`nq watcher digest WATCHER` is the canonical read-only way to obtain the exact
semantic digest. Deployment scripts must not approximate canonical JSON or
infer the digest from field names.

## Admission and finite H

The finite operating grant H contains a closed set of exact relation IDs and an
exact maximum edge count. Edge issuance is append-only and must extend the
directed chain from H's initial watcher. It creates no admission. The existing
watcher-admission boundary may consume an issued relation by proving:

* the predecessor has its exact active admission;
* both current watcher configurations equal the relation snapshots;
* both provider configurations still equal their exact custody snapshots;
* the successor remains inside H's observer, capacity, eligibility, key, and
  deployment-policy envelope.

It then performs an ordinary fresh admission for the distinct successor. Every
successor G, watcher, admission, and E retains its own identity and custody.
Semantic drift refuses succession and returns to human review.

When an H begins after an already retained observer history, it may bind the
exact immediately preceding G identity. That identity is historical continuity
input only: it is not counted as an H child and imports no sampling authority.
The first issued G must name it exactly; omission or substitution refuses.

The recurrence deployment policy predeclares each exact watcher binding to the
same qualified passive coordination domain. H-authorized succession does not
change coordination meaning. A successor E is accepted only after its watcher
is reachable through the actually issued succession chain.

## Activation boundary

An activation manifest may name H's initial watcher or an exact reachable
successor. Mechanical timer wakeups remain inert in `staging` and `validated`:
they create no occurrence and consume no recurrence attempt. Only the durable
`armed` transition exposes the exact finite E. Closeout disarms the semantic
gate before service shutdown.

The manifest binds both the absolute service-unit path and the digest of its
exact installed bytes. Readiness recomputes that digest; a syntactically valid
digest without matching installed custody cannot arm the office.

Succession never touches the retired one-shot provider boundary or A4. It never
creates a sample, diagnostic acquisition, artifact, support occurrence, or
Nightshift cycle.
