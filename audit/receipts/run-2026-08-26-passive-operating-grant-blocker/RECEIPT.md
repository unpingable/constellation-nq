# Finite operating-grant / transactional-activation campaign receipt

Recorded: 2026-08-26T23:17:02Z

Classification: **LIVE RENEWAL BLOCKED — GENERATION-BOUND WATCHER SEMANTICS REQUIRE A NEW SUCCESSION RULE**

## Repository custody

- repository: `nq-ng`
- branch: `campaign/finite-operating-grant`
- start SHA: `965f782cbd94f0281ff9035e8b1359575172d17f`
- fail-closed candidate commit: `3f38bd7e56850a48756a7c8017021600075d149f`
- parent standing: enabled bounded passive operational continuity qualified in
  practice; office dormant

## Qualified local candidate surface

- content-derived finite `nq.passive_load_operating_grant.v1`;
- exclusive H start/expiry;
- finite G/E child counts and aggregate sample/acquisition ceilings;
- ordinary G/E children retained as first-class exact records;
- append-only, idempotent child issuance;
- no H-to-H issuance surface;
- activation states `staging`, `validated`, `armed`, `closing`, `closed`;
- timer wakeup before Armed returns inert with zero attempts consumed;
- Armed tick revalidates H/G/E/admission/genesis/selector/context before calling
  the existing recurrence evaluator;
- closeout disarms under the same local ledger lock before service shutdown.

No claim of production or live qualification is made for this candidate.

## Exact blocker

The immutable passive selector inside `WatcherConfig` contains the exact
observer-generation configuration digest. Every successor G has a new digest
and must use a distinct sample store. Changing that digest changes the exact
watcher semantic digest.

The live pilot witnessed:

- G5 watcher semantic digest:
  `sha256:71f90576660b8f8866eb464fbca6da71d9bbcde114b34099be63288c55b36931`
- G6 watcher semantic digest:
  `sha256:d6875944c36d428d6af998415443db3aead74608a947964fc11693053abb2512`

The campaign's H contract correctly refuses E renewal when the watcher
semantic digest differs from H. Allowing it would require a new exact
generation-bound watcher succession/equivalence law or a provider-selector
redesign. Neither was authorized.

## Validation

- exact watcher-drift regression: passed;
- H lifecycle/expiry/retirement tests: passed;
- G/E child-accounting/idempotency/drift tests: passed;
- pre-Armed/Validated/Closed timer-inertness tests: passed;
- exact 15s/5m/6h/6h/24h arithmetic test: passed;
- passive operating-grant structural surface: passed;
- bounded recurrence structural surface: passed;
- NQ app/core Clippy with warnings denied: passed;
- full locked workspace/all-target suite, serialized to preserve the existing
  short process-boundary deadlines under host load: passed;
- formatting and `git diff --check`: passed.

## Host standing

No release bundle was built or uploaded. No Linode file, policy, grant,
configuration, service, timer, sample, acquisition, Nightshift cycle, or A4
record was changed. The inherited live office remains dormant and A4 remains
historically fenced.

## Required next decision

Govern the exact relationship among generation-bound passive watcher
identities. Manual finite G/E renewal remains the only qualified operational
path until that rule exists.
