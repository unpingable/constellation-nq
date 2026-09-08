# Operator-beta NQ-ng M1B qualification closeout

**Status:** `QUALIFIED_PUBLISHED`
**Accepted closeout:** `5ea0a4be9f7aed0fb7f31db730b2db834957129b`
**Run:** `operator-beta-m1b-run-012`
**Harness subject:** `dc5d602484a4556c465df6947e98d81dba0d314a`
**Scoped disposition:** `MECHANISM_CASES_COMPLETED_WITH_DECLARED_LIMITATIONS`

## Observed result

The authoritative archive remains at
`/var/tmp/constellation-operator-beta-m1b-run-012`; the harness's
`check-run` reopener and independent review both accepted that exact physical
path. [`RESULT.json`](/var/tmp/constellation-operator-beta-m1b-run-012/RESULT.json)
binds the 65-entry manifest. A byte-identical preservation copy exists under
`/data/git/.campaign-artifacts/.../run-012`, but it is not a relocated run
identity.

Observed evidence establishes the fixed two-VM mechanism journey: exact NQ-ng
and AG packages; independent pre/post/restart NQ observations; one AG-owned
successful attempt with exact receipt/evidence and query-only store-cut replay;
package continuity; changed boot identities; six watcher revocations; two
SQLite-integrity-checked evidence backups; guest exit; and host process/listener
absence. The closed
[`qualification-receipt.v1.json`](qualification-receipt.v1.json) preserves
these facts and their exact limits.
The artifact-dependent
[`check-operator-beta-m1b-closeout-v1.sh`](../../scripts/check-operator-beta-m1b-closeout-v1.sh)
gate is separate from the portable harness gate.

Signed upstream checksum custody is `NOT_QUALIFIED`. A Docket database
occurrence, AG authorization consumption, production, and deployment are
`NOT_RUN`. Aggregate postcondition is `NOT_RECORDED`. This is not a claim
of distributed exactly-once execution or general backup restore qualification.

## Engineering / Research / Product / Drift

**Observed — Engineering.** The bounded operator-beta path now performs and
reopens real NQ observation, AG effect custody, reinstall/restart continuity,
owner-store audit, and teardown. The evidence above and 37 harness qualification
cases support that improvement. Operating burden added: one fixed harness,
two local VMs, two exact packages, and retained archives; no daemon or general
orchestrator was added.

**Assessment — Research.** This is a useful composition and qualification of
established mechanisms, not presently a research contribution. It resolves the
practical uncertainty that NQ-ng and the accepted AG adapter can complete this
bounded lifecycle without collapsing historical effect into current support.

**Observed — Product.** An operator has now completed the formerly unexercised
M1B mechanism workflow and obtained a replayable terminal record. This enables
the operator-beta integration/release gate; it does not yet provide a public
installation or UI workflow.

**Assessment — Drift.** The work closed an existing M1B obligation. It exposed
and corrected bounded launch, permission, observation, restart, store-cut, and
teardown seams without creating a new subsystem. The next external showing is
closer because the NQ-ng/AG mechanism lane is now exercised. Defer production,
generic UI, signed-input policy resolution, and cross-ledger authorization
composition to their existing owners. Recommendation: **integrate/show** the
accepted result, then continue only release-blocking composition.

The next lawful transition is the main-loop branch-reconciliation checkpoint.
This closeout authorizes no deployment, production activation, or transfer of
its declared limitations.
