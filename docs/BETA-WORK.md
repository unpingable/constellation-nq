# constellation-nq beta work

Planning only, recorded 2026-10-01. Work below is not started by publication of this plan. Source, package, installation, runtime and composition standing remain separate.

## Current state

Start from [`dev/operator-beta`](https://github.com/unpingable/constellation-nq/tree/dev/operator-beta), canonical product reconciliation at `16e4c2f2c1fb4329260283476a39f57cfdd320e8`. Documentation commits after that point do not select a different product base or transfer predecessor qualification.

NQ 0.2.0 includes notification delivery/replay, saved checks, resource helpers, chained schema upgrades and inert packaging. Selected CLI bounded-input ordering is repaired. Cross-build historical store continuity remains unqualified; the supported procedure exports under the old build, quarantines, re-initializes and re-admits.

## Scope and exclusions

This plan routes current requirements and evidence needed for future bounded work. It does not resume alpha qualification, launch providers, mutate a deployment or implement product changes. Target-specific configuration and operational facts belong in program/application records; component documentation describes abstract interfaces only.

`agent_gov`, Classic NQ (`nq-classic`), retired monorepos, predecessor product lines and historical application implementations are historical/migration evidence only. They are not forward source donors, dependencies or instructions to restore removed APIs. Retired WLP compatibility remains excluded. Record a current requirement if old evidence suggests missing functionality; require an explicit owner decision before any revival.

## NQ-01: Resolve historical store continuity policy across builds

`COMPONENT_PRODUCT` · **Useful during beta; not gating** · Project: Blocked.

Problem: Schema-chain/report repairs ship in NQ 0.2.0. The supported interim rule is back up/export under the old build, quarantine, re-initialize and re-admit; historical continuity remains unqualified.

Intended outcome: Decide whether to add cross-build historical reopening or retain the documented no-continuity policy. Preserve the already-supported procedure and do not reopen resolved schema repairs.

Scope/exclusions: Limit changes to the named outcome; preserve existing semantic and authority boundaries.

Dependencies: Program release scope and current component contracts.

Acceptance/evidence: Chosen future continuity cases or maintained export/re-init/rollback evidence; existing issue records B-04/B-05 procedure acceptance; this is not a new beta blocker.

Owner decisions: Owner chooses historical semantic continuity versus explicit no-continuity policy.

Owning issue: [NQ-01](https://github.com/unpingable/constellation-nq/issues/12).

## NQ-02: Plan NQ runtime recovery and notification evidence

`RELEASE_ENGINEERING` · **Required for operator-beta** · Project: Ready.

Problem: NQ 0.2.0 already ships notification/replay, resource helpers and evaluator fixes; installed lifecycle evidence must remain generation-specific.

Intended outcome: Plan current package/runtime reopen, replay, backup/restore, exact-generation binding and secret-free delivery/replay evidence; preserve inert installation and explicit unknowns.

Scope/exclusions: Limit changes to the named outcome; preserve existing semantic and authority boundaries.

Dependencies: [PA-11](https://github.com/unpingable/unpingable-site/issues/12) and [PA-12](https://github.com/unpingable/unpingable-site/issues/13); Nightshift temporal composition and Monitor current support.

Acceptance/evidence: Normal replay/admission tests and separately admitted current-package recovery/notification checks; no live destinations or campaign controllers embedded.

Owner decisions: None beyond a bounded work order.

Owning issue: [NQ-02](https://github.com/unpingable/constellation-nq/issues/3).
