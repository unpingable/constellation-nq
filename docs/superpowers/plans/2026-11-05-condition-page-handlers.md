# Condition-bound Page Handlers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Admit the existing strict v2 condition envelope through currently configured compatible handlers under the same exact escalation policy.

**Architecture:** Share condition authorization before transport effects; project by configured transport. Preserve v1 history, PagerDuty behavior and local descriptor-bound custody.

**Tech Stack:** Existing Rust 1.94 workspace, serde_json, SQLite and native CLI tests; no dependencies or profile changes.

**Spec:** `docs/superpowers/specs/2026-11-05-condition-page-handlers-design.md`

## Global Constraints

- Do not modify `crates/nq-profiles`, `crates/nq-protocol`, Cargo.lock, toolchain or manifests.
- Tests and builds run only in the admitted disposable Builder checkout, at at most 4 CPU and 10 GiB, alongside the separately owned small Python lane.
- Keep raw build/test logs on Builder; retain selected counts, hashes, exits and source identities.
- No Target operations, external notifications, production routes or policy authority synthesized from an evaluator registry.

## Review Focus

- Unauthorized rule/component/class/route must refuse before replay, credentials, file or store effects.
- Missing policy and legacy non-page v2 must not become a working Page path.
- Local accepted events for one condition must not clear another condition's failure.
- Condition-bearing Slack/Discord must use their own projection and destination binding.
- Local/HTTPS v2 records must never acquire PagerDuty resubmission authority or misleading PagerDuty inspection metadata.

### Task 1: Shared v2 delivery and policy capability

**Files:** `crates/nq-app/src/{notification,escalation}.rs`, `crates/nq-app/tests/condition_page_delivery.rs`, `fixtures/notifications/condition-page-v2.json`, `crates/nq-store/src/lib.rs`, `docs/{ESCALATION-POLICY,NOTIFICATIONS}.md`.

**Interfaces:** Keep the native `notification submit`, `deliver-local`, `inspect`, `resubmit` and `policy --check-registry` commands and the v2 JSON shape. Existing handlers consume shared conditions; PagerDuty projection remains adapter-specific. A local v2 message is versioned explicitly. Existing v1 bytes and histories keep their contract.

- [ ] Write a native CLI counterexample: approved v2 trigger/resolve to local_file must pass full registry checking, retain exact conditions, sync one file per event and deduplicate the same input; unauthorized tuples have no effects.
- [ ] Transfer exact baseline plus tests to Builder and run the regression to observe the existing capability/schema refusal before implementation. Record source and test identities.
- [ ] Update shared policy capability, transport-selected rendering and exact local condition admission. Preserve missing/non-page refusal and PagerDuty-only resubmission.
- [ ] Verify condition-aware inspection and status through local retained wrappers; add regression for cross-condition unresolved failure preservation.
- [ ] Run focused CLI and transport tests on Builder, then full nq-app and notification-focused nq-store tests, format checks of the three touched app/test Rust files and package-scoped clippy under the admitted resource bounds. Preserve pre-existing formatting outside the change; verify exact profile/manifest/lock/toolchain source hashes before tests. Read every failure; keep historical results.
- [ ] Update canonical docs and literal common-envelope vectors; verify the semantic-identity closure is unchanged. Commit the coherent candidate and obtain independent whole-branch review before handoff. No PR or integration is implied.
