#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cli="$root/crates/nq-app/src/cli.rs"
engine="$root/crates/nq-core/src/engine.rs"

fail() {
  echo "repeat-diagnostic-surface: $*" >&2
  exit 1
}

rg -q 'AcquireNextLinodeOrigin' "$cli" || fail "explicit successor command missing"
rg -q 'ReplaySubstrateOrigin' "$cli" || fail "explicit replay command missing"
rg -q 'diagnostic_acquire_successor_with_substrate_origin' "$engine" || fail "V3 successor path missing"
rg -q 'nq\.deliberate_successor_single_admitted_report' "$engine" || fail "successor selection law missing"

replay_cli=$(sed -n '/^fn diagnostic_replay_substrate_origin(/,/^}/p' "$cli")
grep -q 'diagnostic_replay_substrate_origin' <<<"$replay_cli" || fail "replay body not found"
if grep -Eq 'origin_helper|diagnostic_acquire|diagnostic_execute|ProcessCommand|spawn' <<<"$replay_cli"; then
  fail "replay CLI acquired an origin or diagnostic provider surface"
fi

replay_engine=$(sed -n '/^    pub fn diagnostic_replay_substrate_origin(/,/^    }/p' "$engine")
grep -q 'reopen_diagnostic_artifact' <<<"$replay_engine" || fail "replay does not reopen exact custody"
if grep -Eq 'source|attest\(|run_capture|collect_internal|diagnostic_acquire' <<<"$replay_engine"; then
  fail "engine replay contains evidence-generation mechanics"
fi

successor_cli=$(sed -n '/^async fn diagnostic_acquire_next_linode_origin(/,/^}/p' "$cli")
if grep -Eqi 'timer|schedule|interval|loop' <<<"$successor_cli"; then
  fail "successor CLI contains recurrence or cadence mechanics"
fi

echo "repeat-diagnostic-surface: explicit one-shot successor and read-only replay remain separate"
