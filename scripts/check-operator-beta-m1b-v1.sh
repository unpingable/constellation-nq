#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd -P)
runner="$repo/qualification/operator-beta-m1b-v1/run_two_vm.py"
tests="$repo/qualification/operator-beta-m1b-v1/test_run_two_vm.py"
readme="$repo/qualification/operator-beta-m1b-v1/README.md"

test -f "$runner"
test -f "$tests"
test -f "$readme"
python3 -m py_compile "$runner" "$tests"
python3 -m unittest -v "$tests"
python3 "$runner" --help >/dev/null

required=(
  'UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED'
  'MECHANISM_CASES_COMPLETED_WITH_DECLARED_LIMITATIONS'
  'OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE'
  'gwr.executor-transport/v1-shaped testimony only'
  'signed_upstream_checksum": "NOT_QUALIFIED"'
  'docket_database_occurrence": "NOT_RUN"'
  'authorization_consumption": "NOT_RUN"'
  'production": "NOT_RUN"'
  'self.verify_producer()'
  'inspect-run'
  'reconcile-effect'
  'verify_effect_attempt_inputs'
  'REQUIRED_TERMINAL_PATHS'
  'systemd_current_condition'
  'http_current_condition'
  'self.check_runtime()'
  'db4bad1fba2b5ab512cc58356314228167b2f48e'
  '98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279'
  '668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068'
  'retain_and_audit_ag_store_cut'
  'verify_ag_store_cut'
  'ag-attempt-store-cut.sqlite'
  'ag-store-cut.json'
  'ag-store-audit-outcome-v1.json'
  'PRAGMA wal_checkpoint(TRUNCATE)'
  "if=virtio,file={guest.root / 'seed.iso'},format=raw,readonly=on"
)
if [[ ${NQ_M1B_INJECT_BOUNDARY_FAILURE:-0} == 1 ]]; then
  required+=("required-boundary-token-that-does-not-exist")
fi
for token in "${required[@]}"; do
  rg -F --quiet "$token" "$runner"
done
rg -F --quiet 'test_reconcile_refuses_fresh_run_attempt_for_same_semantic_work' "$tests"
rg -F --quiet 'test_producer_retains_locked_store_cut_and_uses_owner_audit' "$tests"
rg -F --quiet 'test_terminal_reopen_refuses_coherently_substituted_owner_outcome' "$tests"
rg -F --quiet 'test_terminal_reopen_refuses_coherently_substituted_store_cut' "$tests"
rg -F --quiet 'test_terminal_reopen_refuses_substituted_owner_executable' "$tests"
rg -F --quiet 'test_nodefaults_launch_uses_explicit_read_only_virtio_nocloud_drive' "$tests"

if rg -n 'shell[[:space:]]*=[[:space:]]*True' "$runner"; then
  echo "M1B runner must not use subprocess shell execution" >&2
  exit 1
fi

printf 'operator-beta M1B harness boundary: PASS\n'
