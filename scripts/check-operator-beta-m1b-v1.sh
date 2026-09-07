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
  'REQUIRED_TERMINAL_PATHS'
  'systemd_current_condition'
  'http_current_condition'
  'self.check_runtime()'
)
if [[ ${NQ_M1B_INJECT_BOUNDARY_FAILURE:-0} == 1 ]]; then
  required+=("required-boundary-token-that-does-not-exist")
fi
for token in "${required[@]}"; do
  rg -F --quiet "$token" "$runner"
done

if rg -n 'shell[[:space:]]*=[[:space:]]*True' "$runner"; then
  echo "M1B runner must not use subprocess shell execution" >&2
  exit 1
fi

printf 'operator-beta M1B harness boundary: PASS\n'
