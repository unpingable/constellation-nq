#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd -P)
root="$repo/qualification/operator-beta-m1b-v1"
runner="$root/run_two_vm.py"
receipt="$root/qualification-receipt.v1.json"
schema="$root/qualification-receipt-v1.schema.json"
tests="$root/test_qualification_receipt.py"
closeout="$root/QUALIFICATION.md"
archive=/var/tmp/constellation-operator-beta-m1b-run-012

test -f "$runner"
test -f "$receipt"
test -f "$schema"
test -f "$tests"
test -f "$closeout"
python3 -m py_compile "$tests"
python3 -m json.tool "$receipt" >/dev/null
python3 -m json.tool "$schema" >/dev/null
python3 -m unittest -v "$tests"
python3 "$runner" check-run "$archive" >/dev/null

required=(
  'constellation.operator_beta.m1b_qualification/v1'
  'MECHANISM_CASES_COMPLETED_WITH_DECLARED_LIMITATIONS'
  'BYTE_IDENTICAL_NON_AUTHORITATIVE_COPY'
  'NOT_QUALIFIED'
  'NOT_RUN'
  'NOT_RECORDED'
  'NOT_CLAIMED'
  'Rawls:/root/second_watch_reaudit'
  'grants_deployment_authority'
  'authorizes_retry_or_resume'
  'Observed — Engineering.'
  'Assessment — Research.'
  'Observed — Product.'
  'Assessment — Drift.'
)
if [[ ${NQ_M1B_CLOSEOUT_INJECT_BOUNDARY_FAILURE:-0} == 1 ]]; then
  required+=(required-closeout-boundary-token-that-does-not-exist)
fi
for token in "${required[@]}"; do
  rg -F --quiet "$token" "$receipt" "$schema" "$tests" "$closeout"
done

echo "operator-beta M1B closeout: PASS"
