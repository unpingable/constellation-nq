#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd -P)
runner="$repo/qualification/operator-beta-m1b-v1/run_two_vm.py"
tests="$repo/qualification/operator-beta-m1b-v1/test_run_two_vm.py"
readme="$repo/qualification/operator-beta-m1b-v1/README.md"
bookworm="$repo/qualification/operator-beta-m1b-v1/BOOKWORM-PACKAGE.md"
bookworm_builder="$repo/qualification/operator-beta-m1b-v1/build_bookworm_package.py"
bookworm_tests="$repo/qualification/operator-beta-m1b-v1/test_build_bookworm_package.py"

test -f "$runner"
test -f "$tests"
test -f "$readme"
test -f "$bookworm"
test -f "$bookworm_builder"
test -f "$bookworm_tests"
python3 -m py_compile "$runner" "$tests" "$bookworm_builder" "$bookworm_tests"
python3 -m unittest -v "$tests"
python3 -m unittest -v "$bookworm_tests"
python3 "$bookworm_builder" --help >/dev/null
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
  '0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636'
  'db4bad1fba2b5ab512cc58356314228167b2f48e'
  '98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279'
  '668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068'
  'retain_and_audit_ag_store_cut'
  'verify_ag_store_cut'
  'ag-attempt-store-cut.sqlite'
  'ag-store-cut.json'
  'ag-store-audit-outcome-v1.json'
  'PRAGMA wal_checkpoint(TRUNCATE)'
  'sudo test ! -s /var/lib/nq/operator-beta.sqlite-wal'
  'sudo test -f /var/lib/nq/operator-beta.sqlite'
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
rg -F --quiet 'test_helper_execution_uses_documented_transient_unit_boundary' "$tests"
rg -F --quiet 'test_package_continuity_checks_protected_store_as_owner' "$tests"
rg -F --quiet 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' "$runner"
rg -F --quiet 'AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' "$runner"
for token in \
  'REFUSED / NO_EFFECT_ATTEMPTED' \
  'sha256:fb7a58d0482a24e269ba85636ce46cb06aaaef3aea0e868154ed0ae7c18fa379' \
  'rust@sha256:365468470075493dc4583f47387001854321c5a8583ea9604b297e67f01c5a4f' \
  '0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636' \
  '8b0298cc690c2c662cbda5bd931380656775b1caa38aed4d7d8f2c517d384ebe' \
  'constellation.operator_beta.nq_bookworm_package_build.v1' \
  'bookworm-package-004' \
  'eff5c73963420fcf0a71bd3f379c2ce926f83e1e497006d857fa218cb6787174' \
  'fa9c00821969ce70f5cf2c53b09f2876e759063ceb3645dfdb220bdc1435a5cf' \
  'GLIBC_2.34'; do
  rg -F --quiet "$token" "$bookworm"
done
rg -F --quiet 'test_closed_receipt_refuses_identity_substitutions' "$bookworm_tests"
rg -F --quiet '"--network", "none"' "$bookworm_builder"
rg -F --quiet '"normalized_docker_argv": normalized_build_command()' "$bookworm_builder"
rg -F --quiet 'BUILD_USER = "1000:1000"' "$bookworm_builder"

if rg -n 'shell[[:space:]]*=[[:space:]]*True' "$runner"; then
  echo "M1B runner must not use subprocess shell execution" >&2
  exit 1
fi

printf 'operator-beta M1B harness boundary: PASS\n'
