#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
model="$root/crates/nq-app/src/operating.rs"
cli="$root/crates/nq-app/src/cli.rs"
service="$root/packaging/systemd/nq-recurring-office.service"

fail() {
  echo "passive-operating-grant-surface: $*" >&2
  exit 1
}

for schema in \
  nq.passive_load_operating_grant.v1 \
  nq.passive_load_child_grant_issuance.v1 \
  nq.passive_load_office_activation.v1; do
  rg -q "$schema" "$model" || fail "missing $schema"
done

rg -q 'max_observer_generations' "$model" || fail "finite G ceiling absent"
rg -q 'max_recurrence_enrollments' "$model" || fail "finite E ceiling absent"
rg -q 'max_aggregate_samples' "$model" || fail "aggregate sampling ceiling absent"
rg -q 'max_aggregate_acquisitions' "$model" || fail "aggregate acquisition ceiling absent"
rg -q 'office_not_canonically_armed' "$model" || fail "pre-Armed inert gate absent"
rg -q 'ActivationStateV1::Closed' "$model" || fail "terminal closeout state absent"
rg -q 'has_child_issuance' "$cli" || fail "activation does not bind ordinary issued G/E"
rg -q 'validate_activation_prerequisites' "$cli" || fail "transactional readiness validation absent"
grep -q 'operating tick' "$service" || fail "service bypasses transactional gate"

if rg -q 'InfiniteGrant|auto_renew_operating_grant|create_nightshift|NightshiftClient' "$model" "$service"; then
  fail "recursive/infinite authority or Nightshift coupling introduced"
fi
if rg -q -e 'diagnostics (execute|acquire-next)|collect ' "$service"; then
  fail "service manager directly invokes acquisition"
fi

echo "passive-operating-grant-surface: finite H, exact child custody, and transactional timer gate present"
