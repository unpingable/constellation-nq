#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
store="$root/crates/nq-store/src/recurrence.rs"
engine="$root/crates/nq-core/src/engine.rs"
cli="$root/crates/nq-app/src/cli.rs"
service="$root/packaging/systemd/nq-recurring-office.service"
timer="$root/packaging/systemd/nq-recurring-office.timer"

fail() {
  echo "bounded-recurrence-surface: $*" >&2
  exit 1
}

rg -q 'max_acquisition_occurrences' "$store" || fail "finite occurrence bound missing"
rg -q 'expires_at_unix_ms' "$store" || fail "exclusive enrollment expiry missing"
rg -q 'CoordinationDomainPolicyV1' "$store" || fail "coordination domain missing"
rg -q 'fencing_epoch' "$store" || fail "durable fencing epoch missing"
rg -q 'outcome_unknown' "$store" || fail "outcome-unknown domain fence missing"
rg -q 'deployment_policy_superseded' "$store" || fail "policy tightening does not fail closed"
rg -q 'commit_recurrence_provider_fence' "$engine" || fail "provider boundary lacks recurrence fence"
rg -q 'diagnostic_acquire_recurring_with_substrate_origin' "$engine" || fail "bounded recurrence engine path missing"
rg -q 'admission renewal is required before provider invocation' "$engine" \
  || fail "evaluator drift is not refused before the recurrence provider boundary"
rg -q 'RecurringCommand::Tick' "$cli" || fail "one-shot tick command missing"
rg -q 'RecurringCommand::Reconcile' "$cli" || fail "exact outcome-unknown reconciliation missing"
rg -q 'reconcile_recurrence_from_exact_custody' "$store" || fail "custody-only fence release missing"

if rg -q 'CronExpression|parse_cron|RRule|PriorityClass|PagerDuty|AlertManager' "$store" "$cli"; then
  fail "generic scheduling or alert surface introduced"
fi
tick=$(sed -n '/^fn recurring_tick(/,/^}/p' "$cli")
[ -n "$tick" ] || fail "cannot inspect one-shot tick implementation"
if grep -Eq 'loop[[:space:]]*\{' <<<"$tick"; then
  fail "recurrence surface contains an internal forever loop"
fi
reconcile=$(sed -n '/^fn reconcile_outcome_unknown(/,/^}/p' "$cli")
[ -n "$reconcile" ] || fail "cannot inspect outcome-unknown reconciliation"
if grep -Eq 'diagnostic_acquire|prepare_recurring_origin|SubstrateOriginAttestationSource' <<<"$reconcile"; then
  fail "outcome-unknown reconciliation can reach an origin/provider acquisition path"
fi
grep -q 'diagnostic_replay_substrate_origin' <<<"$reconcile" \
  || fail "outcome-unknown reconciliation does not reopen exact retained custody"
if rg -q 'NightshiftClient|nightshift::|create_nightshift|run_nightshift' "$store"; then
  fail "NQ recurrence store names Nightshift reasoning mechanics"
fi

grep -q 'recurring tick' "$service" || fail "one-shot service does not invoke tick"
if grep -Eq 'diagnostics (execute|acquire-next)|collect ' "$service"; then
  fail "service manager directly invokes diagnostic acquisition"
fi
grep -q 'Persistent=false' "$timer" || fail "timer may synthesize service-manager catch-up"
if grep -Eqi 'cron|OnCalendar' "$timer"; then
  fail "calendar/cron cadence escaped into service-manager artifact"
fi

echo "bounded-recurrence-surface: finite enrollment, exact slots, durable fencing, and wakeup/authority separation present"
