#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

fail() {
  echo "continuity authority boundary: $*" >&2
  exit 1
}

rg -q 'SubstrateIncarnation' "$root/crates/nq-core/src/continuity.rs" || fail "closed relation missing"
rg -q 'commit_continuity_dispatch' "$root/crates/nq-core/src/engine.rs" || fail "atomic dispatch fence missing"
rg -q 'provider_invocation_started' "$root/crates/nq-core/src/engine.rs" || fail "invocation fence missing"
rg -q 'verify_for_watcher' "$root/crates/nq-core/src/continuity.rs" || fail "Standing signature verifier missing"

if rg -n 'continuity_authorized|current_substrate|hostname_similarity|dns.*continuity|authorized[[:space:]]*=[[:space:]]*true' \
  "$root/crates/nq-core/src/engine.rs" \
  "$root/crates/nq-core/src/config.rs" \
  "$root/crates/nq-core/src/diagnostic_admission.rs" \
  "$root/crates/nq-store/src"; then
  fail "mutable/timestamp/hostname continuity shortcut present"
fi
if rg -n 'Command::new|cron|crontab' "$root/crates/nq-core/src/continuity.rs"; then
  fail "generic execution or scheduler surface present"
fi

echo "continuity authority boundary: ok"
