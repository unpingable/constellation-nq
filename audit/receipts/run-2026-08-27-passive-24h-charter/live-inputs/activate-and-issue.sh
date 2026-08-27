#!/bin/sh
set -eu

NQ=/opt/nq-ng/passive-handoff-87a6ca3-musl/bin/nq
CFG=/etc/nq/passive-load-24h/nq-charter.toml
STATE=/var/lib/nq-passive-load/charter-24h-authorized/operating
CONTROL=/etc/nq/passive-load-24h/control
H=sha256:deb832fdc11d3b32a56643aa3831570154bfd430c1b8328518f26917824c881f

"$NQ" --config "$CFG" operating grant-activate "$H" \
  --operation-id activate-passive-24h-h1-20260827 --state-dir "$STATE" --json

for edge in w1-w2 w2-w3 w3-w4; do
  "$NQ" --config "$CFG" operating issue-watcher-succession "$H" \
    "$CONTROL/$edge-succession.json" --state-dir "$STATE" --json
done

for index in 1 2 3 4; do
  "$NQ" --config "$CFG" recurring enroll "/etc/nq/passive-load-24h/e$index-spec.json" \
    --json > "$CONTROL/e$index-enrollment.json"
  enrollment_id=$(jq -r .enrollment_id "$CONTROL/e$index-enrollment.json")
  "$NQ" --config "$CFG" operating issue-generation "$H" \
    "$CONTROL/g$index-generation.json" \
    --operation-id "issue-passive-24h-g$index-20260827" --state-dir "$STATE" --json
  "$NQ" --config "$CFG" operating issue-enrollment "$H" "$enrollment_id" \
    --operation-id "issue-passive-24h-e$index-20260827" --state-dir "$STATE" --json
  printf 'E%s=%s\n' "$index" "$enrollment_id"
done

"$NQ" --config "$CFG" operating grant-status "$H" --state-dir "$STATE" --json

# Mechanics only: every timer points at an already-materialized exact G.
# Persistent G1 starts the first real slot after child issuance; later timers
# retain their absolute half-open boundary times.
systemctl enable --now \
  nq-passive-24h-observer-g1.timer \
  nq-passive-24h-observer-g2.timer \
  nq-passive-24h-observer-g3.timer \
  nq-passive-24h-observer-g4.timer
