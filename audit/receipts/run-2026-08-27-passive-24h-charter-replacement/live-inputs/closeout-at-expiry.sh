#!/bin/sh
set -u

NQ=/opt/nq-ng/passive-handoff-87a6ca3-musl/bin/nq
HELPER=/opt/nq-ng/passive-handoff-87a6ca3-musl/lib/nq/helpers/nq-passive-load-helper
CFG=/etc/nq/passive-load-24h-r2/nq-charter.toml
CONTROL=/etc/nq/passive-load-24h-r2/control
STATE=/var/lib/nq-passive-load/charter-24h-r2/operating
H=sha256:13dd77121ce3786cf967a4e0e98993e1639dc94612cdb17ce5309d49ba8df06d
OUT=/var/lib/nq-passive-load/charter-24h-r2/closeout-20260828T180005Z.log

exec >> "$OUT" 2>&1
date -u '+closeout_started=%Y-%m-%dT%H:%M:%SZ'

systemctl disable --now nq-passive-24h-r2-recurrence.timer || true
systemctl stop nq-passive-24h-r2-recurrence.service || true

for n in 1 2 3; do
    materialization="$CONTROL/handoff-$n-$((n+1))-materialization.json"
    if test -r "$materialization"; then
        handoff=$(jq -r .handoff.handoff_id "$materialization")
        systemctl disable --now "nq-passive-24h-r2-handoff@$handoff.timer" || true
        systemctl stop "nq-passive-24h-r2-handoff@$handoff.service" || true
    fi
done

for n in 1 2 3 4; do
    systemctl disable --now "nq-passive-24h-r2-observer-g$n.timer" || true
    systemctl stop "nq-passive-24h-r2-observer@g$n.service" || true
done

for n in 1 2 3 4; do
    materialization="$CONTROL/activation-g$n-materialization.json"
    if test -r "$materialization"; then
        activation=$(jq -r .activation.activation_id "$materialization")
        "$NQ" --config "$CFG" --json operating activation-close "$activation" \
            --operation-id "close-passive-24h-r2-g$n-at-expiry" \
            --reason exclusive_h_expiry --state-dir "$STATE" || true
    fi
done

"$NQ" --config "$CFG" --json operating grant-retire "$H" \
    --operation-id retire-passive-24h-r2-h-at-expiry \
    --reason exclusive_h_expiry --state-dir "$STATE" || true

for n in 1 2 3 4; do
    enrollment_file="$CONTROL/e$n-enrollment.json"
    if test -r "$enrollment_file"; then
        enrollment=$(jq -r .enrollment_id "$enrollment_file")
        "$NQ" --config "$CFG" --json recurring revoke "$enrollment" \
            --operation-id "revoke-passive-24h-r2-e$n-at-expiry" \
            --reason exclusive_h_expiry || true
    fi
    "$HELPER" retire-generation "$CONTROL/g$n-generation.json" \
        "retire-passive-24h-r2-g$n-at-expiry" exclusive_h_expiry || true
done

chown -R nq:nq "$STATE" || true
date -u '+closeout_finished=%Y-%m-%dT%H:%M:%SZ'
