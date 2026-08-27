#!/bin/sh
set -eu

NQ=/opt/nq-ng/passive-handoff-87a6ca3-musl/bin/nq
CFG=/etc/nq/passive-load-24h-r2/nq-charter.toml
CONTROL=/etc/nq/passive-load-24h-r2/control
STATE=/var/lib/nq-passive-load/charter-24h-r2/operating
WORK=/tmp/nq-passive-24h-r2-materialization
H=sha256:13dd77121ce3786cf967a4e0e98993e1639dc94612cdb17ce5309d49ba8df06d
START=1787853600000
LATEST_START=1787853900000

now=$(date -u +%s%3N)
test "$now" -ge "$START"
test "$now" -lt "$LATEST_START"

run_nq_service() {
    unit=$1
    shift
    systemd-run --quiet --collect --wait --pipe --unit="$unit" \
        --property=User=nq --property=Group=nq \
        --property='SupplementaryGroups=nq-evidence nq-passive-load-reader' \
        --property='CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' \
        --property='AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' \
        "$NQ" --config "$CFG" --json "$@"
}

# E4 is deliberately materialized only after START, so creation-to-expiry is
# strictly inside the unchanged 24-hour deployment-policy ceiling.
run_nq_service nq-passive-24h-r2-enroll-e4.service \
    recurring enroll "$CONTROL/e4-spec.json" > "$WORK/e4-enrollment.json"
e4=$(jq -r .enrollment_id "$WORK/e4-enrollment.json")
test -n "$e4"

"$NQ" --config "$CFG" --json operating grant-activate "$H" \
    --operation-id activate-passive-24h-r2-h1-20260827 --state-dir "$STATE"

for edge in 1-2 2-3 3-4; do
    "$NQ" --config "$CFG" --json operating issue-watcher-succession "$H" \
        "$CONTROL/w${edge%-*}-w${edge#*-}-succession.json" --state-dir "$STATE"
done

for n in 1 2 3 4; do
    enrollment=$(jq -r .enrollment_id "$WORK/e$n-enrollment.json")
    "$NQ" --config "$CFG" --json operating issue-generation "$H" \
        "$CONTROL/g$n-generation.json" \
        --operation-id "issue-passive-24h-r2-g$n-20260827" --state-dir "$STATE"
    "$NQ" --config "$CFG" --json operating issue-enrollment "$H" "$enrollment" \
        --operation-id "issue-passive-24h-r2-e$n-20260827" --state-dir "$STATE"
done

service_digest=sha256:$(sha256sum /etc/systemd/system/nq-passive-24h-r2-recurrence.service | cut -d' ' -f1)
for n in 2 3 4; do
    generation=sha256:$(sha256sum "$CONTROL/g$n-generation.json" | cut -d' ' -f1)
    enrollment=$(jq -r .enrollment_id "$WORK/e$n-enrollment.json")
    admission=$(jq -r ".successor_admission_ids.g$n" "$WORK/preallocated-identities.json")
    genesis=$(jq -r ".genesis_acquisition_ids.g$n" "$WORK/preallocated-identities.json")
    case "$n" in
        2) semantic=sha256:541606892c526c90b6f70bbceed6ff84fb63d464984d0355f9142fe0a31a09dc ;;
        3) semantic=sha256:33e7c53d29e4ad2ce1cb460d4aa6df31b9f44b9b62dfde51c8e7f137a6372248 ;;
        4) semantic=sha256:171b4945f63e5ace97f0208e858072317959005ed072050f75545c863165beb9 ;;
    esac
    provider_digest=sha256:$(sha256sum "/etc/nq/passive-load-24h-r2/provider-g$n.toml" | cut -d' ' -f1)
    jq -n \
        --arg operation "stage-passive-24h-r2-g$n-activation" \
        --arg grant "$H" --arg generation "$generation" \
        --arg generation_path "$CONTROL/g$n-generation.json" \
        --arg enrollment "$enrollment" \
        --arg watcher_instance "labelwatch-host-passive-24h-r2-g$n" \
        --arg semantic "$semantic" --arg admission "$admission" \
        --arg genesis "$genesis" \
        --arg provider_path "/etc/nq/passive-load-24h-r2/provider-g$n.toml" \
        --arg provider_digest "$provider_digest" \
        --arg sample_store "/var/lib/nq-passive-load/samples/charter-20260827-r2-g$n" \
        --arg service_digest "$service_digest" \
        '{schema:"nq.passive_load_office_activation_spec.v1",
          operation_id:$operation, grant_id:$grant, generation_id:$generation,
          generation_path:$generation_path, enrollment_id:$enrollment,
          watcher_instance_id:$watcher_instance, watcher_semantic_digest:$semantic,
          admission_id:$admission, genesis_acquisition_id:$genesis,
          provider_config_path:$provider_path, provider_config_digest:$provider_digest,
          passive_provider_boundary_id:"nq.passive_host_load_preexisting_sample_provider.v1",
          sample_store:$sample_store,
          capacity_context_id:"sha256:6c6e34b0e088655fce62d4dd15ea355e6d79015736c6e0fb5b8219feac492c7d",
          service_manager_deployment_path:"/etc/systemd/system/nq-passive-24h-r2-recurrence.service",
          service_manager_deployment_digest:$service_digest}' \
        > "$WORK/activation-g$n.json"
    install -m 0640 -o root -g nq-passive-load-reader "$WORK/activation-g$n.json" "$CONTROL/activation-g$n.json"
    "$NQ" --config "$CFG" --json operating activation-stage "$CONTROL/activation-g$n.json" \
        --state-dir "$STATE" > "$WORK/activation-g$n-materialization.json"
    install -m 0640 -o root -g nq-passive-load-reader \
        "$WORK/activation-g$n-materialization.json" "$CONTROL/activation-g$n-materialization.json"
done

# Future G timers are mechanics only. G1 is started explicitly after all exact
# child issuance; recurrence is exposed mechanically while still timer-inert.
systemctl enable --now \
    nq-passive-24h-r2-observer-g2.timer \
    nq-passive-24h-r2-observer-g3.timer \
    nq-passive-24h-r2-observer-g4.timer
systemctl enable --now nq-passive-24h-r2-recurrence.timer
systemctl enable --now nq-passive-24h-r2-closeout.timer
systemctl start nq-passive-24h-r2-observer@g1.service

chown -R nq:nq "$STATE"
"$NQ" --config "$CFG" --json operating grant-status "$H" --state-dir "$STATE"
