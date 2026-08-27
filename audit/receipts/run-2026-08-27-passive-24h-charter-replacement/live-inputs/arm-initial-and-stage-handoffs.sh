#!/bin/sh
set -eu

NQ=/opt/nq-ng/passive-handoff-87a6ca3-musl/bin/nq
CFG=/etc/nq/passive-load-24h-r2/nq-charter.toml
CONTROL=/etc/nq/passive-load-24h-r2/control
STATE=/var/lib/nq-passive-load/charter-24h-r2/operating
WORK=/tmp/nq-passive-24h-r2-materialization
H=sha256:13dd77121ce3786cf967a4e0e98993e1639dc94612cdb17ce5309d49ba8df06d

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

# The caller invokes this only after a real eligible G1 sample exists.
run_nq_service nq-passive-24h-r2-admit-g1.service \
    watcher admit labelwatch-host-passive-24h-r2-g1 > "$WORK/g1-admission.json"
admission=$(jq -r '.. | .admission_id? // empty' "$WORK/g1-admission.json" | head -1)
test -n "$admission"

genesis=$(jq -r .genesis_acquisition_ids.g1 "$WORK/preallocated-identities.json")
run_nq_service nq-passive-24h-r2-genesis-g1.service \
    diagnostics execute-linode-origin labelwatch-host-passive-24h-r2-g1 \
    --acquisition-id "$genesis" \
    --expected-instance-id-sha256 sha256:4c4a4b31edb61934a7d81cfd736af7d6c8a588d866e6116d88049d2a910c695c \
    --origin-helper /opt/nq-ng/linode-v3-20260824/bin/nq-linode-origin-helper \
    --origin-helper-sha256 sha256:058c9220ea0a2c58a4c9f6c9def3307444a9087a2ec2717577446b2ec9d20279 \
    --origin-helper-account nq-origin-helper \
    --origin-helper-public-key /etc/nq-ng-observation-office/origin-helper-public-key.hex \
    > "$WORK/g1-genesis.json"

g1=sha256:$(sha256sum "$CONTROL/g1-generation.json" | cut -d' ' -f1)
e1=$(jq -r .enrollment_id "$WORK/e1-enrollment.json")
service_digest=sha256:$(sha256sum /etc/systemd/system/nq-passive-24h-r2-recurrence.service | cut -d' ' -f1)
provider_digest=sha256:$(sha256sum /etc/nq/passive-load-24h-r2/provider-g1.toml | cut -d' ' -f1)
jq -n \
    --arg grant "$H" --arg generation "$g1" --arg enrollment "$e1" \
    --arg admission "$admission" --arg genesis "$genesis" \
    --arg provider_digest "$provider_digest" --arg service_digest "$service_digest" \
    '{schema:"nq.passive_load_office_activation_spec.v1",
      operation_id:"stage-passive-24h-r2-g1-activation", grant_id:$grant,
      generation_id:$generation,
      generation_path:"/etc/nq/passive-load-24h-r2/control/g1-generation.json",
      enrollment_id:$enrollment,
      watcher_instance_id:"labelwatch-host-passive-24h-r2-g1",
      watcher_semantic_digest:"sha256:3f79c2ff8be52abf25d99fddb1fe1687016189184268534cd73ff05a5f71c082",
      admission_id:$admission, genesis_acquisition_id:$genesis,
      provider_config_path:"/etc/nq/passive-load-24h-r2/provider-g1.toml",
      provider_config_digest:$provider_digest,
      passive_provider_boundary_id:"nq.passive_host_load_preexisting_sample_provider.v1",
      sample_store:"/var/lib/nq-passive-load/samples/charter-20260827-r2-g1",
      capacity_context_id:"sha256:6c6e34b0e088655fce62d4dd15ea355e6d79015736c6e0fb5b8219feac492c7d",
      service_manager_deployment_path:"/etc/systemd/system/nq-passive-24h-r2-recurrence.service",
      service_manager_deployment_digest:$service_digest}' > "$WORK/activation-g1.json"
install -m 0640 -o root -g nq-passive-load-reader "$WORK/activation-g1.json" "$CONTROL/activation-g1.json"
"$NQ" --config "$CFG" --json operating activation-stage "$CONTROL/activation-g1.json" \
    --state-dir "$STATE" > "$WORK/activation-g1-materialization.json"
install -m 0640 -o root -g nq-passive-load-reader \
    "$WORK/activation-g1-materialization.json" "$CONTROL/activation-g1-materialization.json"

for n in 1 2 3; do
    next=$((n+1))
    predecessor=$(jq -r .activation.activation_id "$WORK/activation-g$n-materialization.json")
    successor=$(jq -r .activation.activation_id "$WORK/activation-g$next-materialization.json")
    relation=$(jq -r .relation_id "$CONTROL/w$n-w$next-succession.json")
    generation=sha256:$(sha256sum "$CONTROL/g$next-generation.json" | cut -d' ' -f1)
    enrollment=$(jq -r .enrollment_id "$WORK/e$next-enrollment.json")
    admission_next=$(jq -r ".successor_admission_ids.g$next" "$WORK/preallocated-identities.json")
    genesis_next=$(jq -r ".genesis_acquisition_ids.g$next" "$WORK/preallocated-identities.json")
    case "$next" in
        2) semantic=sha256:541606892c526c90b6f70bbceed6ff84fb63d464984d0355f9142fe0a31a09dc ;;
        3) semantic=sha256:33e7c53d29e4ad2ce1cb460d4aa6df31b9f44b9b62dfde51c8e7f137a6372248 ;;
        4) semantic=sha256:171b4945f63e5ace97f0208e858072317959005ed072050f75545c863165beb9 ;;
    esac
    jq -n \
        --arg operation "stage-passive-24h-r2-handoff-$n-$next" \
        --arg grant "$H" --arg relation "$relation" --arg predecessor "$predecessor" \
        --arg generation "$generation" --arg semantic "$semantic" \
        --arg admission "$admission_next" --arg genesis "$genesis_next" \
        --arg enrollment "$enrollment" --arg successor "$successor" \
        --argjson next "$next" \
        '{schema:"nq.passive_load_successor_handoff_spec.v1",
          operation_id:$operation, grant_id:$grant, succession_relation_id:$relation,
          predecessor_activation_id:$predecessor, next_generation_id:$generation,
          next_generation_path:("/etc/nq/passive-load-24h-r2/control/g"+($next|tostring)+"-generation.json"),
          successor_watcher_instance_id:("labelwatch-host-passive-24h-r2-g"+($next|tostring)),
          successor_watcher_semantic_digest:$semantic,
          expected_admission_id:$admission, genesis_acquisition_id:$genesis,
          expected_instance_id_sha256:"sha256:4c4a4b31edb61934a7d81cfd736af7d6c8a588d866e6116d88049d2a910c695c",
          origin_helper_path:"/opt/nq-ng/linode-v3-20260824/bin/nq-linode-origin-helper",
          origin_helper_sha256:"sha256:058c9220ea0a2c58a4c9f6c9def3307444a9087a2ec2717577446b2ec9d20279",
          origin_helper_account:"nq-origin-helper",
          origin_helper_public_key_path:"/etc/nq-ng-observation-office/origin-helper-public-key.hex",
          next_enrollment_id:$enrollment, next_activation_id:$successor}' \
        > "$WORK/handoff-$n-$next.json"
    install -m 0640 -o root -g nq-passive-load-reader "$WORK/handoff-$n-$next.json" "$CONTROL/handoff-$n-$next.json"
    "$NQ" --config "$CFG" --json operating handoff-stage "$CONTROL/handoff-$n-$next.json" \
        --state-dir "$STATE" > "$WORK/handoff-$n-$next-materialization.json"
    install -m 0640 -o root -g nq-passive-load-reader \
        "$WORK/handoff-$n-$next-materialization.json" \
        "$CONTROL/handoff-$n-$next-materialization.json"
done

initial=$(jq -r .activation.activation_id "$WORK/activation-g1-materialization.json")
"$NQ" --config "$CFG" --json operating activation-validate "$initial" \
    --operation-id validate-passive-24h-r2-g1 --state-dir "$STATE"
"$NQ" --config "$CFG" --json operating activation-arm "$initial" \
    --operation-id arm-passive-24h-r2-g1 --state-dir "$STATE"

chown -R nq:nq "$STATE"
for n in 1 2 3; do
    handoff=$(jq -r .handoff.handoff_id "$WORK/handoff-$n-$((n+1))-materialization.json")
    systemctl enable --now "nq-passive-24h-r2-handoff@$handoff.timer"
done

"$NQ" --config "$CFG" --json operating activation-status "$initial" --state-dir "$STATE"
