#!/usr/bin/env bash
set -euo pipefail

SLUG="k3s-live-origin-capacity-qualification-v1"
LAB_ROOT="${BEDROCK_LAB_ROOT:-/data/git/.bedrock-lab/${SLUG}}"
SSH_KEY="${LAB_ROOT}/ssh/bedrock_ed25519"
KNOWN_HOSTS="${LAB_ROOT}/ssh/known_hosts"
USER_NAME="bedrock"

die() {
    printf 'BEDROCK refusal: %s\n' "$*" >&2
    exit 1
}

node_port() {
    case "$1" in
        server) printf '19321\n' ;;
        agent) printf '19322\n' ;;
        *) die "unknown node: $1" ;;
    esac
}

ssh_node() {
    local node="$1"
    shift
    ssh \
        -i "${SSH_KEY}" \
        -p "$(node_port "${node}")" \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        -o ConnectTimeout=5 \
        "${USER_NAME}@127.0.0.1" "$@"
}

scp_to_node() {
    local node="$1"
    local source="$2"
    local destination="$3"
    scp \
        -q \
        -i "${SSH_KEY}" \
        -P "$(node_port "${node}")" \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        "${source}" "${USER_NAME}@127.0.0.1:${destination}"
}

scp_from_node() {
    local node="$1"
    local source="$2"
    local destination="$3"
    scp \
        -q \
        -i "${SSH_KEY}" \
        -P "$(node_port "${node}")" \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="${KNOWN_HOSTS}" \
        "${USER_NAME}@127.0.0.1:${source}" "${destination}"
}

server_unit="${LAB_ROOT}/nodes/server/k3s.service"
agent_unit="${LAB_ROOT}/nodes/agent/k3s-agent.service"
token_file="${LAB_ROOT}/secrets/node-token"
kubeconfig="${LAB_ROOT}/kubeconfig/bedrock-k3s.yaml"

mkdir -p "${LAB_ROOT}/secrets" "${LAB_ROOT}/kubeconfig"
chmod 700 "${LAB_ROOT}/secrets" "${LAB_ROOT}/kubeconfig"

ssh_node server \
    'sudo chown 65532:65532 /mnt/bedrock-custody/canonical /mnt/bedrock-custody/journal /mnt/bedrock-custody/receipts && sudo chmod 0700 /mnt/bedrock-custody/canonical /mnt/bedrock-custody/journal /mnt/bedrock-custody/receipts'
ssh_node agent \
    'test "$(stat -c %u:%g:%a /mnt/bedrock-custody/canonical)" = 65532:65532:700 && test "$(stat -c %u:%g:%a /mnt/bedrock-custody/journal)" = 65532:65532:700 && test "$(stat -c %u:%g:%a /mnt/bedrock-custody/receipts)" = 65532:65532:700'

cat >"${server_unit}" <<'EOF'
[Unit]
Description=BEDROCK campaign-owned k3s server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
KillMode=process
Delegate=yes
LimitNOFILE=1048576
TasksMax=infinity
Restart=no
ExecStart=/usr/local/bin/k3s server --node-name bedrock-server --node-ip 10.90.0.11 --advertise-address 10.90.0.11 --tls-san 10.90.0.11 --tls-san 127.0.0.1 --flannel-iface cluster0 --disable traefik --disable servicelb --disable local-storage --disable metrics-server --disable coredns --write-kubeconfig-mode 0600

[Install]
WantedBy=multi-user.target
EOF

cat >"${agent_unit}" <<'EOF'
[Unit]
Description=BEDROCK campaign-owned k3s agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
KillMode=process
Delegate=yes
LimitNOFILE=1048576
TasksMax=infinity
Restart=no
ExecStart=/usr/local/bin/k3s agent --server https://10.90.0.11:6443 --token-file /etc/rancher/k3s/bedrock-token --node-name bedrock-agent --node-ip 10.90.0.12 --flannel-iface cluster0

[Install]
WantedBy=multi-user.target
EOF

scp_to_node server "${server_unit}" /tmp/k3s.service
ssh_node server \
    'sudo install -o root -g root -m 0644 /tmp/k3s.service /etc/systemd/system/k3s.service && sudo systemctl daemon-reload && sudo systemctl enable --now k3s.service'

for attempt in $(seq 1 90); do
    if ssh_node server 'sudo /usr/local/bin/k3s kubectl get --raw=/readyz >/dev/null 2>&1'; then
        break
    fi
    test "${attempt}" -ne 90 || die "k3s server readiness gate did not pass"
    sleep 2
done

ssh_node server \
    "sudo install -o ${USER_NAME} -g ${USER_NAME} -m 0600 /var/lib/rancher/k3s/server/node-token /home/${USER_NAME}/bedrock-node-token"
scp_from_node server "/home/${USER_NAME}/bedrock-node-token" "${token_file}"
chmod 600 "${token_file}"
ssh_node server "sudo rm -f /home/${USER_NAME}/bedrock-node-token"
scp_to_node agent "${token_file}" /tmp/bedrock-token
scp_to_node agent "${agent_unit}" /tmp/k3s-agent.service
ssh_node agent \
    'sudo mkdir -p /etc/rancher/k3s && sudo install -o root -g root -m 0600 /tmp/bedrock-token /etc/rancher/k3s/bedrock-token && sudo install -o root -g root -m 0644 /tmp/k3s-agent.service /etc/systemd/system/k3s-agent.service && sudo systemctl daemon-reload && sudo systemctl enable --now k3s-agent.service'

for attempt in $(seq 1 90); do
    if ssh_node server \
        'sudo /usr/local/bin/k3s kubectl get node bedrock-agent -o jsonpath={.status.conditions[\?\(@.type==\"Ready\"\)].status} 2>/dev/null | grep -qx True'; then
        break
    fi
    test "${attempt}" -ne 90 || die "k3s agent readiness gate did not pass"
    sleep 2
done

ssh_node server \
    "sudo install -o ${USER_NAME} -g ${USER_NAME} -m 0600 /etc/rancher/k3s/k3s.yaml /home/${USER_NAME}/bedrock-kubeconfig"
scp_from_node server "/home/${USER_NAME}/bedrock-kubeconfig" "${kubeconfig}"
chmod 600 "${kubeconfig}"
ssh_node server "sudo rm -f /home/${USER_NAME}/bedrock-kubeconfig"
sed -i 's#server: https://127.0.0.1:6443#server: https://127.0.0.1:17443#' "${kubeconfig}"

sha256sum "${server_unit}" "${agent_unit}" >"${LAB_ROOT}/systemd-unit-digests.sha256"
