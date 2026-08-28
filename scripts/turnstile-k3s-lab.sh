#!/usr/bin/env bash
set -euo pipefail

CAMPAIGN="TURNSTILE"
SLUG="k3s-ag-exact-occurrence-adapter-v1"
LAB_ROOT="${TURNSTILE_LAB_ROOT:-/data/git/.turnstile-lab/${SLUG}}"
BASE_IMAGE="${TURNSTILE_BASE_IMAGE:-/data/git/skunkworks/nq-ng/.campaign-local/track-b-vm-deployment-675e247/base.qcow2}"
BASE_SHA256="d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30"
K3S_VERSION="v1.36.4+k3s1"
K3S_SHA256="835873f37245fc615f547a2fe2af9402a347875f13fa64a1f136de644955ea3f"
K3S_BINARY="${LAB_ROOT}/downloads/k3s-${K3S_VERSION}-amd64"
SSH_KEY="${LAB_ROOT}/ssh/turnstile_ed25519"
KNOWN_HOSTS="${LAB_ROOT}/ssh/known_hosts"
USER_NAME="turnstile"
CLUSTER_NETWORK="10.89.0.0/24"
CLUSTER_MCAST="230.89.0.1:19001,localaddr=127.0.0.1"

die() {
    printf 'TURNSTILE refusal: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"
}

node_dir() {
    printf '%s/nodes/%s\n' "${LAB_ROOT}" "$1"
}

node_port() {
    case "$1" in
        server) printf '19221\n' ;;
        agent) printf '19222\n' ;;
        *) die "unknown node: $1" ;;
    esac
}

node_ip() {
    case "$1" in
        server) printf '10.89.0.11\n' ;;
        agent) printf '10.89.0.12\n' ;;
        *) die "unknown node: $1" ;;
    esac
}

node_mac_nat() {
    case "$1" in
        server) printf '52:54:00:89:00:11\n' ;;
        agent) printf '52:54:00:89:00:12\n' ;;
        *) die "unknown node: $1" ;;
    esac
}

node_mac_cluster() {
    case "$1" in
        server) printf '52:54:00:89:01:11\n' ;;
        agent) printf '52:54:00:89:01:12\n' ;;
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

prepare_node() {
    local node="$1"
    local memory_mb="$2"
    local disk_size="$3"
    local cluster_ip
    local nat_mac
    local cluster_mac
    local instance_id
    local directory
    local public_key

    directory="$(node_dir "${node}")"
    cluster_ip="$(node_ip "${node}")"
    nat_mac="$(node_mac_nat "${node}")"
    cluster_mac="$(node_mac_cluster "${node}")"
    instance_id="${SLUG}-${node}-$(uuidgen)"
    public_key="$(<"${SSH_KEY}.pub")"

    test ! -e "${directory}" || die "node directory already exists: ${directory}"
    mkdir -p "${directory}/seed"
    chmod 700 "${directory}"
    qemu-img create \
        -f qcow2 \
        -F qcow2 \
        -b "${BASE_IMAGE}" \
        "${directory}/root.qcow2" \
        "${disk_size}"

    printf '%s\n' \
        "instance-id: ${instance_id}" \
        "local-hostname: turnstile-k3s-${node}" \
        >"${directory}/seed/meta-data"

    cat >"${directory}/seed/user-data" <<EOF
#cloud-config
hostname: turnstile-k3s-${node}
manage_etc_hosts: true
users:
  - default
  - name: ${USER_NAME}
    groups: [adm, sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${public_key}
ssh_pwauth: false
disable_root: true
package_update: false
package_upgrade: false
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
runcmd:
  - [swapoff, -a]
  - [mkdir, -p, /mnt/turnstile-custody]
  - [sh, -c, "mount -t 9p -o trans=virtio,version=9p2000.L turnstile_custody /mnt/turnstile-custody"]
  - [sh, -c, "grep -q '^turnstile_custody ' /etc/fstab || printf '%s\\n' 'turnstile_custody /mnt/turnstile-custody 9p trans=virtio,version=9p2000.L,_netdev 0 0' >> /etc/fstab"]
EOF

    cat >"${directory}/seed/network-config" <<EOF
version: 2
ethernets:
  nat0:
    match:
      macaddress: "${nat_mac}"
    set-name: nat0
    dhcp4: true
  cluster0:
    match:
      macaddress: "${cluster_mac}"
    set-name: cluster0
    dhcp4: false
    addresses:
      - ${cluster_ip}/24
EOF

    (
        cd "${directory}/seed"
        xorriso -as mkisofs \
            -output "${directory}/seed.iso" \
            -volid cidata \
            -joliet \
            -rock \
            user-data meta-data network-config \
            >"${directory}/xorriso.log" 2>&1
    )

    printf '%s\n' \
        "campaign=${CAMPAIGN}" \
        "slug=${SLUG}" \
        "node=${node}" \
        "instance_id=${instance_id}" \
        "memory_mb=${memory_mb}" \
        "vcpus=2" \
        "disk_size=${disk_size}" \
        "cluster_network=${CLUSTER_NETWORK}" \
        "cluster_ip=${cluster_ip}" \
        "nat_mac=${nat_mac}" \
        "cluster_mac=${cluster_mac}" \
        "ssh_forward=127.0.0.1:$(node_port "${node}")" \
        >"${directory}/planned-facts"
}

prepare() {
    require_command qemu-img
    require_command qemu-system-x86_64
    require_command xorriso
    require_command ssh-keygen
    require_command uuidgen
    require_command sha256sum

    mkdir -p "${LAB_ROOT}/downloads" "${LAB_ROOT}/ssh" "${LAB_ROOT}/external-custody"
    chmod 700 "${LAB_ROOT}" "${LAB_ROOT}/ssh"
    test "$(sha256sum "${BASE_IMAGE}" | awk '{print $1}')" = "${BASE_SHA256}" \
        || die "base-image digest mismatch"
    qemu-img check "${BASE_IMAGE}" >"${LAB_ROOT}/base-qemu-img-check.log"
    test -x "${K3S_BINARY}" || die "verified k3s binary is absent: ${K3S_BINARY}"
    test "$(sha256sum "${K3S_BINARY}" | awk '{print $1}')" = "${K3S_SHA256}" \
        || die "k3s binary digest mismatch"

    if test ! -e "${SSH_KEY}"; then
        ssh-keygen \
            -q \
            -t ed25519 \
            -N '' \
            -C "${CAMPAIGN} ${SLUG}" \
            -f "${SSH_KEY}"
    fi
    chmod 600 "${SSH_KEY}"
    chmod 644 "${SSH_KEY}.pub"
    : >"${KNOWN_HOSTS}"
    chmod 600 "${KNOWN_HOSTS}"

    mkdir -p \
        "${LAB_ROOT}/external-custody/canonical" \
        "${LAB_ROOT}/external-custody/journal" \
        "${LAB_ROOT}/external-custody/receipts"
    chmod 700 "${LAB_ROOT}/external-custody" \
        "${LAB_ROOT}/external-custody/canonical" \
        "${LAB_ROOT}/external-custody/journal" \
        "${LAB_ROOT}/external-custody/receipts"

    prepare_node server 4096 30G
    prepare_node agent 3072 24G

    sha256sum \
        "${BASE_IMAGE}" \
        "${K3S_BINARY}" \
        "${LAB_ROOT}/nodes/server/seed.iso" \
        "${LAB_ROOT}/nodes/agent/seed.iso" \
        "${SSH_KEY}.pub" \
        >"${LAB_ROOT}/prepared-digests.sha256"
}

start_node() {
    local node="$1"
    local memory_mb="$2"
    local api_forward=""
    local directory
    local pid

    directory="$(node_dir "${node}")"
    test -f "${directory}/root.qcow2" || die "node is not prepared: ${node}"
    if test -f "${directory}/qemu.pid"; then
        pid="$(<"${directory}/qemu.pid")"
        if kill -0 "${pid}" 2>/dev/null; then
            die "node already running: ${node} pid ${pid}"
        fi
        die "stale qemu pid file requires explicit review: ${directory}/qemu.pid"
    fi

    if test "${node}" = server; then
        api_forward=",hostfwd=tcp:127.0.0.1:16443-:6443"
    fi

    qemu-system-x86_64 \
        -enable-kvm \
        -machine q35,accel=kvm,hpet=off \
        -cpu host \
        -smp 2 \
        -m "${memory_mb}" \
        -name "turnstile-k3s-${node}" \
        -drive "file=${directory}/root.qcow2,if=virtio,format=qcow2,cache=none" \
        -drive "file=${directory}/seed.iso,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=nat0,restrict=on,hostfwd=tcp:127.0.0.1:$(node_port "${node}")-:22${api_forward}" \
        -device "virtio-net-pci,netdev=nat0,mac=$(node_mac_nat "${node}")" \
        -netdev "socket,id=cluster0,mcast=${CLUSTER_MCAST}" \
        -device "virtio-net-pci,netdev=cluster0,mac=$(node_mac_cluster "${node}")" \
        -virtfs "local,path=${LAB_ROOT}/external-custody,mount_tag=turnstile_custody,security_model=mapped-xattr,id=custody0,multidevs=remap" \
        -display none \
        -serial "file:${directory}/serial.log" \
        -monitor "unix:${directory}/monitor.sock,server=on,wait=off" \
        -pidfile "${directory}/qemu.pid" \
        -daemonize \
        2>"${directory}/qemu.stderr.log"
}

capture_host_key() {
    local node="$1"
    local port
    local attempt
    port="$(node_port "${node}")"
    for attempt in $(seq 1 90); do
        if ssh-keyscan -T 2 -p "${port}" 127.0.0.1 \
            >>"${KNOWN_HOSTS}" 2>"$(node_dir "${node}")/ssh-keyscan.log"; then
            return 0
        fi
        sleep 2
    done
    die "SSH host key did not become available for ${node}"
}

wait_cloud_init() {
    local node="$1"
    local attempt
    for attempt in $(seq 1 90); do
        if ssh_node "${node}" 'cloud-init status --wait >/dev/null 2>&1'; then
            return 0
        fi
        sleep 2
    done
    die "cloud-init did not complete for ${node}"
}

start() {
    require_command ssh-keyscan
    start_node server 4096
    start_node agent 3072
    capture_host_key server
    capture_host_key agent
    ssh-keygen -lf "${KNOWN_HOSTS}" >"${LAB_ROOT}/ssh/host-key-fingerprints"
    wait_cloud_init server
    wait_cloud_init agent
}

install_binary() {
    local node="$1"
    scp_to_node "${node}" "${K3S_BINARY}" /tmp/k3s
    ssh_node "${node}" \
        "test \"\$(sha256sum /tmp/k3s | awk '{print \$1}')\" = '${K3S_SHA256}' && sudo install -o root -g root -m 0755 /tmp/k3s /usr/local/bin/k3s && test \"\$(sudo sha256sum /usr/local/bin/k3s | awk '{print \$1}')\" = '${K3S_SHA256}'"
}

install() {
    install_binary server
    install_binary agent
}

status() {
    local node
    local directory
    local pid
    for node in server agent; do
        directory="$(node_dir "${node}")"
        if test -f "${directory}/qemu.pid"; then
            pid="$(<"${directory}/qemu.pid")"
            if kill -0 "${pid}" 2>/dev/null; then
                printf '%s running pid=%s ssh=127.0.0.1:%s cluster_ip=%s\n' \
                    "${node}" "${pid}" "$(node_port "${node}")" "$(node_ip "${node}")"
            else
                printf '%s stopped stale_pid=%s\n' "${node}" "${pid}"
            fi
        else
            printf '%s not-created-or-not-started\n' "${node}"
        fi
    done
}

teardown_node() {
    local node="$1"
    local directory
    local pid
    local attempt
    directory="$(node_dir "${node}")"
    test -f "${directory}/qemu.pid" || return 0
    pid="$(<"${directory}/qemu.pid")"
    if ! kill -0 "${pid}" 2>/dev/null; then
        printf 'TURNSTILE refusal: stale pid file retained for review: %s\n' "${directory}/qemu.pid" >&2
        return 1
    fi
    test "$(tr -d '\0' <"/proc/${pid}/cmdline" | sed 's/qemu-system-x86_64.*/qemu-system-x86_64/')" = qemu-system-x86_64 \
        || die "pid ${pid} is not a QEMU process"
    printf 'system_powerdown\n' | nc -U "${directory}/monitor.sock" >/dev/null
    for attempt in $(seq 1 30); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            mv "${directory}/qemu.pid" "${directory}/qemu.pid.closed"
            return 0
        fi
        sleep 1
    done
    die "node ${node} did not shut down cleanly; pid ${pid} left running"
}

teardown() {
    require_command nc
    teardown_node agent
    teardown_node server
}

case "${1:-}" in
    prepare) prepare ;;
    start) start ;;
    start-agent) start_node agent 3072 ;;
    install) install ;;
    status) status ;;
    teardown-agent) require_command nc; teardown_node agent ;;
    teardown) teardown ;;
    *)
        printf 'usage: %s {prepare|start|start-agent|install|status|teardown-agent|teardown}\n' "$0" >&2
        exit 2
        ;;
esac
