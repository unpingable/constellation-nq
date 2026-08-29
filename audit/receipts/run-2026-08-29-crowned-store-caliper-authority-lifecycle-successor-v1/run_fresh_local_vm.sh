#!/usr/bin/env bash
# Fresh campaign-owned Ubuntu VM controller for CROWNED-STORE.
set -Eeuo pipefail
umask 077

readonly EXPECTED_IMAGE_SHA256=d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30
readonly EXPECTED_VCPUS=2
readonly EXPECTED_MEMORY_MIB=2048
readonly EXPECTED_OVERLAY_BYTES=21474836480

usage() {
    echo "usage: $0 ABSOLUTE_NEW_STATE_DIR IMAGE DEB DEB_SHA256 GUEST_DRIVER SSH_PORT" >&2
    exit 2
}

[[ $# == 6 ]] || usage
state=$1
image=$2
deb=$3
deb_sha=$4
driver=$5
port=$6

[[ $state == /* && ! -e $state ]] || {
    echo "state directory must be a new absolute pathname" >&2
    exit 2
}
[[ -f $image && ! -L $image && -f $deb && ! -L $deb && -f $driver && ! -L $driver ]] || {
    echo "image, package, and guest driver must be regular non-symlink files" >&2
    exit 2
}
[[ $deb_sha =~ ^[0-9a-f]{64}$ && $port =~ ^[0-9]+$ ]] || usage
[[ $(sha256sum -- "$image" | awk '{print $1}') == "$EXPECTED_IMAGE_SHA256" ]] || {
    echo "base image digest mismatch" >&2
    exit 1
}
[[ $(sha256sum -- "$deb" | awk '{print $1}') == "$deb_sha" ]] || {
    echo "Debian package digest mismatch" >&2
    exit 1
}
if ss -ltn "( sport = :$port )" | tail -n +2 | grep -q .; then
    echo "requested loopback SSH port is already in use" >&2
    exit 1
fi

mkdir -m 0700 -- "$state"
readonly physical_state=$(cd -- "$state" && pwd -P)
[[ $physical_state == "$state" ]] || {
    echo "state directory is not one exact physical pathname" >&2
    exit 1
}

pid=
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 30); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "$pid" 2>/dev/null || true
    fi
    if [[ $status != 0 ]]; then
        printf 'result=refused\nexit_status=%s\n' "$status" >"$state/REFUSAL"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

ssh-keygen -q -t ed25519 -N '' -C crowned-store-20260829 -f "$state/ssh-identity"
public_key=$(<"$state/ssh-identity.pub")
cat >"$state/user-data" <<EOF
#cloud-config
users:
  - default
  - name: nqtest
    groups: [sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $public_key
ssh_pwauth: false
disable_root: true
package_update: false
package_upgrade: false
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
EOF
cat >"$state/meta-data" <<'EOF'
instance-id: crowned-store-vm-20260829-v2
local-hostname: crowned-store-vm-v2
EOF

(
    cd -- "$state"
    xorriso -as mkisofs -output "$state/seed.iso" -volid cidata -joliet -rock user-data meta-data
) >"$state/xorriso.stdout" 2>"$state/xorriso.stderr"
qemu-img create -f qcow2 -F qcow2 -b "$image" "$state/overlay.qcow2" "$EXPECTED_OVERLAY_BYTES" \
    >"$state/qemu-img-create.stdout" 2>"$state/qemu-img-create.stderr"

qemu-system-x86_64 \
    -name crowned-store-vm-v2,process=crowned-store-vm-v2 \
    -no-user-config -nodefaults -accel kvm -machine q35 -cpu host \
    -smp "$EXPECTED_VCPUS" -m "$EXPECTED_MEMORY_MIB" \
    -display none -monitor none -serial "file:$state/serial.log" \
    -pidfile "$state/qemu.pid" -rtc base=utc -boot order=c,strict=on \
    -drive "if=virtio,file=$state/overlay.qcow2,format=qcow2,cache=none,aio=native" \
    -drive "if=ide,index=2,media=cdrom,file=$state/seed.iso,format=raw,readonly=on" \
    -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$port-:22" \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:43:53:32 \
    -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
    -smbios type=1,serial=CROWNED-STORE-20260829-V2 -daemonize
pid=$(<"$state/qemu.pid")
[[ $pid =~ ^[0-9]+$ ]] || { echo "QEMU did not record a PID" >&2; exit 1; }

for _ in $(seq 1 180); do
    if ssh-keyscan -T 2 -p "$port" 127.0.0.1 >"$state/known_hosts.candidate" 2>/dev/null && \
       grep -q 'ssh-ed25519' "$state/known_hosts.candidate"; then
        mv "$state/known_hosts.candidate" "$state/known_hosts"
        break
    fi
    sleep 2
done
[[ -s $state/known_hosts ]] || { echo "guest SSH host key did not become available" >&2; exit 1; }

ssh_options=(
    -o BatchMode=yes -o IdentitiesOnly=yes
    -o "UserKnownHostsFile=$state/known_hosts" -o StrictHostKeyChecking=yes
    -o ConnectTimeout=5 -p "$port" -i "$state/ssh-identity"
)
for _ in $(seq 1 120); do
    if ssh "${ssh_options[@]}" nqtest@127.0.0.1 cloud-init status --wait \
        >"$state/cloud-init.stdout" 2>"$state/cloud-init.stderr"; then
        break
    fi
    sleep 2
done
grep -q 'status: done$' "$state/cloud-init.stdout" || {
    echo "cloud-init did not reach done" >&2
    exit 1
}

scp -o BatchMode=yes -o IdentitiesOnly=yes -o "UserKnownHostsFile=$state/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -P "$port" -i "$state/ssh-identity" "$deb" nqtest@127.0.0.1:/home/nqtest/crowned-store-nq-ng.deb
scp -o BatchMode=yes -o IdentitiesOnly=yes -o "UserKnownHostsFile=$state/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -P "$port" -i "$state/ssh-identity" "$driver" nqtest@127.0.0.1:/home/nqtest/crowned-store-guest-driver.py
ssh "${ssh_options[@]}" nqtest@127.0.0.1 \
    'hostnamectl --static; nproc; awk '\''/MemTotal/ {print $2 * 1024}'\'' /proc/meminfo; dpkg-query -W nq-ng 2>/dev/null || true' \
    >"$state/entry-facts.stdout" 2>"$state/entry-facts.stderr"

set +e
ssh "${ssh_options[@]}" nqtest@127.0.0.1 \
    'sudo timeout --signal=TERM --kill-after=30s 1200s python3 /home/nqtest/crowned-store-guest-driver.py' \
    >"$state/guest-driver.stdout" 2>"$state/guest-driver.stderr"
driver_status=$?
set -e

ssh "${ssh_options[@]}" nqtest@127.0.0.1 \
    'if sudo test -d /var/tmp/crowned-store-authority-lifecycle-successor-v1-results; then sudo tar --exclude=revoked-generation-signing-key -C /var/tmp -cf /home/nqtest/terminal-evidence.tar crowned-store-authority-lifecycle-successor-v1-results; sudo chown nqtest:nqtest /home/nqtest/terminal-evidence.tar; fi'
if ssh "${ssh_options[@]}" nqtest@127.0.0.1 test -f /home/nqtest/terminal-evidence.tar; then
    scp -o BatchMode=yes -o IdentitiesOnly=yes -o "UserKnownHostsFile=$state/known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -P "$port" -i "$state/ssh-identity" nqtest@127.0.0.1:/home/nqtest/terminal-evidence.tar "$state/terminal-evidence.tar"
fi
[[ $driver_status == 0 ]] || {
    echo "guest lifecycle refused with status $driver_status" >&2
    exit "$driver_status"
}

tar -tf "$state/terminal-evidence.tar" >"$state/terminal-evidence.members"
if grep -q 'revoked-generation-signing-key' "$state/terminal-evidence.members"; then
    echo "private signing key entered host evidence archive" >&2
    exit 1
fi
sha256sum -- "$state/terminal-evidence.tar" >"$state/terminal-evidence.sha256"

ssh "${ssh_options[@]}" nqtest@127.0.0.1 \
    'sudo systemctl is-active nqd.service nq-passive-load-observer.service nq-recurring-office.service nq-recurring-office.timer || true; sudo systemctl is-enabled nqd.service nq-recurring-office.timer || true; sudo shutdown -h now' \
    >"$state/closeout.stdout" 2>"$state/closeout.stderr" || true
for _ in $(seq 1 90); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
done
kill -0 "$pid" 2>/dev/null && { echo "VM did not power off" >&2; exit 1; }
pid=
qemu-img check "$state/overlay.qcow2" >"$state/qemu-img-check.stdout" 2>"$state/qemu-img-check.stderr"
printf 'result=pass\ncompleted_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$state/RESULT"
