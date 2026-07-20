#!/usr/bin/env bash
# Fail-closed Ubuntu Noble package lifecycle harness for nq-ng.
set -Eeuo pipefail
umask 077

readonly SCRATCH_CAP_BYTES=$((8 * 1024 * 1024 * 1024))
readonly MIN_FREE_KIB=$((12 * 1024 * 1024))
readonly DEFAULT_TIMEOUT=2700
readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

image= image_sha= deb= deb_sha= output=
check_guest_results= check_evidence_seal=
ssh_port=22222
timeout_seconds=$DEFAULT_TIMEOUT
preflight_only=false
output_ready=false
qemu_pid= watchdog_pid=
step=arguments

usage() {
    cat <<'EOF'
Usage: run-noble-qemu.sh --image IMAGE --image-sha256 SHA256 \
  --deb DIST_DEB --deb-sha256 SHA256 --output NEW_ABSOLUTE_DIRECTORY \
  [--ssh-port PORT] [--timeout-seconds 600..7200] [--preflight-only]

       run-noble-qemu.sh --check-guest-results DIRECTORY
       run-noble-qemu.sh --check-evidence-seal DIRECTORY

The bounded v1 harness accepts only a self-contained qcow2 Ubuntu 24.04 AMD64
cloud image and an amd64 nq-ng Debian package. Both exact hashes are mandatory.
EOF
}

refuse() {
    local reason=$1
    if $output_ready; then
        printf 'result=refused\nstep=%s\nreason=%s\n' "$step" "$reason" >"$output/REFUSAL"
    fi
    printf 'hardening harness refused at %s: %s\n' "$step" "$reason" >&2
    exit 1
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n $watchdog_pid ]]; then
        kill "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
    fi
    if [[ -n $qemu_pid ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill -TERM -- "-$qemu_pid" 2>/dev/null || kill -TERM "$qemu_pid" 2>/dev/null || true
        sleep 2
        kill -KILL -- "-$qemu_pid" 2>/dev/null || kill -KILL "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if ((status != 0)) && $output_ready && [[ ! -e $output/REFUSAL ]]; then
        printf 'result=refused\nstep=%s\nreason=unexpected exit %s\n' \
            "$step" "$status" >"$output/REFUSAL"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

digest_value() {
    local value=${1#sha256:}
    [[ $value =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$value"
}

need() { command -v "$1" >/dev/null 2>&1 || refuse "missing required command: $1"; }

regular_input() {
    [[ -f $1 && ! -L $1 ]] || refuse "$2 is not a regular non-symlink file: $1"
}

actual_hash() { sha256sum -- "$1" | awk '{print $1}'; }

check_hash() {
    local actual
    actual=$(actual_hash "$1")
    [[ $actual == "$2" ]] || refuse "$3 SHA-256 mismatch: expected $2, observed $actual"
}

free_kib() { df -Pk -- "$1" | awk 'NR == 2 {print $4}'; }

check_free() {
    local free
    free=$(free_kib "$1")
    [[ $free =~ ^[0-9]+$ ]] || refuse "cannot measure free space at $1"
    ((free >= MIN_FREE_KIB)) || refuse \
        "fewer than 12 GiB are free at $1 (${free} KiB available)"
}

scratch_bytes() { du -sx --block-size=1 -- "$output" | awk '{print $1}'; }

check_cap() {
    local used
    used=$(scratch_bytes)
    [[ $used =~ ^[0-9]+$ ]] || refuse "cannot measure scratch allocation"
    ((used <= SCRATCH_CAP_BYTES)) || refuse \
        "scratch allocation exceeded 8 GiB ($used bytes allocated)"
}

remaining() {
    local now
    now=$(date +%s)
    ((now < deadline)) || refuse "overall lifecycle deadline expired"
    printf '%s\n' "$((deadline - now))"
}

# Every guest qualification that must have run and passed. A missing or non-pass
# marker is failure; a guest-declared refusal is failure; absence is never pass.
readonly REQUIRED_GUEST_CHECKS=(
    AF_UNIX_CROSS_UID
    BYTE_TAMPER_REFUSAL
    HELPER_DRIFT_REFUSAL
    SOCKET_CONTRACT_REFUSAL
)

# Files whose bytes are directly consumed when a completed run is reopened for
# admission. They must be regular, non-symlink files and must occur in the seal;
# an otherwise self-consistent manifest over an incomplete run is not enough.
readonly REQUIRED_SEALED_EVIDENCE=(
    INPUTS
    nq-ng.deb
    guest-results/RESULT
    guest-results/REQUIRED_CHECKS
)

verify_guest_results() {
    local dir=$1 check
    [[ ! -e "$dir/GUEST_REFUSAL" ]] \
        || refuse "guest declared a refusal: $(tr '\n' ' ' <"$dir/GUEST_REFUSAL")"
    [[ -f "$dir/RESULT" ]] || refuse "guest result file is absent"
    [[ $(<"$dir/RESULT") == pass ]] || refuse "guest result is not exactly 'pass'"
    [[ -f "$dir/REQUIRED_CHECKS" ]] || refuse "guest required-checks file is absent"
    for check in "${REQUIRED_GUEST_CHECKS[@]}"; do
        grep -qx "$check=pass" "$dir/REQUIRED_CHECKS" \
            || refuse "mandatory guest qualification $check is absent or not pass"
    done
}

# Emit the one canonical manifest for a run directory. Only the three
# intentionally post-seal/top-level files are outside its inventory. In
# particular, a RESULT at any depth below the run root is evidence and is
# sealed.
canonical_evidence_manifest() {
    local dir=$1
    (
        cd -- "$dir"
        find . -type f \
            ! -path './ARTIFACTS.sha256' \
            ! -path './RESULT' \
            ! -path './seal.log' \
            -print0 \
            | LC_ALL=C sort -z \
            | xargs -0 -r sha256sum
    )
}

require_exact_physical_evidence_root() {
    local dir=$1 physical
    [[ $dir == /* ]] \
        || refuse "evidence root is not an exact physical absolute directory: $dir"
    physical=$(cd -- "$dir" 2>/dev/null && pwd -P) \
        || refuse "evidence root is not an exact physical absolute directory: $dir"
    [[ $dir == "$physical" && -d $dir && ! -L $dir ]] \
        || refuse "evidence root is not an exact physical absolute directory: $dir"
}

verify_evidence_seal() {
    local dir=$1 evidence unexpected actual_manifest_hash expected_manifest_hash
    # Bind reopening to one physical run-directory identity. Besides direct
    # symlinks, this rejects aliases through symlinked ancestors, trailing
    # slashes, and dot components that can defeat a leaf-only `-L` check.
    require_exact_physical_evidence_root "$dir"
    [[ -f $dir/ARTIFACTS.sha256 && ! -L $dir/ARTIFACTS.sha256 ]] \
        || refuse "artifact manifest is not a regular non-symlink file"
    [[ -d $dir/guest-results && ! -L $dir/guest-results ]] \
        || refuse "guest-results is not a non-symlink directory"
    for evidence in "${REQUIRED_SEALED_EVIDENCE[@]}"; do
        [[ -f $dir/$evidence && ! -L $dir/$evidence ]] \
            || refuse "required sealed evidence is not a regular non-symlink file: ./$evidence"
    done
    unexpected=$(find "$dir" ! -type d ! -type f -print -quit) \
        || refuse "cannot inspect evidence entry types"
    [[ -z $unexpected ]] \
        || refuse "evidence tree contains a non-regular entry: $unexpected"
    verify_guest_results "$dir/guest-results"
    actual_manifest_hash=$(actual_hash "$dir/ARTIFACTS.sha256") \
        || refuse "cannot hash artifact manifest"
    expected_manifest_hash=$(canonical_evidence_manifest "$dir" \
        | sha256sum | awk '{print $1}') \
        || refuse "cannot recompute canonical artifact manifest"
    [[ $actual_manifest_hash == "$expected_manifest_hash" ]] \
        || refuse "artifact manifest is not an exact canonical inventory of sealed evidence"
    # Check coverage before following any path written in the manifest. Exact
    # byte equality with the canonical inventory confines every check target to
    # a regular file found below the run root.
    (cd -- "$dir" && sha256sum --strict --quiet --check ARTIFACTS.sha256) \
        || refuse "artifact manifest did not verify"
}

# The write-last top-level RESULT is intentionally outside the cryptographic
# inventory, but a read-only reopening of a completed run must still admit its
# semantics. Extra operator-note lines are allowed; contradictory, duplicate,
# absent, empty, or symlinked completion fields are not.
verify_completed_result() {
    local dir=$1
    [[ ! -e $dir/REFUSAL && ! -L $dir/REFUSAL ]] \
        || refuse "completed run contains a top-level refusal"
    [[ -f $dir/RESULT && ! -L $dir/RESULT ]] \
        || refuse "top-level result is not a regular non-symlink file"
    awk '
        $0 == "result=pass" { pass += 1; next }
        /^result=/ { contradictory = 1; next }
        /^completed_at=/ {
            completed_fields += 1
            if ($0 ~ /^completed_at=[0-9][0-9][0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$/) {
                completed_valid += 1
            }
            next
        }
        END {
            exit !(pass == 1 && contradictory == 0 &&
                   completed_fields == 1 && completed_valid == 1)
        }
    ' "$dir/RESULT" \
        || refuse "top-level result is not one unambiguous completed pass"
}

while (($#)); do
    case $1 in
        --image) image=${2-}; shift 2 ;;
        --image-sha256) image_sha=${2-}; shift 2 ;;
        --deb) deb=${2-}; shift 2 ;;
        --deb-sha256) deb_sha=${2-}; shift 2 ;;
        --output) output=${2-}; shift 2 ;;
        --ssh-port) ssh_port=${2-}; shift 2 ;;
        --timeout-seconds) timeout_seconds=${2-}; shift 2 ;;
        --preflight-only) preflight_only=true; shift ;;
        --check-guest-results) check_guest_results=${2-}; shift 2 ;;
        --check-evidence-seal) check_evidence_seal=${2-}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# Deterministic host-side self-check of the guest-result verifier: no VM, no
# staging. Used by the static test harness to exercise every failure path.
if [[ -n $check_guest_results ]]; then
    step=guest-result-selfcheck
    verify_guest_results "$check_guest_results"
    printf 'guest results verified: %s\n' "$check_guest_results"
    exit 0
fi

# Read-only, independently invocable reopening check for a completed evidence
# directory. The static harness uses it to exercise hostile manifest cases.
if [[ -n $check_evidence_seal ]]; then
    step=evidence-seal-selfcheck
    require_exact_physical_evidence_root "$check_evidence_seal"
    verify_completed_result "$check_evidence_seal"
    verify_evidence_seal "$check_evidence_seal"
    printf 'evidence seal verified: %s\n' "$check_evidence_seal"
    exit 0
fi

[[ -n $image && -n $image_sha && -n $deb && -n $deb_sha && -n $output ]] || {
    usage >&2
    exit 2
}
[[ $ssh_port =~ ^[0-9]+$ ]] && ((ssh_port >= 1024 && ssh_port <= 65535)) || {
    printf 'invalid SSH port: %s\n' "$ssh_port" >&2
    exit 2
}
[[ $timeout_seconds =~ ^[0-9]+$ ]] \
    && ((timeout_seconds >= 600 && timeout_seconds <= 7200)) || {
    printf 'timeout must be 600..7200 seconds\n' >&2
    exit 2
}
image_sha=$(digest_value "$image_sha") || { printf 'invalid image SHA-256\n' >&2; exit 2; }
deb_sha=$(digest_value "$deb_sha") || { printf 'invalid Debian SHA-256\n' >&2; exit 2; }

step=output-custody
[[ $output = /* ]] || refuse "output path must be absolute"
[[ ! -e $output && ! -L $output ]] || refuse "output path already exists: $output"
output_parent=$(dirname -- "$output")
[[ -d $output_parent && ! -L $output_parent ]] || refuse \
    "output parent is not an existing non-symlink directory: $output_parent"
check_free "$output_parent"
mkdir -m 0700 -- "$output" || refuse "cannot create output directory"
output_ready=true
exec > >(tee -a "$output/host.log") 2>&1
printf 'started_at=%s\nscratch_cap_bytes=%s\nminimum_free_kib=%s\n' \
    "$(date --iso-8601=seconds)" "$SCRATCH_CAP_BYTES" "$MIN_FREE_KIB"

step=prerequisites
for command in awk cp date df dpkg-deb du find grep mkdir mv python3 qemu-img \
    qemu-system-x86_64 scp setsid sha256sum sort ssh ssh-keygen ss stat sync timeout xargs xorriso; do
    need "$command"
done

step=input-custody
regular_input "$image" "Ubuntu cloud image"
regular_input "$deb" "nq-ng Debian artifact"
check_hash "$image" "$image_sha" "Ubuntu cloud image"
check_hash "$deb" "$deb_sha" "nq-ng Debian artifact"

package=$(dpkg-deb -f "$deb" Package)
version=$(dpkg-deb -f "$deb" Version)
architecture=$(dpkg-deb -f "$deb" Architecture)
[[ $package == nq-ng ]] || refuse "Debian package is $package, not nq-ng"
[[ -n $version ]] || refuse "Debian package version is empty"
[[ $architecture == amd64 ]] || refuse "v1 harness requires amd64, observed $architecture"

image_info=$(qemu-img info --output=json -- "$image") || refuse "qemu-img info failed"
image_format=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("format", ""))' \
    <<<"$image_info")
image_size=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("virtual-size", ""))' \
    <<<"$image_info")
image_backing=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("backing-filename", ""))' \
    <<<"$image_info")
[[ $image_format == qcow2 ]] || refuse "cloud image format is $image_format, not qcow2"
[[ $image_size =~ ^[0-9]+$ ]] || refuse "cloud image lacks a numeric virtual size"
((image_size <= SCRATCH_CAP_BYTES)) || refuse "cloud image virtual size exceeds 8 GiB"
[[ -z $image_backing ]] || refuse "cloud image has an external backing file"
qemu-img check -- "$image" || refuse "qemu-img check rejected the cloud image"
ss -H -ltn "sport = :$ssh_port" | grep -q . \
    && refuse "loopback SSH port $ssh_port is already in use"
check_free "$output"
check_cap

{
    printf 'schema=nq.hardening.inputs.v1\n'
    printf 'image=%s\nimage_sha256=%s\nimage_virtual_size=%s\n' \
        "$image" "$image_sha" "$image_size"
    printf 'deb=%s\ndeb_sha256=%s\npackage=%s\nversion=%s\narchitecture=%s\n' \
        "$deb" "$deb_sha" "$package" "$version" "$architecture"
    stat -c 'image_stat=dev:%d inode:%i size:%s mode:%a uid:%u gid:%g' -- "$image"
    stat -c 'deb_stat=dev:%d inode:%i size:%s mode:%a uid:%u gid:%g' -- "$deb"
    qemu-img --version | head -n 1
    qemu-system-x86_64 --version | head -n 1
    xorriso -version 2>&1 | head -n 1
} >"$output/INPUTS"

if $preflight_only; then
    step=preflight-complete
    printf 'result=preflight_passed\n' >"$output/PREFLIGHT"
    exit 0
fi

deadline=$(($(date +%s) + timeout_seconds))

step=stage-inputs
cp --reflink=never --sparse=always -- "$image" "$output/base.qcow2.partial"
chmod 0444 "$output/base.qcow2.partial"
mv "$output/base.qcow2.partial" "$output/base.qcow2"
check_hash "$output/base.qcow2" "$image_sha" "staged image"
check_hash "$image" "$image_sha" "source image after staging"
cp --reflink=never -- "$deb" "$output/nq-ng.deb.partial"
chmod 0444 "$output/nq-ng.deb.partial"
mv "$output/nq-ng.deb.partial" "$output/nq-ng.deb"
check_hash "$output/nq-ng.deb" "$deb_sha" "staged Debian artifact"
check_hash "$deb" "$deb_sha" "source Debian artifact after staging"
check_cap

step=overlay
qemu-img create -q -f qcow2 -F qcow2 -b "$output/base.qcow2" \
    "$output/overlay.qcow2.partial" 8G
mv "$output/overlay.qcow2.partial" "$output/overlay.qcow2"
qemu-img check "$output/overlay.qcow2"
check_cap

step=nocloud-seed
ssh-keygen -q -t ed25519 -N '' -C nq-hardening-ephemeral -f "$output/ssh-identity"
public_key=$(<"$output/ssh-identity.pub")
cat >"$output/meta-data" <<'EOF'
instance-id: nq-ng-hardening-noble-v1
local-hostname: nq-hardening
EOF
cat >"$output/user-data" <<EOF
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
EOF
xorriso -as mkisofs -quiet -output "$output/seed.iso.partial" \
    -volid cidata -joliet -rock "$output/user-data" "$output/meta-data"
mv "$output/seed.iso.partial" "$output/seed.iso"
chmod 0444 "$output/seed.iso"
check_cap

step=acceleration
acceleration=tcg,thread=multi
cpu=max
if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] \
    && qemu-system-x86_64 -accel help 2>&1 | grep -qx kvm; then
    acceleration=kvm
    cpu=host
fi
printf 'acceleration=%s\ncpu=%s\n' "$acceleration" "$cpu" >"$output/QEMU_MODE"

step=qemu-start
(
    # Bash expresses `ulimit -f` in 1024-byte blocks.
    ulimit -f $((SCRATCH_CAP_BYTES / 1024))
    exec setsid qemu-system-x86_64 \
        -name nq-ng-hardening-noble -machine q35 -accel "$acceleration" -cpu "$cpu" \
        -m 2048 -smp 2 -nodefaults -display none -monitor none \
        -serial "file:$output/serial.log" \
        -device virtio-scsi-pci,id=scsi0 \
        -drive "file=$output/overlay.qcow2,if=none,id=root,format=qcow2,cache=none,aio=threads" \
        -device scsi-hd,drive=root,bootindex=1 \
        -drive "file=$output/seed.iso,if=none,id=seed,format=raw,readonly=on" \
        -device scsi-cd,drive=seed \
        -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
        -device virtio-net-pci,netdev=net0 -no-hpet
) >"$output/qemu.stdout.log" 2>"$output/qemu.stderr.log" &
qemu_pid=$!
printf '%s\n' "$qemu_pid" >"$output/qemu.pid"

(
    while kill -0 "$qemu_pid" 2>/dev/null; do
        used=$(scratch_bytes)
        if [[ ! $used =~ ^[0-9]+$ ]] || ((used > SCRATCH_CAP_BYTES)); then
            printf 'observed=%s\nlimit=%s\n' "$used" "$SCRATCH_CAP_BYTES" \
                >"$output/SCRATCH_CAP_REFUSAL"
            kill -TERM -- "-$qemu_pid" 2>/dev/null \
                || kill -TERM "$qemu_pid" 2>/dev/null || true
            exit 1
        fi
        sleep 1
    done
) &
watchdog_pid=$!

ssh_opts=(
    -i "$output/ssh-identity" -p "$ssh_port" -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$output/ssh-known-hosts"
    -o ConnectTimeout=5 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
)
scp_opts=(
    -i "$output/ssh-identity" -P "$ssh_port" -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$output/ssh-known-hosts"
    -o ConnectTimeout=5 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
)

# Evidence custody on the failure path. A guest phase that fails takes its
# diagnostics with it: cleanup destroys the VM, so anything the guest wrote under
# $RESULTS — including the exact refusal text a qualification asserted on — is
# lost before an operator can read it. Pull it first.
#
# This is diagnostic-only and MUST NOT touch the verdict. It never calls refuse,
# never writes REFUSAL or RESULT, always returns 0, and lands in a directory the
# sealing path does not read, so a retrieval can neither create nor repair a
# pass. Its own failure is recorded beside the verdict as a secondary
# evidence-custody note, never in place of the original refusal.
preserve_guest_evidence() {
    local phase=$1 dest=$output/failed-guest-results
    # Every path returns 0. This runs with set -e active on the failure path, so
    # anything that propagates a non-zero status would replace the very verdict
    # this function exists to preserve.
    $output_ready || return 0
    if [[ -e $dest ]]; then return 0; fi
    mkdir -m 0700 -p "$dest" 2>/dev/null || return 0
    # A fixed bound, not remaining(): the deadline may already be blown, and
    # remaining() refuses — which would hijack the verdict being preserved.
    if {
        printf '\n===== preserve-evidence %s %s =====\n' "$phase" "$(date --iso-8601=seconds)"
        timeout 120 scp "${scp_opts[@]}" -r \
            nqtest@127.0.0.1:/var/tmp/nq-hardening-results/. "$dest/"
    } >>"$output/ssh-session.log" 2>&1; then
        printf 'result=retrieved\nphase=%s\npath=failed-guest-results\n' \
            "$phase" >"$output/EVIDENCE_CUSTODY"
    else
        printf 'result=unretrieved\nphase=%s\nreason=scp from the failed guest failed\n' \
            "$phase" >"$output/EVIDENCE_CUSTODY_FAILURE"
    fi
    return 0
}

wait_ssh() {
    local expected=$1 limit=$2 start=$SECONDS budget
    # Never wait past the overall lifecycle deadline: bound the phase limit by
    # the remaining budget (remaining() itself refuses once the deadline passes).
    budget=$(remaining)
    ((limit <= budget)) || limit=$budget
    while ((SECONDS - start < limit)); do
        kill -0 "$qemu_pid" 2>/dev/null || refuse "QEMU exited while waiting for SSH $expected"
        if timeout 10 ssh "${ssh_opts[@]}" nqtest@127.0.0.1 true \
            >>"$output/ssh-readiness.log" 2>&1; then
            [[ $expected == up ]] && return 0
        else
            [[ $expected == down ]] && return 0
        fi
        sleep 2
    done
    refuse "SSH did not become $expected within $limit seconds"
}

ssh_run() {
    local label=$1
    shift
    {
        printf '\n===== %s %s =====\n' "$label" "$(date --iso-8601=seconds)"
        timeout "$(remaining)" ssh "${ssh_opts[@]}" nqtest@127.0.0.1 "$@"
    } >>"$output/ssh-session.log" 2>&1
}

step=cloud-init
wait_ssh up 900
ssh_run cloud-init 'cloud-init status --wait && test -f /var/lib/cloud/instance/boot-finished'
ssh_run noble-version \
    'test "$(. /etc/os-release && printf %s "$ID:$VERSION_ID")" = ubuntu:24.04'

step=upload
regular_input "$SCRIPT_DIR/guest-lifecycle.sh" "guest lifecycle driver"
guest_driver_sha=$(actual_hash "$SCRIPT_DIR/guest-lifecycle.sh")
printf 'guest_driver_sha256=%s\n' "$guest_driver_sha" >>"$output/INPUTS"
{
    printf '\n===== upload %s =====\n' "$(date --iso-8601=seconds)"
    timeout "$(remaining)" scp "${scp_opts[@]}" \
        "$output/nq-ng.deb" "$SCRIPT_DIR/guest-lifecycle.sh" \
        nqtest@127.0.0.1:/home/nqtest/
} >>"$output/ssh-session.log" 2>&1

step=guest-before-reboot
set +e
timeout "$(remaining)" ssh "${ssh_opts[@]}" nqtest@127.0.0.1 \
    "sudo -- /home/nqtest/guest-lifecycle.sh before-reboot /home/nqtest/nq-ng.deb $deb_sha $guest_driver_sha" \
    >>"$output/ssh-session.log" 2>&1
before_status=$?
set -e
printf 'before_reboot_ssh_status=%s\n' "$before_status" >>"$output/ssh-session.log"
# The before-reboot phase ends in `systemctl reboot`, so SSH status 255 (dropped
# connection) is expected here and ONLY here. Any other non-zero status is a
# failure, and a 255 is accepted only provisionally: the reboot itself must then
# be independently confirmed below (SSH goes down and back up, boot id changes,
# and the guest's BEFORE_REBOOT_COMPLETE marker is present). A 255 that was not
# actually an expected reboot fails those checks.
if ((before_status != 0 && before_status != 255)); then
    preserve_guest_evidence before-reboot
    refuse "before-reboot guest phase failed with SSH status $before_status"
fi

step=reboot
wait_ssh down 180
wait_ssh up 900
ssh_run reboot-marker 'sudo test -f /var/tmp/nq-hardening-results/BEFORE_REBOOT_COMPLETE'

step=guest-after-reboot
set +e
ssh_run after-reboot \
    "sudo -- /home/nqtest/guest-lifecycle.sh after-reboot /home/nqtest/nq-ng.deb $deb_sha $guest_driver_sha"
after_status=$?
set -e
if ((after_status != 0)); then
    # Preserve the guest's diagnostics, then re-raise the identical failure: the
    # cleanup trap writes the same REFUSAL (step, and "unexpected exit N") it
    # would have written had this phase simply tripped set -e.
    preserve_guest_evidence after-reboot
    exit "$after_status"
fi

step=retrieve-results
mkdir -m 0700 "$output/guest-results"
{
    printf '\n===== retrieve %s =====\n' "$(date --iso-8601=seconds)"
    timeout "$(remaining)" scp "${scp_opts[@]}" -r \
        nqtest@127.0.0.1:/var/tmp/nq-hardening-results/. "$output/guest-results/"
} >>"$output/ssh-session.log" 2>&1
verify_guest_results "$output/guest-results"

step=poweroff
set +e
timeout 30 ssh "${ssh_opts[@]}" nqtest@127.0.0.1 'sudo systemctl poweroff' \
    >>"$output/ssh-session.log" 2>&1
set -e
for _ in {1..120}; do
    kill -0 "$qemu_pid" 2>/dev/null || break
    sleep 1
done
kill -0 "$qemu_pid" 2>/dev/null && refuse "QEMU did not exit after poweroff"
wait "$qemu_pid"
qemu_pid=
wait "$watchdog_pid" || refuse "scratch-cap watchdog failed"
watchdog_pid=
check_cap

step=verify-disk
# The overlay must remain a consistent qcow2 after clean shutdown.
qemu-img check -- "$output/overlay.qcow2" || refuse "post-shutdown overlay disk check failed"

step=seal-evidence
rm -f "$output/ssh-identity"
# Freeze host.log by stopping the tee, so the log is complete and stable before
# it is hashed. Post-seal harness output goes to seal.log, which is deliberately
# outside the sealed manifest.
exec >>"$output/seal.log" 2>&1
sync
# Manifest over every sealed artifact (the frozen host.log included), excluding
# only the top-level manifest itself, the not-yet-written top-level pass marker,
# and the top-level post-seal log. Nested files with any of those basenames are
# evidence and remain inside the seal.
canonical_evidence_manifest "$output" >"$output/ARTIFACTS.sha256"
# No pass marker may exist until the manifest verifies.
verify_evidence_seal "$output"
# The pass marker is written last: an early, partial, or failed run cannot
# produce a result that appears sealed.
printf 'result=pass\ncompleted_at=%s\n' "$(date --iso-8601=seconds)" >"$output/RESULT"
printf 'hardening lifecycle passed; evidence retained at %s\n' "$output"
