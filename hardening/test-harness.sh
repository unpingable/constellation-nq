#!/usr/bin/env bash
# Static contract checks plus one deliberately refused local preflight.
set -Eeuo pipefail
umask 077

readonly HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
host=$HERE/run-noble-qemu.sh
guest=$HERE/guest-lifecycle.sh

bash -n "$host"
bash -n "$guest"

require_text() {
    grep -F -- "$2" "$1" >/dev/null || {
        printf 'missing hardening invariant %q in %s\n' "$2" "$1" >&2
        exit 1
    }
}

require_text "$host" 'SCRATCH_CAP_BYTES=$((8 * 1024 * 1024 * 1024))'
require_text "$host" 'MIN_FREE_KIB=$((12 * 1024 * 1024))'
require_text "$host" 'qemu-img create -q -f qcow2 -F qcow2'
require_text "$host" 'xorriso -as mkisofs'
require_text "$host" 'acceleration=tcg,thread=multi'
require_text "$host" 'acceleration=kvm'
require_text "$host" 'ulimit -f $((SCRATCH_CAP_BYTES / 1024))'
require_text "$host" '-P "$ssh_port"'
require_text "$host" '-serial "file:$output/serial.log"'
require_text "$host" 'restrict=on,hostfwd=tcp:127.0.0.1:'
require_text "$host" 'before_status != 0 && before_status != 255'
require_text "$host" 'AF_UNIX_CROSS_UID=pass'
require_text "$host" 'BYTE_TAMPER_REFUSAL=pass'
require_text "$guest" 'carrier = "unix"'
require_text "$guest" 'run_nq witness test conformance-local'
require_text "$guest" 'run_nq witness admit conformance-local'
require_text "$guest" 'run_nq collect conformance-local'
require_text "$guest" 'reports_after_restart=$(admitted_report_count)'
require_text "$guest" 'wait_for_admitted_report_after "$reports_after_restart" service-restart'
require_text "$guest" 'reports_after_reboot=$(admitted_report_count)'
require_text "$guest" 'wait_for_admitted_report_after "$reports_after_reboot" service-reboot'
require_text "$guest" 'dpkg --remove nq-ng'
require_text "$guest" 'dpkg --purge nq-ng'
require_text "$guest" 'systemctl reboot'
require_text "$guest" "grep -F 'binary drift'"
require_text "$guest" '/usr/share/nq/system-contract/manifest.json'
require_text "$guest" '/usr/share/nq/profiles/nq.conformance.v1.json'
require_text "$guest" 'systemctl start nqd.service >"$RESULTS/$label-tamper-start.log"'
require_text "$guest" 'HELPER_DRIFT_REFUSAL=pass'

if grep -Ei 'skip(ped|ping)? (cross-uid|af_unix)|AF_UNIX.*skip' "$guest" >/dev/null; then
    printf 'guest lifecycle contains a forbidden cross-UID skip path\n' >&2
    exit 1
fi

scratch=$(mktemp -d /tmp/nq-hardening-static.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
missing_image=$scratch/missing-noble.qcow2
missing_deb=$scratch/missing-nq-ng.deb
set +e
"$host" \
    --image "$missing_image" \
    --image-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
    --deb "$missing_deb" \
    --deb-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
    --output "$scratch/refusal" \
    --preflight-only >"$scratch/preflight.stdout" 2>"$scratch/preflight.stderr"
status=$?
set -e
((status != 0)) || {
    printf 'missing-input preflight unexpectedly succeeded\n' >&2
    exit 1
}
grep -qx 'result=refused' "$scratch/refusal/REFUSAL"
grep -qx 'step=input-custody' "$scratch/refusal/REFUSAL"
grep -F 'Ubuntu cloud image is not a regular non-symlink file' \
    "$scratch/refusal/REFUSAL" >/dev/null

printf 'hardening harness syntax/static checks passed; local preflight refused missing image as required\n'
