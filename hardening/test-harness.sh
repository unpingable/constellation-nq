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
# SSH status 255 must be accepted only as an expected reboot, and only when that
# reboot is then independently confirmed — never as broad acceptance.
require_text "$host" 'expected here and ONLY here'
require_text "$host" 'BEFORE_REBOOT_COMPLETE'
require_text "$host" 'verify_guest_results "$output/guest-results"'
require_text "$host" 'qemu-img check -- "$output/overlay.qcow2"'
require_text "$host" 'guest_driver_sha=$(actual_hash'
require_text "$guest" 'guest lifecycle driver bytes differ from host-bound digest'
# The host enforces these guest qualifications by name; the guest emits the pass
# markers.
require_text "$host" 'AF_UNIX_CROSS_UID'
require_text "$host" 'BYTE_TAMPER_REFUSAL'
require_text "$host" 'HELPER_DRIFT_REFUSAL'
require_text "$guest" 'AF_UNIX_CROSS_UID=pass'
require_text "$guest" 'BYTE_TAMPER_REFUSAL=pass'
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

# --- Deterministic host-side negatives for the sealing logic (no VM). ---

# A complete, passing guest-result set verifies.
gr_valid=$scratch/gr-valid
mkdir -p "$gr_valid"
printf 'pass\n' >"$gr_valid/RESULT"
printf 'AF_UNIX_CROSS_UID=pass\nBYTE_TAMPER_REFUSAL=pass\nHELPER_DRIFT_REFUSAL=pass\n' \
    >"$gr_valid/REQUIRED_CHECKS"
"$host" --check-guest-results "$gr_valid" >/dev/null \
    || { printf 'valid guest results were rejected\n' >&2; exit 1; }

expect_guest_refusal() {
    local dir=$1 needle=$2 status
    set +e
    "$host" --check-guest-results "$dir" >"$scratch/gr.out" 2>"$scratch/gr.err"
    status=$?
    set -e
    ((status != 0)) || {
        printf 'guest-result check unexpectedly passed for %s\n' "$dir" >&2
        exit 1
    }
    grep -F -- "$needle" "$scratch/gr.err" >/dev/null || {
        printf 'guest-result refusal for %s did not mention %q\n' "$dir" "$needle" >&2
        exit 1
    }
}

# A guest-declared refusal is failure, never pass.
gr_refused=$scratch/gr-refused
cp -r "$gr_valid" "$gr_refused"
printf 'result=refused\ncheck=cross-uid\n' >"$gr_refused/GUEST_REFUSAL"
expect_guest_refusal "$gr_refused" 'guest declared a refusal'

# A non-pass or malformed RESULT is failure.
gr_notpass=$scratch/gr-notpass
cp -r "$gr_valid" "$gr_notpass"
printf 'partial\n' >"$gr_notpass/RESULT"
expect_guest_refusal "$gr_notpass" "not exactly 'pass'"

# A missing mandatory qualification is failure — absence is never pass.
gr_missing=$scratch/gr-missing
cp -r "$gr_valid" "$gr_missing"
printf 'AF_UNIX_CROSS_UID=pass\n' >"$gr_missing/REQUIRED_CHECKS"
expect_guest_refusal "$gr_missing" 'mandatory guest qualification'

# A missing result file is failure.
gr_noresult=$scratch/gr-noresult
cp -r "$gr_valid" "$gr_noresult"
rm -f "$gr_noresult/RESULT"
expect_guest_refusal "$gr_noresult" 'guest result file is absent'

# A real staged input with the wrong declared hash is refused.
real_input=$scratch/real.bin
head -c 4096 /dev/zero >"$real_input"
zero_hash=0000000000000000000000000000000000000000000000000000000000000000
set +e
"$host" --image "$real_input" --image-sha256 "$zero_hash" \
    --deb "$real_input" --deb-sha256 "$zero_hash" \
    --output "$scratch/badhash" --preflight-only \
    >"$scratch/badhash.out" 2>"$scratch/badhash.err"
status=$?
set -e
((status != 0)) || { printf 'bad-hash preflight unexpectedly succeeded\n' >&2; exit 1; }
grep -F 'SHA-256 mismatch' "$scratch/badhash/REFUSAL" >/dev/null

# A pre-existing output directory (e.g. a stale pass marker) is refused: a pass
# can never be produced into an existing path.
stale=$scratch/stale-out
mkdir -p "$stale"
printf 'result=pass\n' >"$stale/RESULT"
real_hash=$(sha256sum "$real_input" | awk '{print $1}')
set +e
"$host" --image "$real_input" --image-sha256 "$real_hash" \
    --deb "$real_input" --deb-sha256 "$real_hash" \
    --output "$stale" --preflight-only \
    >"$scratch/stale.out" 2>"$scratch/stale.err"
status=$?
set -e
((status != 0)) || { printf 'stale-output run unexpectedly succeeded\n' >&2; exit 1; }
grep -F 'output path already exists' "$scratch/stale.err" >/dev/null

printf 'hardening harness syntax/static checks passed; guest-result, bad-hash, and stale-output negatives refused as required\n'
