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
require_text "$host" 'SOCKET_CONTRACT_REFUSAL'
require_text "$guest" 'AF_UNIX_CROSS_UID=pass'
require_text "$guest" 'BYTE_TAMPER_REFUSAL=pass'
# The non-conforming-socket qualification must exercise the production
# supervisor and assert the exact refused predicate, not a generic failure.
require_text "$guest" 'SOCKET_CONTRACT_REFUSAL=pass'
require_text "$guest" 'run_nq witness test hostile-socket-local'
require_text "$guest" "grep -F 'helper socket mode is'"
require_text "$guest" 'supervisor accepted a non-conforming helper socket'
require_text "$guest" 'a report was admitted after a refused socket'
require_text "$guest" 'os.chmod(path, 0o660)'
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
# A package transaction must invalidate the admitted execution identity, and
# re-admission must stay an explicit operator act.
require_text "$guest" 'reinstall after purge did not invalidate the admitted execution identity'
require_text "$guest" 'run_nq witness rotate conformance-local'
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
printf 'AF_UNIX_CROSS_UID=pass\nBYTE_TAMPER_REFUSAL=pass\nHELPER_DRIFT_REFUSAL=pass\nSOCKET_CONTRACT_REFUSAL=pass\n' \
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

# The non-conforming-socket qualification is enforced specifically: a run that
# omits it, or reports it as anything but pass, cannot seal.
gr_nosocket=$scratch/gr-nosocket
cp -r "$gr_valid" "$gr_nosocket"
grep -v '^SOCKET_CONTRACT_REFUSAL=' "$gr_valid/REQUIRED_CHECKS" \
    >"$gr_nosocket/REQUIRED_CHECKS"
expect_guest_refusal "$gr_nosocket" 'SOCKET_CONTRACT_REFUSAL'

gr_socketfail=$scratch/gr-socketfail
cp -r "$gr_valid" "$gr_socketfail"
sed 's/^SOCKET_CONTRACT_REFUSAL=pass$/SOCKET_CONTRACT_REFUSAL=fail/' \
    "$gr_valid/REQUIRED_CHECKS" >"$gr_socketfail/REQUIRED_CHECKS"
expect_guest_refusal "$gr_socketfail" 'SOCKET_CONTRACT_REFUSAL'

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

# --- An asserted attempt must retain its stream, status, and execution context. ---
#
# A refusal assertion that greps a shell variable, a pipe, or a process
# substitution destroys the evidence it is judging: when the assertion fails,
# the operator is told the message was wrong but never what it was. But the
# stream alone is not enough. A "silent non-zero" -- an attempt that exits
# non-zero having printed nothing -- is underdetermined without its numeric
# status and, when it ran through a transient systemd unit, that unit's journal:
# the service's own output went to the --pipe, while systemd's manager-side
# records (exec failure, sandbox step failure, killed vs exited) reach only the
# journal under the unit name, which --collect reaps from live state.
#
# So an asserted attempt is preserved only if its stream, status, and execution
# context are all retained in $RESULTS.
python3 - "$guest" <<'CHECK'
import re
import sys

guest = open(sys.argv[1], encoding="utf-8").read()
lines = guest.splitlines()
problems = []

# Region boundaries: each check is introduced by `current_check=...`. Preserved
# artifacts for an attempt land after it, within the same check's region.
def region_end(index):
    for j in range(index + 1, len(lines)):
        if lines[j].strip().startswith("current_check="):
            return j
    return len(lines)

def region_has(start, end, *needles):
    for j in range(start, end):
        if all(n in lines[j] for n in needles):
            return True
    return False

for index, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("run_nq ") or stripped.startswith("systemctl start"):
        following = lines[index + 1].strip() if index + 1 < len(lines) else ""
        status_capture = following.endswith("=$?")
        asserted = status_capture or "||" in stripped
        if not asserted:
            continue
        end = region_end(index)
        # Stream: the attempt's stdout+stderr must be redirected to $RESULTS.
        if '>"$RESULTS/' not in stripped:
            problems.append(f"line {index + 1}: asserted attempt discards its stream: {stripped}")
        # Status: the captured numeric status must itself be written durably.
        if status_capture:
            statusvar = following.split("=", 1)[0].strip()
            if not region_has(index, end, f'"${statusvar}"', '>"$RESULTS/'):
                problems.append(
                    f"line {index + 1}: asserted attempt discards its status ${statusvar}: {stripped}")
        # Execution context: an attempt run through a transient systemd unit
        # (run_nq) must capture that unit's journal into $RESULTS, keyed on the
        # recorded unit variable. Requiring the journalctl to reference a `_unit`
        # variable folds unit identity into retrievability: it bites both when
        # the journal capture is dropped and when it stops naming the transient
        # unit (e.g. points at a fixed persistent unit instead).
        if stripped.startswith("run_nq "):
            if not region_has(index, end, "journalctl", "_unit", '>"$RESULTS/'):
                problems.append(
                    f"line {index + 1}: transient attempt discards its unit journal: {stripped}")
    # Grepping command substitution or a here-string of a command consumes
    # output that was never written down.
    if re.search(r"grep[^\n|]*<<<\s*\"?\$\(", stripped) or re.search(r"\$\([^)]*run_nq[^)]*\)\s*\|\s*grep", stripped):
        problems.append(f"line {index + 1}: assertion greps unpreserved output: {stripped}")

if problems:
    print("asserted attempts must preserve stream, status, and execution context:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    raise SystemExit(1)
CHECK

# The transient unit name must actually be recorded where an asserted attempt
# can capture it; without this assignment the unit-identity artifact is empty.
require_text "$guest" 'last_nq_unit=nq-hardening'

# The guest must flush refusal evidence: a refused run is killed without a
# guest shutdown, so unflushed diagnostics never reach the overlay.
require_text "$guest" 'sync || true'

# --- Evidence custody at the failure boundary. ---
#
# A failed qualification must preserve the evidence it generated before failing,
# without letting evidence recovery alter the verdict. Both guest phases pull
# $RESULTS before the VM is destroyed; neither a successful nor a failed
# retrieval may change what the run concluded.
require_text "$host" 'preserve_guest_evidence before-reboot'
require_text "$host" 'preserve_guest_evidence after-reboot'

# The failure-path retrieval must land somewhere the sealing path does not read.
# Sealing consumes $output/guest-results; recovered failure evidence must never
# be able to stand in for it.
require_text "$host" 'dest=$output/failed-guest-results'
if grep -F 'preserve_guest_evidence' "$host" | grep -F '"$output/guest-results"' >/dev/null; then
    printf 'failure-path retrieval must not write the sealed guest-results directory\n' >&2
    exit 1
fi

# Behavioural proof, no VM: drive preserve_guest_evidence directly with a stubbed
# scp and assert verdict-neutrality on both the success and the failure branch.
probe=$scratch/preserve-probe.sh
{
    printf '%s\n' 'set -Eeuo pipefail'
    printf '%s\n' 'output=$1'
    printf '%s\n' 'output_ready=true'
    printf '%s\n' 'scp_opts=()'
    # If the function ever reaches the verdict machinery, these fire loudly.
    printf '%s\n' 'refuse() { printf "FORBIDDEN: refuse called\n" >&2; exit 91; }'
    # remaining() refuses once the deadline has passed, so the retrieval must
    # never call it. It leaves a file rather than only exiting: a call inside a
    # command substitution would otherwise die in the subshell unnoticed.
    printf '%s\n' 'remaining() { printf "called\n" >"$output/FORBIDDEN_REMAINING"; exit 92; }'
    printf '%s\n' 'timeout() { return "$STUB_SCP_STATUS"; }'
    sed -n '/^preserve_guest_evidence()/,/^}/p' "$host"
    printf '%s\n' 'preserve_guest_evidence after-reboot'
    printf '%s\n' 'printf "returned=%s\n" "$?"'
} >"$probe"

expect_custody() {
    local label=$1 stub_status=$2 expect_file=$3 probe_out probe_status
    probe_out=$scratch/custody-$label
    mkdir -p "$probe_out"
    set +e
    STUB_SCP_STATUS=$stub_status bash "$probe" "$probe_out" \
        >"$scratch/custody-$label.out" 2>"$scratch/custody-$label.err"
    probe_status=$?
    set -e
    # Verdict-neutrality: the function itself must never fail the run.
    ((probe_status == 0)) || {
        printf 'evidence retrieval (%s) altered control flow: exit %s\n' \
            "$label" "$probe_status" >&2
        cat "$scratch/custody-$label.err" >&2
        exit 1
    }
    grep -qx 'returned=0' "$scratch/custody-$label.out" || {
        printf 'evidence retrieval (%s) did not return 0\n' "$label" >&2
        exit 1
    }
    # It must never manufacture, repair, or overwrite a verdict.
    for forbidden in REFUSAL RESULT guest-results FORBIDDEN_REMAINING; do
        [[ ! -e "$probe_out/$forbidden" ]] || {
            printf 'evidence retrieval (%s) wrote verdict artifact %s\n' \
                "$label" "$forbidden" >&2
            exit 1
        }
    done
    [[ -e "$probe_out/$expect_file" ]] || {
        printf 'evidence retrieval (%s) did not record %s\n' "$label" "$expect_file" >&2
        exit 1
    }
}

# A successful retrieval records custody and changes nothing else.
expect_custody retrieved 0 EVIDENCE_CUSTODY
# A failed retrieval is a SECONDARY note: it must not obscure the original
# refusal, and must still leave the verdict untouched.
expect_custody unretrieved 1 EVIDENCE_CUSTODY_FAILURE
[[ ! -e "$scratch/custody-unretrieved/EVIDENCE_CUSTODY" ]] || {
    printf 'a failed retrieval falsely claimed custody\n' >&2
    exit 1
}

# --- run_nq must reconstruct every runtime directory nqd.service creates,
#     exactly, before a transient unit depends on it. ---
#
# run_nq launches nq inside a transient systemd unit whose sandbox binds /run/nq
# (ReadWritePaths) and whose helper carrier prepares a private directory under
# /run/nq/helpers. Both are created by nqd.service and both live on the /run
# tmpfs, so `systemctl stop nqd` tears them down. A transient unit run after that
# stop then failed one gate apart depending on which was missing:
#   - /run/nq gone     -> 226/NAMESPACE, empty stream (run 2026-07-19-9f9a391);
#   - /run/nq/helpers gone -> nq ran but reported carrier_startup_failed before
#     it could bind or inspect the socket (run 2026-07-19-0a2938c).
# run_nq must reconstruct BOTH to the exact packaged contract before launching.
# The contract is read from the package sources (nq.tmpfiles, cross-checked
# against nqd.service's ExecStartPre) rather than hardcoded, so this tracks them.
tmpfiles=$HERE/../packaging/systemd/nq.tmpfiles
unit=$HERE/../packaging/systemd/nqd.service
[[ -f $tmpfiles ]] || { printf 'packaged nq.tmpfiles not found at %s\n' "$tmpfiles" >&2; exit 1; }
[[ -f $unit ]] || { printf 'packaged nqd.service not found at %s\n' "$unit" >&2; exit 1; }
python3 - "$guest" "$tmpfiles" "$unit" <<'CHECK'
import sys

guest_path, tmpfiles_path, unit_path = sys.argv[1], sys.argv[2], sys.argv[3]
problems = []

# Every runtime directory run_nq must reconstruct, parent before child.
required = ["/run/nq", "/run/nq/helpers"]

# Authoritative contract, read from the package's tmpfiles source.
contract = {}
for row in open(tmpfiles_path, encoding="utf-8"):
    f = row.split()
    if len(f) >= 5 and f[0] == "d" and f[1] in required:
        contract[f[1]] = {"mode": f[2], "user": f[3], "group": f[4]}
for path in required:
    if path not in contract:
        problems.append(f"nq.tmpfiles declares no `d {path}` entry to enforce")


def parse_install(tokens):
    """Extract (user, group, mode, path) from an `install -d -o U -g G -m M P`."""
    got = {"-o": None, "-g": None, "-m": None}
    path = None
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in got and i + 1 < len(tokens):
            got[t] = tokens[i + 1]
            i += 2
            continue
        if t != "-d" and not t.startswith("-"):
            path = t
        i += 1
    return got["-o"], got["-g"], got["-m"], path


# Cross-check: nqd.service's ExecStartPre for /run/nq/helpers must agree with
# tmpfiles, so run_nq's single copy can be validated against a coherent contract.
for line in open(unit_path, encoding="utf-8"):
    s = line.strip()
    if s.startswith("ExecStartPre=") and "install -d" in s and "/run/nq/helpers" in s:
        u, g, m, p = parse_install(s.split())
        c = contract.get("/run/nq/helpers")
        if c and (u, g, m) != (c["user"], c["group"], c["mode"]):
            problems.append(
                "nqd.service ExecStartPre and nq.tmpfiles disagree on /run/nq/helpers: "
                f"unit says {u}:{g}:{m}, tmpfiles says {c['user']}:{c['group']}:{c['mode']}")
        break

# run_nq must recreate each required directory, exactly, before systemd-run.
lines = open(guest_path, encoding="utf-8").read().splitlines()
start = next(i for i, l in enumerate(lines) if l.strip() == "run_nq() {")
end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "}")
body = [l.strip() for l in lines[start:end]]
launch_idx = next((i for i, l in enumerate(body) if l.startswith("systemd-run")), None)
if launch_idx is None:
    problems.append("run_nq must launch its transient unit via systemd-run")

prov_at = {}
for path in required:
    c = contract.get(path)
    if not c:
        continue
    expected = f"install -d -o {c['user']} -g {c['group']} -m {c['mode']} {path}"
    idx = body.index(expected) if expected in body else None
    prov_at[path] = idx
    if idx is None:
        problems.append(f"run_nq must recreate {path} exactly as the package declares: `{expected}`")
    elif launch_idx is not None and idx > launch_idx:
        problems.append(f"run_nq must recreate {path} before launching the transient unit")

# Parent before child: /run/nq must be provisioned before /run/nq/helpers.
a, b = prov_at.get("/run/nq"), prov_at.get("/run/nq/helpers")
if a is not None and b is not None and a > b:
    problems.append("run_nq must recreate /run/nq before its /run/nq/helpers child")

if problems:
    for problem in problems:
        print(problem, file=sys.stderr)
    raise SystemExit(1)
CHECK

# Behavioural proof, no VM: model systemd bringing up a transient unit against
# the two runtime directories. A launch after `systemctl stop nqd` sees neither;
# missing /run/nq is a namespace-setup refusal (226) before nq runs, and a
# present /run/nq with a missing /run/nq/helpers lets nq run but the helper
# carrier cannot start (exit 1) before it can inspect the socket -- the two gates
# the real runs hit. Provisioning both, in run_nq's order, reaches execution.
# The static check above pins the privileged owner/mode this model omits.
runtime_probe=$scratch/run-nq-runtime
launched=$scratch/run-nq-launched
sandbox_launch() {
    [[ -d $runtime_probe ]] || return 226            # /run/nq bind: 226/NAMESPACE
    [[ -d $runtime_probe/helpers ]] || return 1      # helper carrier: carrier_startup_failed
    printf 'reached\n' >"$launched"
}
provision_runtime() {
    install -d -m 0751 "$runtime_probe"
    install -d -m 0711 "$runtime_probe/helpers"
}

# Post-stop state: both directories are gone. Provision both, then launch.
rm -rf "$runtime_probe"; rm -f "$launched"
provision_runtime
set +e; sandbox_launch; launch_status=$?; set -e
((launch_status == 0)) || {
    printf 'transient unit did not reach execution after provisioning (exit %s)\n' "$launch_status" >&2
    exit 1
}
[[ $(stat -c '%a' "$runtime_probe") == 751 ]] || { printf '/run/nq mode is not 0751\n' >&2; exit 1; }
[[ $(stat -c '%a' "$runtime_probe/helpers") == 711 ]] || { printf '/run/nq/helpers mode is not 0711\n' >&2; exit 1; }
[[ $(cat "$launched") == reached ]] || { printf 'transient unit did not execute\n' >&2; exit 1; }

# Bite: neither directory -- the first regression. Launch fails 226, nothing runs.
rm -rf "$runtime_probe"; rm -f "$launched"
set +e; sandbox_launch; s=$?; set -e
((s == 226)) || { printf 'expected 226/NAMESPACE with no runtime dirs, got %s\n' "$s" >&2; exit 1; }
[[ ! -e $launched ]] || { printf 'transient unit ran with no runtime dirs\n' >&2; exit 1; }

# Bite: /run/nq only, /run/nq/helpers absent -- the second regression, the exact
# state the /run/nq-only fix left. nq runs but the carrier fails (exit 1).
rm -rf "$runtime_probe"; rm -f "$launched"
install -d -m 0751 "$runtime_probe"
set +e; sandbox_launch; s=$?; set -e
((s == 1)) || { printf 'expected carrier_startup_failed (exit 1) without /run/nq/helpers, got %s\n' "$s" >&2; exit 1; }
[[ ! -e $launched ]] || { printf 'transient unit executed without its helper runtime root\n' >&2; exit 1; }

printf 'hardening harness syntax/static checks passed; guest-result, bad-hash, and stale-output negatives refused as required\n'
