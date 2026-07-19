#!/usr/bin/env bash
# Runs inside the disposable Ubuntu Noble guest. There are no skip paths.
set -Eeuo pipefail
umask 077

readonly RESULTS=/var/tmp/nq-hardening-results
readonly CONFIG=/etc/nq/nq.toml
phase=${1-}
deb=${2-}
expected_sha=${3-}
expected_driver_sha=${4-}
current_check=guest-arguments

fail() {
    printf 'guest lifecycle refused at %s: %s\n' "$current_check" "$1" >&2
    exit 1
}

on_exit() {
    local status=$?
    if ((status != 0)) && [[ -d $RESULTS ]]; then
        printf 'result=refused\ncheck=%s\nexit=%s\n' \
            "$current_check" "$status" >"$RESULTS/GUEST_REFUSAL"
        systemctl status nqd.service --no-pager >"$RESULTS/failure-systemd-status.log" 2>&1 || true
        journalctl -u nqd.service --no-pager >"$RESULTS/failure-journal.log" 2>&1 || true
        chmod -R a+rX "$RESULTS" || true
    fi
}
trap on_exit EXIT

[[ $phase == before-reboot || $phase == after-reboot ]] || fail "unknown phase $phase"
[[ $EUID == 0 ]] || fail "guest lifecycle must run as root"
[[ -f $deb && ! -L $deb ]] || fail "Debian input is not a regular non-symlink file"
[[ $expected_sha =~ ^[0-9a-f]{64}$ ]] || fail "invalid expected Debian SHA-256"
[[ $(sha256sum "$deb" | awk '{print $1}') == "$expected_sha" ]] || fail \
    "guest Debian bytes differ from host-bound digest"
# Re-verify this driver's own bytes inside the guest: host-side staging success
# must not stand in for guest verification of what actually executes here.
[[ $expected_driver_sha =~ ^[0-9a-f]{64}$ ]] || fail "invalid expected driver SHA-256"
[[ $(sha256sum "$0" | awk '{print $1}') == "$expected_driver_sha" ]] || fail \
    "guest lifecycle driver bytes differ from host-bound digest"
[[ $(dpkg-deb -f "$deb" Package) == nq-ng ]] || fail "guest artifact is not nq-ng"
[[ $(dpkg-deb -f "$deb" Architecture) == amd64 ]] || fail "guest artifact is not amd64"
# shellcheck disable=SC1091
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || fail \
    "guest is not exact Ubuntu 24.04"
[[ -d /run/systemd/system ]] || fail "guest is not booted under systemd"

if [[ $phase == before-reboot ]]; then
    [[ ! -e $RESULTS ]] || fail "results directory already exists before first phase"
    mkdir -m 0755 "$RESULTS"
else
    [[ -f $RESULTS/BEFORE_REBOOT_COMPLETE ]] || fail "before-reboot marker is absent"
fi
exec > >(tee -a "$RESULTS/guest-lifecycle.log") 2>&1

counter=0
run_nq() {
    counter=$((counter + 1))
    systemd-run --quiet --wait --pipe --collect \
        --unit="nq-hardening-$$-$counter" \
        --property=Type=exec \
        --property=User=nq --property=Group=nq --property=UMask=0077 \
        --property=NoNewPrivileges=yes --property=PrivateTmp=yes \
        --property=ProtectSystem=strict --property=ProtectHome=yes \
        --property=RestrictNamespaces=yes --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=yes --property=LockPersonality=yes \
        --property=RemoveIPC=yes --property=KeyringMode=private \
        --property=SystemCallArchitectures=native \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
        --property=ReadOnlyPaths=/etc/nq \
        --property='ReadWritePaths=/var/lib/nq /run/nq' \
        --property='CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' \
        --property='AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL' \
        --property=LimitNOFILE=4096 --property=LimitFSIZE=1G \
        --property=LimitCORE=0 --property=TasksMax=256 \
        --property=MemoryMax=2G --property=MemorySwapMax=0 --property=CPUQuota=200% \
        -- /usr/bin/nq --config="$CONFIG" "$@"
}

inactive() { [[ $(systemctl is-active nqd.service 2>/dev/null || true) == inactive ]]; }
disabled() { [[ $(systemctl is-enabled nqd.service 2>/dev/null || true) == disabled ]]; }

admitted_report_count() {
    python3 - /var/lib/nq/nq.db <<'PY'
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as database:
    row = database.execute(
        "SELECT count(*) FROM admitted_reports WHERE instance_id = ?",
        ("conformance-local",),
    ).fetchone()
print(row[0])
PY
}

wait_for_admitted_report_after() {
    local earlier=$1 label=$2 count
    for _ in {1..90}; do
        count=$(admitted_report_count)
        if ((count > earlier)); then
            printf '%s_before=%s\n%s_after=%s\n' \
                "$label" "$earlier" "$label" "$count" \
                >>"$RESULTS/AF_UNIX_RESTART_COUNTS"
            return 0
        fi
        sleep 1
    done
    fail "no admitted cross-UID Unix report appeared after $label"
}

assert_layout() {
    local state_expected=$1
    [[ $(id -u nq) != 0 && $(id -u nq-witness) != 0 ]] || fail "package identities are root"
    [[ $(id -u nq) != "$(id -u nq-witness)" ]] || fail "daemon and witness UIDs are equal"
    [[ $(id -g nq) != "$(id -g nq-witness)" ]] || fail "daemon and witness GIDs are equal"
    [[ $(stat -c '%U:%G:%a' /etc/nq) == root:nq:750 ]] || fail "wrong /etc/nq custody"
    [[ $(stat -c '%U:%G:%a' /var/lib/nq) == nq:nq:700 ]] || fail "wrong state custody"
    [[ $(stat -c '%U:%G:%a' /run/nq) == nq:nq:751 ]] || fail "wrong runtime custody"
    [[ $(stat -c '%U:%G:%a' /run/nq/helpers) == nq:nq:711 ]] || fail \
        "wrong helper-runtime custody"
    [[ -x /usr/bin/nq && -x /usr/bin/nqd ]] || fail "package executables are absent"
    inactive || fail "package hook unexpectedly started nqd"
    if [[ $state_expected == empty ]]; then
        disabled || fail "package hook unexpectedly enabled nqd"
        [[ ! -e $CONFIG && ! -e /var/lib/nq/nq.db ]] || fail \
            "package hook initialized configuration or database"
    fi
}

verify_build_info() {
    local component path
    for component in nq nqd nq-host-helper; do
        case $component in
            nq) path=/usr/bin/nq ;;
            nqd) path=/usr/bin/nqd ;;
            *) path=/usr/lib/nq/helpers/nq-host-helper ;;
        esac
        "$path" --build-info >>"$RESULTS/build-info.jsonl"
    done
    python3 - "$RESULTS/build-info.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert [row["component"] for row in rows] == ["nq", "nqd", "nq-host-helper"]
assert all(row["schema"] == "nq.build_info.v1" for row in rows)
assert all(row["debug_assertions"] is False for row in rows)
assert all(row["helper_isolation_policy"] == "production_separate_identity_required" for row in rows)
PY
}

install_config_and_admit() {
    install -o root -g nq -m 0640 \
        /usr/share/doc/nq-ng/examples/nq.toml "$CONFIG"
    sed -i 's/carrier = "stdio"/carrier = "unix"/' "$CONFIG"
    sed -i 's/replace-with-a-local-nonce/noble-hardening-fixed-nonce/' "$CONFIG"
    sed -i 's/interval_seconds = 300/interval_seconds = 2/' "$CONFIG"
    sed -i 's/jitter_seconds = 15/jitter_seconds = 0/' "$CONFIG"
    grep -qx 'carrier = "unix"' "$CONFIG" || fail "Unix carrier was not selected"
    runuser -u nq -- /usr/bin/nq --config="$CONFIG" config check
    runuser -u nq -- /usr/bin/nq --config="$CONFIG" init

    current_check=cross-uid-af-unix
    local daemon_uid witness_uid
    daemon_uid=$(id -u nq)
    witness_uid=$(id -u nq-witness)
    [[ $daemon_uid != "$witness_uid" ]] || fail "cross-UID check has equal identities"
    printf 'daemon_uid=%s\nwitness_uid=%s\ncarrier=unix\n' \
        "$daemon_uid" "$witness_uid" >"$RESULTS/AF_UNIX_IDENTITIES"
    run_nq witness test conformance-local
    run_nq witness admit conformance-local
    run_nq doctor
    run_nq collect conformance-local
}

if [[ $phase == before-reboot ]]; then
    current_check=clean-install
    if dpkg-query -W -f='${db:Status-Status}' nq-ng 2>/dev/null | grep -qx installed; then
        fail "nq-ng is already installed in supposedly clean guest"
    fi
    dpkg -i "$deb"
    assert_layout empty
    first_uid=$(id -u nq)
    first_witness_uid=$(id -u nq-witness)
    verify_build_info
    /usr/bin/nq protocol check >"$RESULTS/protocol-check.json"

    current_check=idempotent-empty-reinstall
    dpkg -i "$deb"
    dpkg -i "$deb"
    assert_layout empty
    [[ $(id -u nq) == "$first_uid" && $(id -u nq-witness) == "$first_witness_uid" ]] \
        || fail "idempotent postinst changed service identities"

    current_check=explicit-initialization
    install_config_and_admit

    current_check=explicit-service-lifecycle
    systemctl enable nqd.service
    reports_before_start=$(admitted_report_count)
    systemctl start nqd.service
    systemctl is-active --quiet nqd.service
    wait_for_admitted_report_after "$reports_before_start" service-start
    systemctl restart nqd.service
    systemctl is-active --quiet nqd.service
    reports_after_restart=$(admitted_report_count)
    wait_for_admitted_report_after "$reports_after_restart" service-restart
    systemctl stop nqd.service
    inactive || fail "explicit stop did not make nqd inactive"
    reports_before_second_start=$(admitted_report_count)
    systemctl start nqd.service
    systemctl is-active --quiet nqd.service
    wait_for_admitted_report_after "$reports_before_second_start" second-service-start
    systemctl is-enabled --quiet nqd.service
    journalctl -u nqd.service --no-pager >"$RESULTS/journal-before-reboot.log"
    cat /proc/sys/kernel/random/boot_id >"$RESULTS/BOOT_ID_BEFORE"
    printf 'complete\n' >"$RESULTS/BEFORE_REBOOT_COMPLETE"
    sync
    current_check=reboot
    systemctl reboot
    exit 0
fi

current_check=post-reboot-service
[[ $(<"$RESULTS/BOOT_ID_BEFORE") != "$(< /proc/sys/kernel/random/boot_id)" ]] || fail \
    "boot identity did not change"
systemctl is-enabled --quiet nqd.service || fail "nqd was not enabled across reboot"
systemctl is-active --quiet nqd.service || fail "nqd was not active after reboot"
reports_after_reboot=$(admitted_report_count)
wait_for_admitted_report_after "$reports_after_reboot" service-reboot
printf 'AF_UNIX_CROSS_UID=pass\n' >>"$RESULTS/REQUIRED_CHECKS"
journalctl -b -u nqd.service --no-pager >"$RESULTS/journal-after-reboot.log"

current_check=idempotent-stateful-reinstall
systemctl stop nqd.service
config_hash=$(sha256sum "$CONFIG" | awk '{print $1}')
database_hash=$(sha256sum /var/lib/nq/nq.db | awk '{print $1}')
dpkg -i "$deb"
inactive || fail "upgrade hook restarted nqd"
[[ $(sha256sum "$CONFIG" | awk '{print $1}') == "$config_hash" ]] || fail \
    "stateful reinstall changed configuration"
[[ $(sha256sum /var/lib/nq/nq.db | awk '{print $1}') == "$database_hash" ]] || fail \
    "stateful reinstall changed the stopped database"

current_check=remove
systemctl start nqd.service
dpkg --remove nq-ng
[[ -e $CONFIG && -e /var/lib/nq/nq.db ]] || fail "remove deleted retained state"
[[ $(sha256sum "$CONFIG" | awk '{print $1}') == "$config_hash" ]] || fail \
    "remove changed retained configuration"
getent passwd nq >/dev/null && getent passwd nq-witness >/dev/null || fail \
    "remove deleted service identities"

current_check=debian-purge
dpkg --purge nq-ng
[[ -e $CONFIG && -e /var/lib/nq/nq.db ]] || fail "Debian purge deleted retained state"
[[ $(sha256sum "$CONFIG" | awk '{print $1}') == "$config_hash" ]] || fail \
    "Debian purge changed retained configuration"
getent passwd nq >/dev/null && getent passwd nq-witness >/dev/null || fail \
    "Debian purge deleted service identities"

current_check=reinstall-after-purge
dpkg -i "$deb"
assert_layout retained
disabled || fail "reinstall after remove/purge unexpectedly enabled nqd"
run_nq doctor
run_nq collect conformance-local

current_check=byte-tamper-refusal
helper=/usr/lib/nq/helpers/nq_conformance_helper.py
cp --preserve=mode,ownership,timestamps "$helper" "$RESULTS/helper.original"
original_helper_hash=$(sha256sum "$helper" | awk '{print $1}')
printf '\n# nq-hardening-byte-tamper\n' >>"$helper"
set +e
run_nq doctor >"$RESULTS/tamper-doctor.log" 2>&1
tamper_status=$?
set -e
((tamper_status != 0)) || fail "doctor accepted changed helper bytes"
grep -F 'binary drift' "$RESULTS/tamper-doctor.log" >/dev/null || fail \
    "tamper refusal was not diagnosed as binary drift"
cp --preserve=mode,ownership,timestamps "$RESULTS/helper.original" "$helper"
[[ $(sha256sum "$helper" | awk '{print $1}') == "$original_helper_hash" ]] || fail \
    "could not restore exact helper bytes"
dpkg -V nq-ng >"$RESULTS/dpkg-verify.log"
[[ ! -s $RESULTS/dpkg-verify.log ]] || fail "package bytes differ after restoration"
run_nq doctor
run_nq collect conformance-local
printf 'HELPER_DRIFT_REFUSAL=pass\n' >>"$RESULTS/REQUIRED_CHECKS"

current_check=installed-manifest-tamper-refusal
systemctl stop nqd.service
for entry in \
    'contract:/usr/share/nq/system-contract/manifest.json' \
    'profile:/usr/share/nq/profiles/nq.conformance.v1.json'; do
    label=${entry%%:*}
    packaged_path=${entry#*:}
    backup="$RESULTS/$label.original"
    cp --preserve=mode,ownership,timestamps "$packaged_path" "$backup"
    printf '\n' >>"$packaged_path"
    systemctl reset-failed nqd.service
    set +e
    systemctl start nqd.service >"$RESULTS/$label-tamper-start.log" 2>&1
    start_status=$?
    set -e
    ((start_status != 0)) || fail "service accepted tampered $label bytes"
    if systemctl is-active --quiet nqd.service; then
        fail "service became active with tampered $label bytes"
    fi
    journalctl -u nqd.service --no-pager -n 100 \
        >"$RESULTS/$label-tamper-journal.log"
    grep -F "./${packaged_path#/usr/}: FAILED" \
        "$RESULTS/$label-tamper-journal.log" >/dev/null || fail \
        "startup refusal did not identify the tampered $label path"
    cp --preserve=mode,ownership,timestamps "$backup" "$packaged_path"
    rm -f "$backup"
    (
        cd /usr
        sha256sum --quiet --check /usr/share/nq/MANIFEST.sha256
    ) || fail "installed manifest did not verify after restoring $label bytes"
done
systemctl reset-failed nqd.service
systemctl start nqd.service
systemctl is-active --quiet nqd.service
systemctl stop nqd.service
printf 'BYTE_TAMPER_REFUSAL=pass\n' >>"$RESULTS/REQUIRED_CHECKS"

current_check=final-receipts
systemctl enable --now nqd.service
systemctl is-active --quiet nqd.service
systemctl is-enabled --quiet nqd.service
systemctl status nqd.service --no-pager >"$RESULTS/final-systemd-status.log"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' nq-ng \
    >"$RESULTS/final-package-status.tsv"
sha256sum "$deb" /usr/bin/nq /usr/bin/nqd \
    /usr/lib/nq/helpers/nq_conformance_helper.py >"$RESULTS/final-hashes.txt"
find /etc/nq /var/lib/nq /run/nq -maxdepth 3 -printf '%M %u:%g %p\n' \
    | sort >"$RESULTS/final-layout.txt"
sort -u "$RESULTS/REQUIRED_CHECKS" -o "$RESULTS/REQUIRED_CHECKS"
[[ $(wc -l <"$RESULTS/REQUIRED_CHECKS") == 3 ]] || fail "required pass markers are incomplete"
printf 'pass\n' >"$RESULTS/RESULT"
rm -f "$RESULTS/helper.original"
chmod -R a+rX "$RESULTS"
sync
