#!/bin/bash
# Disposable guest-only fixtures for the release-closure acceptance:
# loop-mounted ext4 images and systemd fixture units. Never run on a host.
set -euo pipefail
BASE=/srv/nq-fixture

identities() {
  python3 - <<'PY'
import json, os
print(json.dumps({
    "hostname": os.uname().nodename,
    "kernel": os.uname().release,
    "machine_id": open("/etc/machine-id").read().strip(),
    "boot_id": open("/proc/sys/kernel/random/boot_id").read().strip(),
    "cmdline": open("/proc/cmdline").read().strip(),
    "psi_memory_present": os.path.exists("/proc/pressure/memory"),
    "psi_memory": open("/proc/pressure/memory").read() if os.path.exists("/proc/pressure/memory") else None,
    "cpus": os.cpu_count(),
}))
PY
}

setup_fs() {
  sudo mkdir -p -m 0755 $BASE/img $BASE/full $BASE/roomy $BASE/inodes
  sudo truncate -s 64M $BASE/img/full.img
  sudo truncate -s 64M $BASE/img/roomy.img
  sudo truncate -s 16M $BASE/img/inodes.img
  sudo mkfs.ext4 -q -F -m 0 -L nqfull $BASE/img/full.img
  sudo mkfs.ext4 -q -F -m 0 -L nqroomy $BASE/img/roomy.img
  sudo mkfs.ext4 -q -F -m 0 -N 256 -L nqinodes $BASE/img/inodes.img
  for n in full roomy inodes; do
    sudo mount -o loop $BASE/img/$n.img $BASE/$n
    sudo chmod 0755 $BASE/$n
  done
  sudo udevadm trigger --action=change --subsystem-match=block || true
  sudo udevadm settle
  # Fill "full" to ~93% of non-reserved capacity (law: used/(used+avail) >= 0.90).
  sudo python3 - <<'PY'
import os
mp = "/srv/nq-fixture/full"
st = os.statvfs(mp)
used = (st.f_blocks - st.f_bfree) * st.f_frsize
avail = st.f_bavail * st.f_frsize
target_used = int(0.93 * (used + avail))
extra = max(0, target_used - used)
fd = os.open(f"{mp}/filler", os.O_CREAT | os.O_WRONLY, 0o600)
os.posix_fallocate(fd, 0, extra)
os.close(fd)
PY
  # Fill "inodes" to >= 92% of inodes.
  sudo python3 - <<'PY'
import os
mp = "/srv/nq-fixture/inodes"
st = os.statvfs(mp)
used = st.f_files - st.f_ffree
need = max(0, int(0.92 * st.f_files + 0.999) - used)
os.makedirs(f"{mp}/many", exist_ok=True)
for i in range(need):
    open(f"{mp}/many/f{i}", "w").close()
PY
  sync
  report_fs
}

report_fs() {
  python3 - <<'PY'
import json, os, subprocess
out = {}
for n in ("full", "roomy", "inodes"):
    mp = f"/srv/nq-fixture/{n}"
    st = os.statvfs(mp)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    avail = st.f_bavail * st.f_frsize
    src = None
    for line in open("/proc/self/mountinfo"):
        f = line.split()
        if f[4] == mp:
            src = f[f.index("-") + 2]
    uuid = subprocess.run(["sudo", "blkid", "-s", "UUID", "-o", "value", src], capture_output=True, text=True).stdout.strip()
    by_uuid = os.path.exists(f"/dev/disk/by-uuid/{uuid}")
    out[n] = {
        "mountpoint": mp, "device": src, "uuid": uuid, "by_uuid_link": by_uuid,
        "used_bytes": used, "avail_bytes": avail,
        "used_fraction_of_usable": round(used / (used + avail), 4) if used + avail else None,
        "inodes_total": st.f_files, "inodes_free": st.f_ffree,
        "inodes_used_fraction": round((st.f_files - st.f_ffree) / st.f_files, 4) if st.f_files else None,
    }
print(json.dumps(out))
PY
}

setup_units() {
  sudo tee /etc/systemd/system/nq-fixture.service >/dev/null <<'UNIT'
[Unit]
Description=NQ acceptance fixture (sleeps)

[Service]
Type=simple
ExecStart=/bin/sleep infinity
UNIT
  sudo tee /etc/systemd/system/nq-fixture-fail.service >/dev/null <<'UNIT'
[Unit]
Description=NQ acceptance fixture (exits non-zero)

[Service]
Type=simple
ExecStart=/bin/sh -c 'exit 3'
Restart=no
UNIT
  # An alias name: a symlink whose name differs from the unit it points to.
  sudo ln -sfn nq-fixture.service /etc/systemd/system/nq-fixture-alias.service
  sudo systemctl daemon-reload
  sudo systemctl start nq-fixture.service
  sudo systemctl start nq-fixture-fail.service || true
  sleep 1
  report_units
}

report_units() {
  for u in nq-fixture.service nq-fixture-fail.service nq-fixture-alias.service "${1:-nq-fixture-absent.service}"; do
    printf '%s: ' "$u"; systemctl show "$u" -p Id,LoadState,ActiveState,SubState,Result,Names --value | paste -sd' '
  done
}

teardown() {
  sudo systemctl stop nq-fixture.service nq-fixture-fail.service 2>/dev/null || true
  for n in full roomy inodes; do sudo umount $BASE/$n 2>/dev/null || true; done
  sudo losetup -D || true
  sudo rm -rf $BASE
}

case "${1:-}" in
  identities) identities ;;
  setup-fs) setup_fs ;;
  report-fs) report_fs ;;
  setup-units) setup_units ;;
  report-units) report_units "${2:-}" ;;
  teardown) teardown ;;
  *) echo "usage: fixtures.sh identities|setup-fs|report-fs|setup-units|report-units|teardown" >&2; exit 2 ;;
esac
