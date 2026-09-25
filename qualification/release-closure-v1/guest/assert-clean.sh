#!/bin/bash
# Assert the guest holds no source tree, no host share, and no egress.
set -u
echo "== os-release"; . /etc/os-release; echo "$ID $VERSION_ID"; uname -r
echo "== source-tree names (expect none)"
sudo find / -xdev \( -name Cargo.toml -o -name .git \) 2>/dev/null | sed 's/^/found: /'
echo "== cargo-style target directories (expect none)"
sudo find / -xdev -type d -name target 2>/dev/null | while read -r d; do
  if [ -d "$d/release" ] || [ -d "$d/debug" ]; then echo "found: $d"; fi
done
echo "== any directory named target (informational)"
sudo find / -xdev -type d -name target 2>/dev/null | sed 's/^/dir: /'
echo "== shared/host filesystems in /proc/mounts (expect none)"
awk '$3 ~ /^(9p|virtiofs|nfs|nfs4|cifs|fuse\.sshfs)$/ { print "found: " $0 }' /proc/mounts
echo "== block devices"; lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
echo "== PATH"; echo "$PATH"
echo "== egress probe (expect failure)"
python3 - <<'PY'
import socket
for host, port in (("1.1.1.1", 53), ("9.9.9.9", 443)):
    s = socket.socket(); s.settimeout(5)
    try:
        s.connect((host, port)); print(f"egress: CONNECTED {host}:{port}")
    except OSError as e:
        print(f"egress: refused/timeout {host}:{port}: {e}")
    finally:
        s.close()
PY
getent hosts deb.debian.org && echo "dns: resolved (unexpected)" || echo "dns: no resolution"
