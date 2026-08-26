#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
helper="$root/crates/nq-host-helper/src/lib.rs"
store="$root/crates/nq-store/src/recurrence.rs"
cli="$root/crates/nq-app/src/cli.rs"
config="$root/crates/nq-core/src/config.rs"
doctrine="$root/docs/PROVIDER_OPERATION_NONINTERFERENCE_V1.md"

fail() {
  echo "provider-operation-noninterference-surface: $*" >&2
  exit 1
}

python3 "$root/scripts/verify_provider_operation_noninterference.py"

rg -q 'const PROC_LOADAVG: &str = "/proc/loadavg"' "$helper" \
  || fail "exact load source is no longer closed"
rg -q 'const PROC_UPTIME: &str = "/proc/uptime"' "$helper" \
  || fail "exact uptime source is no longer closed"
rg -q 'std::thread::available_parallelism' "$helper" \
  || fail "CPU-capacity source is no longer explicit"
if rg -q 'File::create|OpenOptions|TcpStream|UdpSocket|Command::new' "$helper"; then
  fail "bounded host helper gained mutation, network, or command execution"
fi

rg -q 'fenced_outcome_unknown' "$store" \
  || fail "unknown provider activity no longer fences the domain"
if rg -qi 'assume[_-]?noninterfer|allow[_-]?overlap|force[_-]?(clear|unlock)' \
  "$store" "$cli" "$config"; then
  fail "configuration or operator surface can invent provider noninterference"
fi

rg -q 'Noninterference can remove the need to wait for an unknown operation' \
  "$doctrine" || fail "coordination-only meaning is undocumented"
rg -q 'Read-only is a property of effects' \
  "$doctrine" || fail "read-only/noninterference distinction is undocumented"
rg -q 'A renamed coordination domain is not an independent system' "$doctrine" \
  || fail "domain rename prohibition is undocumented"

echo "provider-operation-noninterference-surface: fail-closed exact-class boundary present"
