#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
crate="$root/crates/nq-operator-beta-helper"
manifest="$crate/Cargo.toml"
systemd_source="$crate/src/systemd.rs"
http_source="$crate/src/http.rs"

for path in "$manifest" "$crate/src/lib.rs" "$systemd_source" "$http_source" "$crate/src/main.rs"; do
    [[ -f "$path" ]] || { echo "missing helper surface: $path" >&2; exit 1; }
done

if rg -n 'nq-core|nq-store|nq-app' "$manifest" >/dev/null; then
    echo "helper acquired scheduling, store, or application authority" >&2
    exit 1
fi
if rg -n 'StartUnit|systemctl|Command::new|std::process::Command' "$crate/src" >/dev/null; then
    echo "helper boundary contains mutation or subprocess mechanics" >&2
    exit 1
fi

required=(
    '"GetMachineId"'
    '"RefUnit"'
    '"GetUnit"'
    '"GetUnitFileState"'
    '"LoadState"'
    '"ActiveState"'
    '"SubState"'
    '"FragmentPath"'
    'MAX_UNIT_FILE_BYTES: usize = 1_048_576'
    'libc::O_CLOEXEC | libc::O_NOFOLLOW'
)
if [[ "${NQ_OPERATOR_BETA_HELPER_INJECT_CONTROL:-0}" == 1 ]]; then
    required[1]='"RefUnit__deterministic_missing_control"'
fi
for needle in "${required[@]}"; do
    rg -Fq "$needle" "$systemd_source" || {
        echo "systemd acquisition law missing: $needle" >&2
        exit 1
    }
done

python3 - "$systemd_source" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
positions = [text.index(token) for token in ('"GetMachineId"', '"RefUnit"', '"GetUnit"', '"GetUnitFileState"', '"LoadState"', '"ActiveState"', '"SubState"', '"FragmentPath"')]
if positions != sorted(positions) or len(set(positions)) != len(positions):
    raise SystemExit("systemd calls/properties are not in the frozen acquisition order")
PY

for needle in \
    'MAX_HEADER_BYTES: usize = 16_384' \
    '"transfer-encoding"' \
    '"content-length"' \
    'HTTP/1.0' \
    'HTTP/1.1' \
    'http://127.0.0.1:18080/healthz'; do
    rg -Fq "$needle" "$http_source" || {
        echo "HTTP framing law missing: $needle" >&2
        exit 1
    }
done

cargo test --locked --manifest-path "$manifest"
printf '%s\n' 'operator-beta helper boundary: PASS'
