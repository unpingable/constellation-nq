#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export TZ=UTC

if [[ $# -ne 4 ]]; then
    echo "usage: $0 VERSION ARCH BIN_DIR PROFILE_DIR" >&2
    exit 2
fi

version=$1
arch=$2
bin_dir=$3
profile_dir=$4
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/nq-release-atomicity.XXXXXXXX")
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

base_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Every package-owned helper binary is mandatory and its build-info component
# identity must match its installed name. Missing or substituted bytes refuse
# before any output artifact is created.
invalid_bin_dir=$work/invalid-binaries
missing_out=$work/missing-helper-out
substituted_out=$work/substituted-helper-out
substituted_resource_out=$work/substituted-resource-helper-out
mkdir -p -- "$invalid_bin_dir" "$missing_out" "$substituted_out" \
    "$substituted_resource_out"
for binary in nq nqd nq-host-helper nq-host-resource-helper \
    nq-synthetic-cache-result-helper; do
    cp -- "$bin_dir/$binary" "$invalid_bin_dir/$binary"
done
set +e
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$invalid_bin_dir" "$profile_dir" "$missing_out" \
    >"$work/missing-helper.stdout" 2>"$work/missing-helper.stderr"
missing_helper_status=$?
set -e
[[ $missing_helper_status -ne 0 ]] || {
    echo "release assembly accepted a missing operator-beta helper" >&2
    exit 1
}
grep -Fq 'missing executable' "$work/missing-helper.stderr"
if find "$missing_out" -mindepth 1 -print -quit | grep -q .; then
    echo "missing operator-beta helper created a release output" >&2
    exit 1
fi

cp -- "$bin_dir/nq-host-helper" "$invalid_bin_dir/nq-operator-beta-helper"
set +e
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$invalid_bin_dir" "$profile_dir" "$substituted_out" \
    >"$work/substituted-helper.stdout" 2>"$work/substituted-helper.stderr"
substituted_helper_status=$?
set -e
[[ $substituted_helper_status -ne 0 ]] || {
    echo "release assembly accepted substituted operator-beta helper bytes" >&2
    exit 1
}
grep -Fq "expected 'nq-operator-beta-helper'" "$work/substituted-helper.stderr"
if find "$substituted_out" -mindepth 1 -print -quit | grep -q .; then
    echo "substituted operator-beta helper created a release output" >&2
    exit 1
fi

# The host-resource helper is also the catalog agreement witness; bytes of a
# different helper installed under its name must be refused by identity.
cp -- "$bin_dir/nq-operator-beta-helper" "$invalid_bin_dir/nq-operator-beta-helper"
cp -- "$bin_dir/nq-host-helper" "$invalid_bin_dir/nq-host-resource-helper"
set +e
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$invalid_bin_dir" "$profile_dir" "$substituted_resource_out" \
    >"$work/substituted-resource-helper.stdout" \
    2>"$work/substituted-resource-helper.stderr"
substituted_resource_status=$?
set -e
[[ $substituted_resource_status -ne 0 ]] || {
    echo "release assembly accepted substituted host-resource helper bytes" >&2
    exit 1
}
grep -Fq "expected 'nq-host-resource-helper'" \
    "$work/substituted-resource-helper.stderr"
if find "$substituted_resource_out" -mindepth 1 -print -quit | grep -q .; then
    echo "substituted host-resource helper created a release output" >&2
    exit 1
fi

# Every binary must carry the same recorded source commit. A binary whose
# embedded commit differs (here: one helper's 40-hex commit rewritten in place
# with a same-length different value, so the ELF layout is untouched) and a
# binary whose recorded commit is malformed are refused by identity, before
# any output artifact is created.
drift_bin_dir=$work/drift-binaries
drift_out=$work/drift-commit-out
malformed_bin_dir=$work/malformed-binaries
malformed_out=$work/malformed-commit-out
mkdir -p -- "$drift_bin_dir" "$drift_out" "$malformed_bin_dir" "$malformed_out"
for binary in nq nqd nq-host-helper nq-host-resource-helper \
    nq-operator-beta-helper nq-synthetic-cache-result-helper; do
    cp -- "$bin_dir/$binary" "$drift_bin_dir/$binary"
    cp -- "$bin_dir/$binary" "$malformed_bin_dir/$binary"
done
python3 - "$bin_dir/nq-host-helper" "$drift_bin_dir/nq-host-helper" \
    "$malformed_bin_dir/nq-host-helper" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

original, drifted, malformed = (pathlib.Path(argument) for argument in sys.argv[1:])
probe = subprocess.run(
    [original, "--build-info"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, check=True
)
commit = json.loads(probe.stdout)["source_commit"]
if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
    raise SystemExit(f"fixture binary does not record a source commit: {commit!r}")
image = original.read_bytes()
needle = commit.encode("ascii")
if image.count(needle) == 0:
    raise SystemExit("fixture binary does not embed its source commit literally")
different = "".join(f"{15 - int(digit, 16):x}" for digit in commit).encode("ascii")
drifted.write_bytes(image.replace(needle, different))
malformed.write_bytes(image.replace(needle, b"Z" * 40))
PY
chmod 0755 "$drift_bin_dir/nq-host-helper" "$malformed_bin_dir/nq-host-helper"
set +e
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$drift_bin_dir" "$profile_dir" "$drift_out" \
    >"$work/drift-commit.stdout" 2>"$work/drift-commit.stderr"
drift_commit_status=$?
set -e
[[ $drift_commit_status -ne 0 ]] || {
    echo "release assembly accepted a binary from a different source commit" >&2
    exit 1
}
grep -Fq "release binaries must come from one source commit" \
    "$work/drift-commit.stderr"
if find "$drift_out" -mindepth 1 -print -quit | grep -q .; then
    echo "source-commit drift created a release output" >&2
    exit 1
fi
set +e
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$malformed_bin_dir" "$profile_dir" "$malformed_out" \
    >"$work/malformed-commit.stdout" 2>"$work/malformed-commit.stderr"
malformed_commit_status=$?
set -e
[[ $malformed_commit_status -ne 0 ]] || {
    echo "release assembly accepted a binary without a well-formed source commit" >&2
    exit 1
}
grep -Fq "not a full lowercase git commit id" "$work/malformed-commit.stderr"
if find "$malformed_out" -mindepth 1 -print -quit | grep -q .; then
    echo "malformed source commit created a release output" >&2
    exit 1
fi

# Concurrent assemblers must fail before constructing anything. The lock is on
# the output-directory inode and therefore cannot become stale after a crash.
lock_out=$work/lock-out
mkdir -p -- "$lock_out"
exec {lock_descriptor}<"$lock_out"
flock -n "$lock_descriptor"
set +e
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$bin_dir" "$profile_dir" "$lock_out" \
    >"$work/lock.stdout" 2>"$work/lock.stderr"
lock_status=$?
set -e
exec {lock_descriptor}>&-
[[ $lock_status -ne 0 ]] || {
    echo "concurrent release assembler unexpectedly acquired the output lock" >&2
    exit 1
}
if find "$lock_out" -mindepth 1 -print -quit | grep -q .; then
    echo "lock contention created a release output" >&2
    exit 1
fi

# A normal package-builder failure before publication must clean the hidden
# stage and preserve an existing committed bundle byte for byte.
failure_tools=$work/failure-tools
failure_out=$work/failure-out
mkdir -p -- "$failure_tools" "$failure_out"
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$bin_dir" "$profile_dir" "$failure_out" \
    >"$work/failure-baseline.stdout" 2>"$work/failure-baseline.stderr"
(
    cd -- "$failure_out"
    sha256sum --check SHA256SUMS >/dev/null
    sha256sum -- *
) >"$work/failure-before.sha256"
cat > "$failure_tools/dpkg-deb" <<'SH'
#!/bin/sh
exit 97
SH
chmod 0755 "$failure_tools/dpkg-deb"
set +e
PATH="$failure_tools:$base_path" \
    "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$bin_dir" "$profile_dir" "$failure_out" \
    >"$work/failure.stdout" 2>"$work/failure.stderr"
failure_status=$?
set -e
[[ $failure_status -ne 0 ]] || {
    echo "fault-injected package builder unexpectedly succeeded" >&2
    exit 1
}
(
    cd -- "$failure_out"
    sha256sum --check SHA256SUMS >/dev/null
    sha256sum -- *
) >"$work/failure-after.sha256"
cmp -- "$work/failure-before.sha256" "$work/failure-after.sha256"
if find "$failure_out" -mindepth 1 -maxdepth 1 \
    -name '.nq-release-publish.*' -print -quit | grep -q .; then
    echo "ordinary assembly failure left hidden publish scratch" >&2
    exit 1
fi

# Start with a valid committed bundle. SIGKILL after two replacement renames
# may leave complete individually checksummed artifacts, but the old marker
# must already be absent and the new marker must not yet be published.
kill_tools=$work/kill-tools
kill_out=$work/kill-out
count_file=$work/mv-count
stopped_pid_file=$work/stopped-mv-pid
mkdir -p -- "$kill_tools" "$kill_out"
PATH="$base_path" "$root/scripts/build-release-bundle.sh" \
    "$version" "$arch" "$bin_dir" "$profile_dir" "$kill_out" \
    >"$work/kill-baseline.stdout" 2>"$work/kill-baseline.stderr"
(
    cd -- "$kill_out"
    sha256sum --check SHA256SUMS >/dev/null
)
cat > "$kill_tools/mv" <<'SH'
#!/bin/sh
count=0
if test -f "$NQ_TEST_MV_COUNT"; then
    count=$(sed -n '1p' "$NQ_TEST_MV_COUNT")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$NQ_TEST_MV_COUNT"
if test "$count" -eq 3; then
    printf '%s\n' "$$" > "$NQ_TEST_STOPPED_MV_PID"
    kill -STOP "$$"
    exit 98
fi
exec /usr/bin/mv "$@"
SH
chmod 0755 "$kill_tools/mv"
kill_status_file=$work/kill-status
python3 - \
    "$root/scripts/build-release-bundle.sh" "$version" "$arch" \
    "$bin_dir" "$profile_dir" "$kill_out" "$kill_tools:$base_path" \
    "$count_file" "$stopped_pid_file" "$work/kill.stdout" \
    "$work/kill.stderr" "$kill_status_file" <<'PY'
import os
import pathlib
import signal
import subprocess
import sys
import time

(
    builder,
    version,
    architecture,
    binary_directory,
    profile_directory,
    output_directory,
    path,
    count_file,
    stopped_pid_file,
    stdout_path,
    stderr_path,
    status_path,
) = sys.argv[1:]
environment = os.environ.copy()
environment.update(
    {
        "PATH": path,
        "NQ_TEST_MV_COUNT": count_file,
        "NQ_TEST_STOPPED_MV_PID": stopped_pid_file,
    }
)
stopped = pathlib.Path(stopped_pid_file)
with open(stdout_path, "wb") as stdout, open(stderr_path, "wb") as stderr:
    process = subprocess.Popen(
        [
            builder,
            version,
            architecture,
            binary_directory,
            profile_directory,
            output_directory,
        ],
        env=environment,
        stdout=stdout,
        stderr=stderr,
        start_new_session=True,
    )
    process_group = os.getpgid(process.pid)
    if process_group != process.pid or process_group == os.getpgrp():
        process.kill()
        process.wait()
        raise SystemExit(
            "fault-injected assembler did not receive a private process group"
        )
    deadline = time.monotonic() + 60
    while not (stopped.is_file() and stopped.stat().st_size > 0):
        return_code = process.poll()
        if return_code is not None:
            raise SystemExit(
                f"fault-injected assembler exited {return_code} before publication"
            )
        if time.monotonic() >= deadline:
            os.killpg(process_group, signal.SIGKILL)
            process.wait()
            raise SystemExit(
                "fault-injected assembler did not reach the publication boundary"
            )
        time.sleep(0.1)
    os.killpg(process_group, signal.SIGKILL)
    return_code = process.wait()
if return_code != -signal.SIGKILL:
    raise SystemExit(f"assembler returned {return_code}, not SIGKILL")
pathlib.Path(status_path).write_text("137\n", encoding="ascii")
PY
read -r kill_status <"$kill_status_file"
[[ $kill_status -ne 0 ]] || {
    echo "fault-injected publication unexpectedly succeeded" >&2
    exit 1
}
[[ ! -e "$kill_out/SHA256SUMS" ]] || {
    echo "killed publication exposed its bundle commit marker" >&2
    exit 1
}
find "$kill_out" -mindepth 1 -maxdepth 1 \
    -type d -name '.nq-release-publish.*' -print -quit | grep -q . || {
    echo "killed publication did not retain distinguishable hidden scratch" >&2
    exit 1
}
package="nq-ng-${version}-linux-${arch}.tar.gz"
[[ -f "$kill_out/$package" && -f "$kill_out/$package.sha256" ]] || {
    echo "fault did not occur at the intended publication boundary" >&2
    exit 1
}
(
    cd -- "$kill_out"
    sha256sum --check "$package.sha256" >/dev/null
)

printf 'release failure atomicity passed (missing=%s, substituted=%s, substituted_resource=%s, drift_commit=%s, malformed_commit=%s, lock=%s, failure=%s, killed=%s)\n' \
    "$missing_helper_status" "$substituted_helper_status" \
    "$substituted_resource_status" "$drift_commit_status" \
    "$malformed_commit_status" "$lock_status" "$failure_status" \
    "$kill_status"
