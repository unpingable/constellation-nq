#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
umask 077

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/test_release_reproducibility.sh VERSION ARCH BIN_DIR PROFILE_DIR

Assemble the release twice from equivalent inputs under deliberately different
absolute paths, directory insertion orders, umasks, locales, time zones, and
TMPDIRs. The test compares the archives, extracted trees, embedded manifests,
and checksum sidecars byte for byte without writing to dist/.

NQ_REPRO_SCRATCH_KIB bounds aggregate scratch use (default: 327680 KiB).
NQ_REPRO_EPOCH selects the shared SOURCE_DATE_EPOCH (default: 1700000000).
USAGE
    exit 2
}

[[ $# -eq 4 ]] || usage

version=$1
arch=$2
bin_dir=$3
profile_dir=$4
scratch_limit_kib=${NQ_REPRO_SCRATCH_KIB:-327680}
epoch=${NQ_REPRO_EPOCH:-1700000000}

[[ "$scratch_limit_kib" =~ ^[1-9][0-9]*$ ]] || {
    echo "NQ_REPRO_SCRATCH_KIB must be a positive integer" >&2
    exit 2
}
[[ "$epoch" =~ ^[0-9]+$ ]] || {
    echo "NQ_REPRO_EPOCH must be an unsigned integer" >&2
    exit 2
}

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
bin_dir=$(cd -- "$bin_dir" && pwd -P)
profile_dir=$(cd -- "$profile_dir" && pwd -P)

for tool in basename cmp cp diff dirname dpkg-deb du find md5sum mkdir mktemp \
    readlink rm sha256sum sleep sort stat tar wc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required local tool is missing: $tool" >&2
        exit 1
    }
done

scratch=''
cleanup() {
    status=$?
    trap - EXIT
    if [[ -n "$scratch" && -d "$scratch" && \
          -f "$scratch/.nq-release-repro-scratch" && \
          "$scratch" != / && "$scratch" != "$root" ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

scratch=$(mktemp -d "${TMPDIR:-/tmp}/nq-release-repro.XXXXXXXX")
: > "$scratch/.nq-release-repro-scratch"
peak_kib=0

measure_scratch() {
    local measurement used_kib
    # The assembler removes its private stage on exit, so a concurrent du can
    # observe entries disappearing. A missed sample during deletion is safe;
    # the next quiescent measurement below remains a hard budget check.
    measurement=$(du -sk -- "$scratch" 2>/dev/null) || measurement=''
    if [[ ! "$measurement" =~ ^([0-9]+)[[:space:]] ]]; then
        return 0
    fi
    used_kib=${BASH_REMATCH[1]}
    if (( used_kib > peak_kib )); then
        peak_kib=$used_kib
    fi
    if (( used_kib > scratch_limit_kib )); then
        echo "scratch budget exceeded: ${used_kib} KiB > ${scratch_limit_kib} KiB" >&2
        return 1
    fi
}

tree_inventory() {
    local directory=$1
    local include_inode=${2:-no}
    local path relative metadata digest target inode size
    (
        cd -- "$directory"
        while IFS= read -r -d '' path; do
            relative=${path#./}
            metadata=$(stat -c '%F|%a|%u|%g|%Y' -- "$path")
            digest=-
            target=-
            inode=-
            size=-
            if [[ -f "$path" && ! -L "$path" ]]; then
                digest=$(sha256sum -- "$path")
                digest=${digest%% *}
                size=$(stat -c '%s' -- "$path")
            elif [[ -L "$path" ]]; then
                target=$(readlink -- "$path")
            fi
            if [[ "$include_inode" == yes ]]; then
                inode=$(stat -c '%i' -- "$path")
            fi
            printf '%s|%s|%s|%s|%s|%s\n' \
                "$relative" "$metadata" "$size" "$digest" "$target" "$inode"
        done < <(find . -mindepth 1 -print0 | sort -z)
    )
}

input_inventory() {
    local directory=$1
    local path relative metadata digest
    (
        cd -- "$directory"
        while IFS= read -r -d '' path; do
            relative=${path#./}
            metadata=$(stat -c '%F|%a|%s' -- "$path")
            digest=$(sha256sum -- "$path")
            digest=${digest%% *}
            printf '%s|%s|%s\n' "$relative" "$metadata" "$digest"
        done < <(find . -type f -print0 | sort -z)
    )
}

compare_inputs() {
    local label=$1
    local left=$2
    local right=$3
    local left_inventory="$scratch/${label}.left.input-inventory"
    local right_inventory="$scratch/${label}.right.input-inventory"
    input_inventory "$left" > "$left_inventory"
    input_inventory "$right" > "$right_inventory"
    if ! cmp -s -- "$left_inventory" "$right_inventory"; then
        echo "$label input inventory differs" >&2
        diff -u -- "$left_inventory" "$right_inventory" >&2 || true
        return 1
    fi
    diff -r --no-dereference -- "$left" "$right" >/dev/null
}

compare_trees() {
    local label=$1
    local left=$2
    local right=$3
    local left_inventory="$scratch/${label}.left.inventory"
    local right_inventory="$scratch/${label}.right.inventory"
    tree_inventory "$left" > "$left_inventory"
    tree_inventory "$right" > "$right_inventory"
    if ! cmp -s -- "$left_inventory" "$right_inventory"; then
        echo "$label tree inventory differs" >&2
        diff -u -- "$left_inventory" "$right_inventory" >&2 || true
        return 1
    fi
    diff -r --no-dereference -- "$left" "$right" >/dev/null
}

source_files() {
    find "$root" \
        \( -path "$root/.git" -o -path "$root/.agents" -o \
           -path "$root/.codex" -o -path "$root/target" -o \
           -path "$root/dist" \) -prune -o -type f -print0
}

copy_source() {
    local destination=$1
    local order=$2
    local source relative
    mkdir -p -- "$destination"
    if [[ "$order" == forward ]]; then
        while IFS= read -r -d '' source; do
            relative=${source#"$root"/}
            mkdir -p -- "$destination/$(dirname -- "$relative")"
            cp -a -- "$source" "$destination/$relative"
        done < <(source_files | sort -z)
    else
        while IFS= read -r -d '' source; do
            relative=${source#"$root"/}
            mkdir -p -- "$destination/$(dirname -- "$relative")"
            cp -a -- "$source" "$destination/$relative"
        done < <(source_files | sort -zr)
    fi
}

copy_profiles() {
    local destination=$1
    local order=$2
    local source
    mkdir -p -- "$destination"
    if [[ "$order" == forward ]]; then
        while IFS= read -r -d '' source; do
            cp -a -- "$source" "$destination/$(basename -- "$source")"
        done < <(
            find "$profile_dir" -maxdepth 1 -type f -name '*.json' -print0 | sort -z
        )
    else
        while IFS= read -r -d '' source; do
            cp -a -- "$source" "$destination/$(basename -- "$source")"
        done < <(
            find "$profile_dir" -maxdepth 1 -type f -name '*.json' -print0 | sort -zr
        )
    fi
}

copy_binaries() {
    local destination=$1
    local order=$2
    local names=(nq nqd nq-host-helper nq-operator-beta-helper)
    local name
    mkdir -p -- "$destination"
    if [[ "$order" == reverse ]]; then
        names=(nq-operator-beta-helper nq-host-helper nqd nq)
    fi
    for name in "${names[@]}"; do
        [[ -f "$bin_dir/$name" && -x "$bin_dir/$name" ]] || {
            echo "missing executable $bin_dir/$name" >&2
            return 1
        }
        cp -a -- "$bin_dir/$name" "$destination/$name"
    done
}

run_case() {
    local label=$1
    local case_root=$2
    local mask=$3
    local locale=$4
    local timezone=$5
    local pid status
    mkdir -p -- "$case_root/tmp" "$case_root/out"
    (
        umask "$mask"
        export LC_ALL="$locale"
        export TZ="$timezone"
        export TMPDIR="$case_root/tmp"
        export SOURCE_DATE_EPOCH="$epoch"
        exec "$case_root/source/scripts/build-release-bundle.sh" \
            "$version" "$arch" "$case_root/bin" \
            "$case_root/profile input" "$case_root/out"
    ) &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if ! measure_scratch; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 1
        fi
        sleep 0.1
    done
    status=0
    wait "$pid" || status=$?
    if (( status != 0 )); then
        echo "$label assembly failed with status $status" >&2
        return "$status"
    fi
    measure_scratch
}

case_a="$scratch/case-a.forward"
case_b="$scratch/case b.reverse"
mkdir -p -- "$case_a" "$case_b"

dist_before="$scratch/dist.before"
dist_after="$scratch/dist.after"
if [[ -d "$root/dist" ]]; then
    tree_inventory "$root/dist" yes > "$dist_before"
else
    printf '%s\n' absent > "$dist_before"
fi

copy_source "$case_a/source" forward
copy_profiles "$case_a/profile input" forward
copy_binaries "$case_a/bin" forward
measure_scratch

copy_source "$case_b/source" reverse
copy_profiles "$case_b/profile input" reverse
copy_binaries "$case_b/bin" reverse
measure_scratch

compare_inputs source-inputs "$case_a/source" "$case_b/source"
compare_inputs profile-inputs "$case_a/profile input" "$case_b/profile input"
compare_inputs binary-inputs "$case_a/bin" "$case_b/bin"

run_case case-a "$case_a" 077 C.utf8 Pacific/Kiritimati
run_case case-b "$case_b" 002 POSIX America/Los_Angeles

package="nq-ng-${version}-linux-${arch}"
tar_name="$package.tar.gz"
deb_name="nq-ng_${version}_${arch}.deb"
artifacts=(
    SHA256SUMS
    "$tar_name"
    "$tar_name.sha256"
    "$deb_name"
    "$deb_name.sha256"
)

for output in "$case_a/out" "$case_b/out"; do
    (
        cd -- "$output"
        sha256sum --check SHA256SUMS >/dev/null
        sha256sum --check "$tar_name.sha256" >/dev/null
        sha256sum --check "$deb_name.sha256" >/dev/null
    )
done

for artifact in "${artifacts[@]}"; do
    cmp -- "$case_a/out/$artifact" "$case_b/out/$artifact"
done

mkdir -p -- "$case_a/extracted/tar" "$case_a/extracted/deb"
mkdir -p -- "$case_b/extracted/tar" "$case_b/extracted/deb"
tar --same-permissions -xzf "$case_a/out/$tar_name" -C "$case_a/extracted/tar"
tar --same-permissions -xzf "$case_b/out/$tar_name" -C "$case_b/extracted/tar"
dpkg-deb --raw-extract "$case_a/out/$deb_name" "$case_a/extracted/deb"
dpkg-deb --raw-extract "$case_b/out/$deb_name" "$case_b/extracted/deb"
measure_scratch

tar --numeric-owner --full-time -tvzf "$case_a/out/$tar_name" \
    > "$scratch/case-a.tar.list"
tar --numeric-owner --full-time -tvzf "$case_b/out/$tar_name" \
    > "$scratch/case-b.tar.list"
cmp -- "$scratch/case-a.tar.list" "$scratch/case-b.tar.list"

dpkg-deb --ctrl-tarfile "$case_a/out/$deb_name" \
    | tar --numeric-owner --full-time -tvf - > "$scratch/case-a.control.list"
dpkg-deb --ctrl-tarfile "$case_b/out/$deb_name" \
    | tar --numeric-owner --full-time -tvf - > "$scratch/case-b.control.list"
cmp -- "$scratch/case-a.control.list" "$scratch/case-b.control.list"

dpkg-deb --fsys-tarfile "$case_a/out/$deb_name" \
    | tar --numeric-owner --full-time -tvf - > "$scratch/case-a.data.list"
dpkg-deb --fsys-tarfile "$case_b/out/$deb_name" \
    | tar --numeric-owner --full-time -tvf - > "$scratch/case-b.data.list"
cmp -- "$scratch/case-a.data.list" "$scratch/case-b.data.list"

tar_a="$case_a/extracted/tar/$package"
tar_b="$case_b/extracted/tar/$package"
deb_a="$case_a/extracted/deb"
deb_b="$case_b/extracted/deb"

compare_trees tar-payloads "$tar_a" "$tar_b"
compare_trees deb-trees "$deb_a" "$deb_b"
compare_trees tar-vs-deb-payload "$tar_a" "$deb_a/usr"

for payload_root in "$tar_a" "$tar_b" "$deb_a/usr" "$deb_b/usr"; do
    (
        cd -- "$payload_root"
        sha256sum --check share/nq/MANIFEST.sha256 >/dev/null
    )
done
cmp -- "$tar_a/share/nq/MANIFEST.sha256" "$tar_b/share/nq/MANIFEST.sha256"
cmp -- "$tar_a/share/nq/MANIFEST.sha256" "$deb_a/usr/share/nq/MANIFEST.sha256"
cmp -- "$deb_a/usr/share/nq/MANIFEST.sha256" "$deb_b/usr/share/nq/MANIFEST.sha256"

for deb_root in "$deb_a" "$deb_b"; do
    (
        cd -- "$deb_root"
        md5sum --check DEBIAN/md5sums >/dev/null
    )
done

# Capture the same state again at the end: the test never publishes to dist/.
if [[ -d "$root/dist" ]]; then
    tree_inventory "$root/dist" yes > "$dist_after"
else
    printf '%s\n' absent > "$dist_after"
fi
cmp -- "$dist_before" "$dist_after"
measure_scratch

tar_digest=$(sha256sum "$case_a/out/$tar_name")
tar_digest=${tar_digest%% *}
deb_digest=$(sha256sum "$case_a/out/$deb_name")
deb_digest=${deb_digest%% *}
manifest_digest=$(sha256sum "$tar_a/share/nq/MANIFEST.sha256")
manifest_digest=${manifest_digest%% *}
payload_files=$(wc -l < "$tar_a/share/nq/MANIFEST.sha256")

printf 'reproducible tar sha256 %s\n' "$tar_digest"
printf 'reproducible deb sha256 %s\n' "$deb_digest"
printf 'embedded manifest sha256 %s (%s payload files)\n' \
    "$manifest_digest" "$payload_files"
printf 'scratch peak %s KiB of %s KiB budget\n' "$peak_kib" "$scratch_limit_kib"
printf 'verified path, insertion-order, umask, locale, timezone, and TMPDIR perturbations\n'
