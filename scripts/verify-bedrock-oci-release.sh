#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-}"
die() { printf 'BEDROCK release verification refusal: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"; }
for command_name in jq sha256sum stat tar gzip find diff mktemp; do require_command "${command_name}"; done
test -n "${ROOT}" && test -d "${ROOT}" || die "usage: verify-bedrock-oci-release.sh RELEASE_ROOT"
ROOT="$(cd "${ROOT}" && pwd -P)"
test -f "${ROOT}/release-digests.sha256" || die "release digest manifest is absent"
(cd "${ROOT}" && sha256sum -c release-digests.sha256 >/dev/null) || die "retained release digest mismatch"

jq -e '.schema == "nq.bedrock_oci_input_pins.v1" and (.inputs | length == 7)' "${ROOT}/input-pins.json" >/dev/null || die "input pin manifest is invalid"
while IFS=$'\t' read -r input_id destination mode size expected_digest; do
    path="${ROOT}/inputs${destination}"
    test -f "${path}" && test ! -L "${path}" || die "retained input ${input_id} is absent or symbolic"
    test "$(stat -c %s "${path}")" = "${size}" || die "retained input ${input_id} size mismatch"
    test "$(stat -c %a "${path}")" = "${mode#0}" || die "retained input ${input_id} mode mismatch"
    test "$(sha256sum "${path}" | awk '{print $1}')" = "${expected_digest}" || die "retained input ${input_id} digest mismatch"
done < <(jq -r '.inputs[] | [.id,.destination,.mode,(.size_bytes|tostring),.sha256] | @tsv' "${ROOT}/input-pins.json")

test "$(cat "${ROOT}/layout/oci-layout")" = '{"imageLayoutVersion":"1.0.0"}' || die "OCI layout version mismatch"
manifest_digest="$(jq -er '.manifests | if length == 1 then .[0].digest else error("cardinality") end' "${ROOT}/layout/index.json")"
manifest_size="$(jq -er '.manifests[0].size' "${ROOT}/layout/index.json")"; manifest="${ROOT}/layout/blobs/sha256/${manifest_digest#sha256:}"
test "sha256:$(sha256sum "${manifest}" | awk '{print $1}')" = "${manifest_digest}" || die "manifest digest mismatch"
test "$(stat -c %s "${manifest}")" = "${manifest_size}" || die "manifest size mismatch"
config_digest="$(jq -er '.config.digest' "${manifest}")"; config_size="$(jq -er '.config.size' "${manifest}")"; config="${ROOT}/layout/blobs/sha256/${config_digest#sha256:}"
test "sha256:$(sha256sum "${config}" | awk '{print $1}')" = "${config_digest}" || die "config digest mismatch"
test "$(stat -c %s "${config}")" = "${config_size}" || die "config size mismatch"
test "$(jq -er '.layers | length' "${manifest}")" = 1 || die "layer cardinality mismatch"
layer_digest="$(jq -er '.layers[0].digest' "${manifest}")"; layer_size="$(jq -er '.layers[0].size' "${manifest}")"; layer="${ROOT}/layout/blobs/sha256/${layer_digest#sha256:}"
test "sha256:$(sha256sum "${layer}" | awk '{print $1}')" = "${layer_digest}" || die "layer digest mismatch"
test "$(stat -c %s "${layer}")" = "${layer_size}" || die "layer size mismatch"
diff_id="$(jq -er '.rootfs.diff_ids | if length == 1 then .[0] else error("cardinality") end' "${config}")"
test "sha256:$(gzip -cd "${layer}" | sha256sum | awk '{print $1}')" = "${diff_id}" || die "layer diff-id mismatch"

facts="${ROOT}/oci-artifact-facts.json"
jq -e --arg manifest "${manifest_digest}" --arg config "${config_digest}" --arg layer "${layer_digest}" --arg diff_id "${diff_id}" \
    '.schema == "nq.bedrock_oci_artifact_facts.v2" and .manifest_digest == $manifest and .image_config_digest == $config and .layers[0].digest == $layer and .layers[0].diff_id == $diff_id and (.copied_inputs | length == 7)' "${facts}" >/dev/null \
    || die "artifact facts do not bind the retained OCI graph"
archive_digest="$(jq -er '.archive.digest' "${facts}")"; archive="$(find "${ROOT}" -maxdepth 1 -type f -name 'bedrock-nq-*.oci.tar' -print)"
test -n "${archive}" && test "$(printf '%s\n' "${archive}" | wc -l)" = 1 || die "OCI archive cardinality mismatch"
test "sha256:$(sha256sum "${archive}" | awk '{print $1}')" = "${archive_digest}" || die "OCI archive digest mismatch"
scratch="$(mktemp -d)"; trap 'rm -rf "${scratch}"' EXIT
tar -xf "${archive}" -C "${scratch}"
diff -qr --no-dereference "${ROOT}/layout" "${scratch}" >/dev/null || die "archive does not reopen to the retained layout"
printf '%s\n' "BEDROCK retained OCI release verified: ${manifest_digest}"
