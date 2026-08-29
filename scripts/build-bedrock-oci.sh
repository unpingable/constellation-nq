#!/usr/bin/env bash
set -euo pipefail

SLUG="quiet-ember-release-custody-successor-v1"
LAB_ROOT="${BEDROCK_LAB_ROOT:-/data/git/.bedrock-lab/${SLUG}}"
OUTPUT_ROOT="${LAB_ROOT}/oci"
SOURCE_ROOT="$(git rev-parse --show-toplevel)"
SOURCE_COMMIT="${BEDROCK_SOURCE_COMMIT:-$(git rev-parse HEAD)}"
SOURCE_EPOCH="$(git show -s --format=%ct "${SOURCE_COMMIT}")"
PIN_FILE="${BEDROCK_INPUT_PINS:-${SOURCE_ROOT}/release/quiet-ember-oci-input-pins-v1.json}"
INPUT_ROOT="${BEDROCK_INPUT_ROOT:-}"
IMAGE_REPOSITORY="bedrock.local/nq"

die() { printf 'BEDROCK refusal: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"; }

for command_name in git jq tar gzip sha256sum install stat find sort xargs rustc cargo; do
    require_command "${command_name}"
done
git cat-file -e "${SOURCE_COMMIT}^{commit}" || die "source commit is unavailable"
test -z "$(git status --short)" || die "source worktree is not clean"
jq -e '
  keys == ["inputs","schema"] and
  .schema == "nq.bedrock_oci_input_pins.v1" and
  (.inputs | type == "array" and length == 7) and
  ([.inputs[].destination] | unique | length == 7) and
  ([.inputs[] | {id,destination,mode}] | sort_by(.id)) == [
    {"id":"dynamic_loader","destination":"/lib64/ld-linux-x86-64.so.2","mode":"0755"},
    {"id":"libc","destination":"/lib/x86_64-linux-gnu/libc.so.6","mode":"0644"},
    {"id":"libgcc_s","destination":"/lib/x86_64-linux-gnu/libgcc_s.so.1","mode":"0644"},
    {"id":"libm","destination":"/lib/x86_64-linux-gnu/libm.so.6","mode":"0644"},
    {"id":"nq","destination":"/usr/bin/nq","mode":"0755"},
    {"id":"passive_helper","destination":"/usr/lib/nq/helpers/nq-passive-load-helper","mode":"0755"},
    {"id":"runtime_carrier","destination":"/usr/bin/nq-bedrock-runtime-carrier","mode":"0755"}
  ] and
  all(.inputs[];
    keys == ["destination","id","mode","sha256","size_bytes","source"] and
    (.id | type == "string" and length > 0) and
    (.source | type == "string" and length > 0) and
    (.destination | type == "string" and startswith("/") and (contains("..") | not)) and
    (.mode == "0755" or .mode == "0644") and
    (.size_bytes | type == "number" and . >= 0 and floor == .) and
    (.sha256 | test("^[0-9a-f]{64}$")))
' "${PIN_FILE}" >/dev/null || die "input pins are not the closed V1 shape"

layout="${OUTPUT_ROOT}/layout"
rootfs="${OUTPUT_ROOT}/rootfs"
inputs="${OUTPUT_ROOT}/inputs"
facts="${OUTPUT_ROOT}/oci-artifact-facts.json"
archive="${OUTPUT_ROOT}/bedrock-nq-${SOURCE_COMMIT}.oci.tar"
test ! -e "${OUTPUT_ROOT}" || die "OCI output already exists: ${OUTPUT_ROOT}"
mkdir -p "${layout}/blobs/sha256" "${rootfs}/etc/nq" "${inputs}"
install -m 0444 "${PIN_FILE}" "${OUTPUT_ROOT}/input-pins.json"

while IFS=$'\t' read -r input_id source destination mode size expected_digest; do
    if test -n "${INPUT_ROOT}"; then source="${INPUT_ROOT}${destination}"
    elif [[ "${source}" != /* ]]; then source="${SOURCE_ROOT}/${source}"; fi
    test -f "${source}" && test ! -L "${source}" || die "input ${input_id} is not a regular nonsymlink file"
    test "$(stat -c %s "${source}")" = "${size}" || die "input ${input_id} size differs from its pin"
    test "$(sha256sum "${source}" | awk '{print $1}')" = "${expected_digest}" || die "input ${input_id} content differs from its pin"
    install -D -m "${mode}" "${source}" "${inputs}${destination}"
    install -D -m "${mode}" "${inputs}${destination}" "${rootfs}${destination}"
    test "$(stat -c %s "${inputs}${destination}")" = "${size}" || die "retained input ${input_id} size changed"
    test "$(sha256sum "${inputs}${destination}" | awk '{print $1}')" = "${expected_digest}" || die "retained input ${input_id} content changed"
done < <(jq -r '.inputs[] | [.id,.source,.destination,.mode,(.size_bytes|tostring),.sha256] | @tsv' "${PIN_FILE}")

nq_digest="sha256:$(jq -r '.inputs[] | select(.id == "nq") | .sha256' "${PIN_FILE}")"
helper_digest="sha256:$(jq -r '.inputs[] | select(.id == "passive_helper") | .sha256' "${PIN_FILE}")"
carrier_digest="sha256:$(jq -r '.inputs[] | select(.id == "runtime_carrier") | .sha256' "${PIN_FILE}")"
pins_digest="sha256:$(sha256sum "${OUTPUT_ROOT}/input-pins.json" | awk '{print $1}')"
jq -cn --arg schema nq.bedrock_image_identity.v1 --arg campaign BEDROCK --arg slug "${SLUG}" \
    --arg source_commit "${SOURCE_COMMIT}" --arg nq_executable_digest "${nq_digest}" \
    --arg passive_helper_digest "${helper_digest}" --arg runtime_carrier_digest "${carrier_digest}" \
    --arg input_pins_digest "${pins_digest}" \
    --arg invocation '/usr/bin/nq-bedrock-runtime-carrier --binding /run/nq/binding.json --release /run/nq/release.json --state /var/lib/nq/carrier/state.sqlite3 --executable /usr/bin/nq' \
    '{schema:$schema,campaign:$campaign,slug:$slug,source_commit:$source_commit,nq_executable_digest:$nq_executable_digest,passive_helper_digest:$passive_helper_digest,runtime_carrier_digest:$runtime_carrier_digest,input_pins_digest:$input_pins_digest,default_invocation:$invocation}' \
    >"${rootfs}/etc/nq/bedrock-image.json"
chmod 0444 "${rootfs}/etc/nq/bedrock-image.json"
configuration_digest="sha256:$(sha256sum "${rootfs}/etc/nq/bedrock-image.json" | awk '{print $1}')"

layer_tar="${OUTPUT_ROOT}/layer.tar"; layer_gzip="${OUTPUT_ROOT}/layer.tar.gz"
LC_ALL=C tar --sort=name --format=gnu --mtime="@${SOURCE_EPOCH}" --owner=0 --group=0 --numeric-owner -C "${rootfs}" -cf "${layer_tar}" .
gzip -n -9 -c "${layer_tar}" >"${layer_gzip}"
layer_diff_id="sha256:$(sha256sum "${layer_tar}" | awk '{print $1}')"
layer_digest="sha256:$(sha256sum "${layer_gzip}" | awk '{print $1}')"; layer_size="$(stat -c %s "${layer_gzip}")"

created="$(git show -s --format=%cI "${SOURCE_COMMIT}")"; config_json="${OUTPUT_ROOT}/config.json"
jq -cn --arg created "${created}" --arg diff_id "${layer_diff_id}" --arg revision "${SOURCE_COMMIT}" \
    --arg nq_digest "${nq_digest}" --arg helper_digest "${helper_digest}" --arg carrier_digest "${carrier_digest}" --arg pins_digest "${pins_digest}" \
    '{architecture:"amd64",os:"linux",created:$created,config:{User:"65532:65532",Env:["PATH=/usr/bin:/usr/lib/nq/helpers"],Entrypoint:["/usr/bin/nq-bedrock-runtime-carrier"],Cmd:["--binding","/run/nq/binding.json","--release","/run/nq/release.json","--state","/var/lib/nq/carrier/state.sqlite3","--executable","/usr/bin/nq"],WorkingDir:"/",Labels:{"org.opencontainers.image.revision":$revision,"org.opencontainers.image.source":"BEDROCK/quiet-ember-release-custody-successor-v1","nq.bedrock.nq-digest":$nq_digest,"nq.bedrock.passive-helper-digest":$helper_digest,"nq.bedrock.runtime-carrier-digest":$carrier_digest,"nq.bedrock.input-pins-digest":$pins_digest}},rootfs:{type:"layers",diff_ids:[$diff_id]},history:[{created:$created,created_by:"scripts/build-bedrock-oci.sh",comment:"content-pinned BEDROCK NQ, passive helper, inert carrier, and runtime libraries"}]}' >"${config_json}"
config_digest="sha256:$(sha256sum "${config_json}" | awk '{print $1}')"; config_size="$(stat -c %s "${config_json}")"

manifest_json="${OUTPUT_ROOT}/manifest.json"
jq -cn --arg config_digest "${config_digest}" --argjson config_size "${config_size}" --arg layer_digest "${layer_digest}" --argjson layer_size "${layer_size}" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$config_digest,size:$config_size},layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$layer_digest,size:$layer_size}]}' >"${manifest_json}"
manifest_digest="sha256:$(sha256sum "${manifest_json}" | awk '{print $1}')"; manifest_size="$(stat -c %s "${manifest_json}")"
install -m 0444 "${config_json}" "${layout}/blobs/sha256/${config_digest#sha256:}"
install -m 0444 "${manifest_json}" "${layout}/blobs/sha256/${manifest_digest#sha256:}"
install -m 0444 "${layer_gzip}" "${layout}/blobs/sha256/${layer_digest#sha256:}"
printf '%s\n' '{"imageLayoutVersion":"1.0.0"}' >"${layout}/oci-layout"
jq -cn --arg digest "${manifest_digest}" --argjson size "${manifest_size}" --arg ref "${IMAGE_REPOSITORY}:${SOURCE_COMMIT}" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",manifests:[{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$digest,size:$size,annotations:{"org.opencontainers.image.ref.name":$ref},platform:{architecture:"amd64",os:"linux"}}]}' >"${layout}/index.json"
LC_ALL=C tar --sort=name --format=gnu --mtime="@${SOURCE_EPOCH}" --owner=0 --group=0 --numeric-owner -C "${layout}" -cf "${archive}" .

tool_facts="$(jq -cn --arg rustc "$(rustc -Vv)" --arg cargo "$(cargo -V)" --arg jq "$(jq --version)" \
    --arg tar "$(tar --version | head -n 1)" --arg gzip "$(gzip --version | head -n 1)" --arg sha256sum "$(sha256sum --version | head -n 1)" \
    '{rustc:$rustc,cargo:$cargo,jq:$jq,tar:$tar,gzip:$gzip,sha256sum:$sha256sum}')"
input_facts="$(jq -c '.inputs' "${PIN_FILE}")"
jq -cn --arg schema nq.bedrock_oci_artifact_facts.v2 --arg image_reference "${IMAGE_REPOSITORY}@${manifest_digest}" \
    --arg manifest_digest "${manifest_digest}" --argjson manifest_size "${manifest_size}" --arg image_config_digest "${config_digest}" --argjson config_size "${config_size}" \
    --arg layer_digest "${layer_digest}" --arg layer_diff_id "${layer_diff_id}" --argjson layer_size "${layer_size}" --arg source_commit "${SOURCE_COMMIT}" \
    --arg nq_digest "${nq_digest}" --arg helper_digest "${helper_digest}" --arg carrier_digest "${carrier_digest}" --arg configuration_digest "${configuration_digest}" \
    --arg input_pins_digest "${pins_digest}" --arg archive_digest "sha256:$(sha256sum "${archive}" | awk '{print $1}')" --argjson archive_size "$(stat -c %s "${archive}")" \
    --argjson inputs "${input_facts}" --argjson toolchain "${tool_facts}" \
    '{schema:$schema,image_reference:$image_reference,object_kind:"image_manifest",manifest_digest:$manifest_digest,manifest_size_bytes:$manifest_size,selected_manifest_digest:null,image_config_digest:$image_config_digest,image_config_size_bytes:$config_size,platform:{os:"linux",architecture:"amd64",variant:null},layers:[{media_type:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$layer_digest,diff_id:$layer_diff_id,size_bytes:$layer_size}],source_commit:$source_commit,nq_executable_digest:$nq_digest,passive_helper_digest:$helper_digest,runtime_carrier_digest:$carrier_digest,configuration_digests:{bedrock_image_v1:$configuration_digest,input_pins_v1:$input_pins_digest},archive:{digest:$archive_digest,size_bytes:$archive_size},copied_inputs:$inputs,toolchain:$toolchain}' >"${facts}"

rm -rf "${rootfs}" "${layer_tar}" "${layer_gzip}" "${config_json}" "${manifest_json}"
printf '%s\n' "${manifest_digest}" >"${OUTPUT_ROOT}/manifest-digest"
printf '%s\n' "${IMAGE_REPOSITORY}@${manifest_digest}" >"${OUTPUT_ROOT}/immutable-image-reference"
(
    cd "${OUTPUT_ROOT}"
    LC_ALL=C find layout inputs -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    sha256sum "$(basename "${archive}")" input-pins.json oci-artifact-facts.json manifest-digest immutable-image-reference
) >"${OUTPUT_ROOT}/release-digests.sha256"
"${SOURCE_ROOT}/scripts/verify-bedrock-oci-release.sh" "${OUTPUT_ROOT}"
