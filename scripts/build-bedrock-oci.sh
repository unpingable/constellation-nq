#!/usr/bin/env bash
set -euo pipefail

SLUG="k3s-live-origin-capacity-qualification-v1"
LAB_ROOT="${BEDROCK_LAB_ROOT:-/data/git/.bedrock-lab/${SLUG}}"
OUTPUT_ROOT="${LAB_ROOT}/oci"
SOURCE_ROOT="$(git rev-parse --show-toplevel)"
SOURCE_COMMIT="$(git rev-parse HEAD)"
SOURCE_EPOCH="$(git show -s --format=%ct HEAD)"
NQ_BINARY="${SOURCE_ROOT}/target/release/nq"
PASSIVE_HELPER="${SOURCE_ROOT}/target/release/nq-passive-load-helper"
IMAGE_REPOSITORY="bedrock.local/nq"

die() {
    printf 'BEDROCK refusal: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"
}

for command_name in git jq tar gzip sha256sum install; do
    require_command "${command_name}"
done

test -x "${NQ_BINARY}" || die "release nq executable is absent"
test -x "${PASSIVE_HELPER}" || die "release passive helper is absent"
test -z "$(git status --short)" || die "source worktree is not clean"

layout="${OUTPUT_ROOT}/layout"
rootfs="${OUTPUT_ROOT}/rootfs"
facts="${OUTPUT_ROOT}/oci-artifact-facts.json"
archive="${OUTPUT_ROOT}/bedrock-nq-${SOURCE_COMMIT}.oci.tar"
test ! -e "${OUTPUT_ROOT}" || die "OCI output already exists: ${OUTPUT_ROOT}"
mkdir -p \
    "${layout}/blobs/sha256" \
    "${rootfs}/usr/bin" \
    "${rootfs}/usr/lib/nq/helpers" \
    "${rootfs}/lib64" \
    "${rootfs}/lib/x86_64-linux-gnu" \
    "${rootfs}/etc/nq"

install -m 0755 "${NQ_BINARY}" "${rootfs}/usr/bin/nq"
install -m 0755 "${PASSIVE_HELPER}" "${rootfs}/usr/lib/nq/helpers/nq-passive-load-helper"
install -m 0755 /lib64/ld-linux-x86-64.so.2 "${rootfs}/lib64/ld-linux-x86-64.so.2"
install -m 0644 /lib/x86_64-linux-gnu/libc.so.6 "${rootfs}/lib/x86_64-linux-gnu/libc.so.6"
install -m 0644 /lib/x86_64-linux-gnu/libm.so.6 "${rootfs}/lib/x86_64-linux-gnu/libm.so.6"
install -m 0644 /lib/x86_64-linux-gnu/libgcc_s.so.1 "${rootfs}/lib/x86_64-linux-gnu/libgcc_s.so.1"

nq_digest="sha256:$(sha256sum "${NQ_BINARY}" | awk '{print $1}')"
helper_digest="sha256:$(sha256sum "${PASSIVE_HELPER}" | awk '{print $1}')"
jq -cn \
    --arg schema nq.bedrock_image_identity.v1 \
    --arg campaign BEDROCK \
    --arg slug "${SLUG}" \
    --arg source_commit "${SOURCE_COMMIT}" \
    --arg nq_executable_digest "${nq_digest}" \
    --arg passive_helper_digest "${helper_digest}" \
    --arg invocation '/usr/bin/nq --version' \
    '{schema:$schema,campaign:$campaign,slug:$slug,source_commit:$source_commit,nq_executable_digest:$nq_executable_digest,passive_helper_digest:$passive_helper_digest,default_invocation:$invocation}' \
    >"${rootfs}/etc/nq/bedrock-image.json"
chmod 0444 "${rootfs}/etc/nq/bedrock-image.json"
configuration_digest="sha256:$(sha256sum "${rootfs}/etc/nq/bedrock-image.json" | awk '{print $1}')"

layer_tar="${OUTPUT_ROOT}/layer.tar"
layer_gzip="${OUTPUT_ROOT}/layer.tar.gz"
tar \
    --sort=name \
    --format=gnu \
    --mtime="@${SOURCE_EPOCH}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "${rootfs}" \
    -cf "${layer_tar}" .
gzip -n -9 -c "${layer_tar}" >"${layer_gzip}"
layer_diff_id="sha256:$(sha256sum "${layer_tar}" | awk '{print $1}')"
layer_digest="sha256:$(sha256sum "${layer_gzip}" | awk '{print $1}')"
layer_size="$(stat -c %s "${layer_gzip}")"

created="$(git show -s --format=%cI HEAD)"
config_json="${OUTPUT_ROOT}/config.json"
jq -cn \
    --arg created "${created}" \
    --arg diff_id "${layer_diff_id}" \
    --arg revision "${SOURCE_COMMIT}" \
    --arg nq_digest "${nq_digest}" \
    --arg helper_digest "${helper_digest}" \
    '{architecture:"amd64",os:"linux",created:$created,config:{User:"65532:65532",Env:["PATH=/usr/bin:/usr/lib/nq/helpers"],Entrypoint:["/usr/bin/nq"],Cmd:["--version"],WorkingDir:"/",Labels:{"org.opencontainers.image.revision":$revision,"org.opencontainers.image.source":"BEDROCK/k3s-live-origin-capacity-qualification-v1","nq.bedrock.nq-digest":$nq_digest,"nq.bedrock.passive-helper-digest":$helper_digest}},rootfs:{type:"layers",diff_ids:[$diff_id]},history:[{created:$created,created_by:"scripts/build-bedrock-oci.sh",comment:"exact BEDROCK nq and passive helper"}]}' \
    >"${config_json}"
config_digest="sha256:$(sha256sum "${config_json}" | awk '{print $1}')"
config_size="$(stat -c %s "${config_json}")"

manifest_json="${OUTPUT_ROOT}/manifest.json"
jq -cn \
    --arg config_digest "${config_digest}" \
    --argjson config_size "${config_size}" \
    --arg layer_digest "${layer_digest}" \
    --argjson layer_size "${layer_size}" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$config_digest,size:$config_size},layers:[{mediaType:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$layer_digest,size:$layer_size}]}' \
    >"${manifest_json}"
manifest_digest="sha256:$(sha256sum "${manifest_json}" | awk '{print $1}')"
manifest_size="$(stat -c %s "${manifest_json}")"

install -m 0444 "${config_json}" "${layout}/blobs/sha256/${config_digest#sha256:}"
install -m 0444 "${manifest_json}" "${layout}/blobs/sha256/${manifest_digest#sha256:}"
install -m 0444 "${layer_gzip}" "${layout}/blobs/sha256/${layer_digest#sha256:}"
printf '%s\n' '{"imageLayoutVersion":"1.0.0"}' >"${layout}/oci-layout"
jq -cn \
    --arg digest "${manifest_digest}" \
    --argjson size "${manifest_size}" \
    --arg ref "${IMAGE_REPOSITORY}:${SOURCE_COMMIT}" \
    '{schemaVersion:2,mediaType:"application/vnd.oci.image.index.v1+json",manifests:[{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$digest,size:$size,annotations:{"org.opencontainers.image.ref.name":$ref},platform:{architecture:"amd64",os:"linux"}}]}' \
    >"${layout}/index.json"

tar \
    --sort=name \
    --format=gnu \
    --mtime="@${SOURCE_EPOCH}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "${layout}" \
    -cf "${archive}" .

jq -cn \
    --arg schema nq.bedrock_oci_artifact_facts.v1 \
    --arg image_reference "${IMAGE_REPOSITORY}@${manifest_digest}" \
    --arg manifest_digest "${manifest_digest}" \
    --arg image_config_digest "${config_digest}" \
    --arg layer_digest "${layer_digest}" \
    --argjson layer_size "${layer_size}" \
    --arg source_commit "${SOURCE_COMMIT}" \
    --arg nq_digest "${nq_digest}" \
    --arg helper_digest "${helper_digest}" \
    --arg configuration_digest "${configuration_digest}" \
    '{schema:$schema,image_reference:$image_reference,object_kind:"image_manifest",manifest_digest:$manifest_digest,selected_manifest_digest:null,image_config_digest:$image_config_digest,platform:{os:"linux",architecture:"amd64",variant:null},layers:[{media_type:"application/vnd.oci.image.layer.v1.tar+gzip",digest:$layer_digest,size_bytes:$layer_size}],source_commit:$source_commit,nq_executable_digest:$nq_digest,passive_helper_digest:$helper_digest,configuration_digests:{bedrock_image_v1:$configuration_digest}}' \
    >"${facts}"

sha256sum \
    "${archive}" \
    "${facts}" \
    "${layout}/index.json" \
    "${layout}/oci-layout" \
    >"${OUTPUT_ROOT}/oci-digests.sha256"
printf '%s\n' "${manifest_digest}" >"${OUTPUT_ROOT}/manifest-digest"
printf '%s\n' "${IMAGE_REPOSITORY}@${manifest_digest}" >"${OUTPUT_ROOT}/immutable-image-reference"
