#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

fail() {
  echo "substrate origin boundary: $*" >&2
  exit 1
}

origin="$root/crates/nq-core/src/substrate_origin.rs"
engine="$root/crates/nq-core/src/engine.rs"
store="$root/crates/nq-store/src/lib.rs"

test -f "$origin" || fail "typed origin contract missing"
rg -q 'SubstrateCoordinateKindV1' "$origin" || fail "closed coordinate kind missing"
rg -q 'Ed25519AcquisitionChallenge' "$origin" || fail "closed verification method missing"
rg -q 'LinodeInstanceMetadataV1' "$origin" || fail "closed Linode metadata profile missing"
rg -q 'http://169\.254\.169\.254/v1/instance' "$origin" || fail "fixed Linode metadata endpoint missing"
rg -q 'host UUID is supplemental evidence and is not part of the qualified coordinate' "$origin" \
  || fail "Linode host UUID nonclaim missing"
rg -q 'SubstrateOriginAttestationSourceV1' "$origin" || fail "origin source interface missing"
rg -q 'commit_substrate_origin_dispatch' "$engine" || fail "atomic origin/dispatch fence missing"
rg -q 'provider_invocation_started' "$engine" || fail "provider invocation fence missing"
rg -q 'substrate_origin_acquisition_intents' "$store" || fail "durable origin intent missing"

# Production origin code is verification-only. Test-only synthetic signing is
# below cfg(test) and deliberately excluded from this structural scan.
if awk '/#\[cfg\(test\)\]/{exit} {print}' "$origin" \
  | rg -n 'SigningKey|Command::new|cron|crontab|pub (hostname|dns|ip|boot_id|machine_id|current_substrate):'; then
  fail "signing, execution, scheduler, heuristic, or mutable origin shortcut present"
fi
if rg -n 'origin_authorized[[:space:]]*=[[:space:]]*true|subject.*==.*substrate|producer.*==.*substrate|vantage.*==.*substrate' \
  "$engine" "$origin"; then
  fail "configured identity or mutable flag is used as substrate proof"
fi
if rg -n 'ssh|curl|wget|systemctl|docker|podman' "$origin"; then
  fail "origin contract grew a remote/effectful acquisition surface"
fi
if rg -n 'LINODE_METADATA_INSTANCE_ENDPOINT_V1.*(String|PathBuf)|pub (label|region|hostname|dns|ip):' "$origin"; then
  fail "Linode profile exposes a configurable endpoint or naming-based coordinate"
fi

echo "substrate origin boundary: ok"
