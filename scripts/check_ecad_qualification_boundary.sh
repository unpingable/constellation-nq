#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
source_file="$root/crates/nq-core/src/ecad_qualification.rs"
deck_schema="$root/operational-contract/schemas/nq.ecad-claim-deck.v1.schema.json"
profile_schema="$root/operational-contract/schemas/nq.ecad-qualification-profile.v1.schema.json"
temporary=
trap 'test -z "$temporary" || rm -f "$temporary"' EXIT

if test "${1:-}" = "--negative-control"; then
  temporary=$(mktemp)
  cp "$source_file" "$temporary"
  printf '\npub struct InvalidAggregate { pub aggregate_health: bool }\n' >> "$temporary"
  source_file="$temporary"
fi

rg -q 'bb75c4325f903f2c544e9758b5ea8d30c8bbc773' "$source_file"
rg -q 'fa51387ed569064281f63576e46de44628e2833bfbec2955fc7d990209ae173f' "$source_file"
rg -q '7f9ba67910df6962e4e02cb2e1fa75562a59889e16cef3c9133c90aa090cea0d' "$source_file"
rg -q 'validate_distant_custody' "$source_file"
rg -q 'recompute_silicon_qualification' "$source_file"
rg -q 'artifact != &recomputed' "$source_file"
rg -q '"const"' "$deck_schema"
rg -q '"const"' "$profile_schema"

if rg -n 'pub (aggregate_health|overall_health|remediation|authority|dispatch|retry):' "$source_file"; then
  echo 'NQ ECAD checker absorbed an aggregate or authority/control field' >&2
  exit 1
fi
if test "${1:-}" = "--negative-control"; then
  echo 'negative control was not detected' >&2
  exit 1
fi
echo 'NQ ECAD exact-evidence boundary: pass'

