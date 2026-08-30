#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
source_file="$root/crates/nq-core/src/operational_qualification.rs"
temporary=
trap 'test -z "$temporary" || rm -f "$temporary"' EXIT

if test "${1:-}" = "--negative-control"; then
  temporary=$(mktemp)
  cp "$source_file" "$temporary"
  printf '\npub struct InvalidWidening { pub aggregate_health: bool }\n' >> "$temporary"
  source_file="$temporary"
fi

rg -q 'nightshift_claim_widening' "$source_file"
rg -q 'failure_as_world_claim' "$source_file"
rg -q 'payload schema is unknown and remains raw-only' "$source_file"
rg -q 'producer class alone grants no evidentiary precedence' "$source_file"
rg -q 'producer_identity_digest' "$source_file"
rg -q 'public_key_digest' "$source_file"
rg -q 'subject_basis_kind_mismatch' "$source_file"
rg -q 'unsupported_subject_basis_contract' "$source_file"
rg -q 'coverage_incomplete' "$source_file"
rg -q 'receiver_custody_inversion' "$source_file"
rg -q 'evaluation_time_inversion' "$source_file"

if rg -n 'pub (aggregate_health|overall_health|temporal_currentness|remediation|authority):' "$source_file"; then
  echo 'NQ operational qualifier absorbed another office or an aggregate' >&2
  exit 1
fi
if rg -n 'producer_class\s*==' "$source_file"; then
  echo 'producer source class gained semantic precedence' >&2
  exit 1
fi
if test "${1:-}" = "--negative-control"; then
  echo 'negative control was not detected' >&2
  exit 1
fi
echo 'NQ operational qualification boundary: pass'
