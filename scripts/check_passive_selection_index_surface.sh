#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
helper="$root/crates/nq-passive-load-helper/src/lib.rs"
main="$root/crates/nq-passive-load-helper/src/main.rs"
doctrine="$root/docs/PASSIVE_LOAD_BOUNDED_SELECTION_CUSTODY_V1.md"

fail() {
  echo "passive-selection-index-surface: $*" >&2
  exit 1
}

for schema in \
  nq.passive_load_selection_index_entry.v1 \
  nq.passive_load_selection_manifest.v1 \
  nq.passive_load_selection_index_current.v1 \
  nq.passive_load_selection_index_update.v1; do
  rg -q "$schema" "$helper" || fail "missing $schema"
done

rg -q 'select_indexed_sample' "$helper" || fail "bounded indexed selector absent"
rg -q 'sample_document_digest' "$helper" || fail "index does not bind exact canonical bytes"
rg -q 'verify_sample\(&sample, public, expected\)' "$helper" \
  || fail "selected sample does not cross exact signature/identity verification"
rg -q 'update-in-progress.json' "$helper" || fail "crash marker absent"
rg -q 'LockShared' "$helper" || fail "selection/append concurrency is not explicit"
rg -q 'reconstruct_selection_index' "$helper" "$main" \
  || fail "derived-index reconstruction surface absent"
rg -q 'NoEligibleSample|SelectionIndexMissing|SelectionIndexCorrupt|SelectionIndexStale|CanonicalSampleMissing|CanonicalSampleMismatch' "$helper" \
  || fail "closed failure taxonomy absent"
rg -q 'Routine work is' "$doctrine" || fail "bounded hot-path law undocumented"
rg -q 'No charter, deployment, unattended enablement' "$doctrine" \
  || fail "qualification/deployment boundary undocumented"

if rg -qi 'delete.*canonical sample|fallback.*nq-host-helper|timeoutstartsec.*increase' "$doctrine"; then
  fail "selection doctrine weakens retain-all, provider separation, or service bounds"
fi

python3 - "$helper" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
eligible = source[source.index("pub fn eligible_sample_at("):source.index("/// Serve one exchange", source.index("pub fn eligible_sample_at("))]
provider = source[source.index("fn select_sample("):source.index("struct ExpectedSampleIdentity", source.index("fn select_sample("))]
if "load_samples(" in eligible or "load_samples(" in provider:
    raise SystemExit("routine selection still scans canonical retained custody")
if "select_indexed_sample(" not in eligible or "select_indexed_sample(" not in provider:
    raise SystemExit("routine selection does not use the bounded index")
PY

echo "passive-selection-index-surface: immutable derived index, exact selected-object verification, crash refusal, and no authority widening present"
