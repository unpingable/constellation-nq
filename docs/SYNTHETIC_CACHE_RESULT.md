# Retained synthetic-cache result

`nq.synthetic_cache_executor_result/v1` reads one already settled Docket row
and its receipt-bound executor record. It does not send cache HTTP requests,
start containers, repeat an effect, or establish current cache health.

Copy `examples/nq-synthetic-cache-result.toml` and replace every placeholder
with the exact values reopened from the Docket row and executor record. Keep
the Docket database, its WAL files, and the record available read-only. The
scope is closed to `maude.local-compose-workflow/v1`; the helper also requires
the exact evidence schema, successful settlement and outcome, nested
attempt/marker identities, and the receipt recomputed over the canonical
record preimage.

The example's numeric execution account and `allow_same_identity_in_debug` are
only for a local debug build. Replace the uid with the current local uid and
place mutable state below a private `0700` directory whose parent is a safe
sticky temporary directory. A production admission uses its configured
distinct helper account and package-owned paths.

From a clean candidate build, use the ordinary admitted watcher path:

```sh
target/debug/nq --config /absolute/cache-result.toml init
target/debug/nq --config /absolute/cache-result.toml watcher test synthetic-cache-result
target/debug/nq --config /absolute/cache-result.toml watcher admit synthetic-cache-result
target/debug/nq --config /absolute/cache-result.toml --json collect synthetic-cache-result
```

`watcher test` exercises acquisition without admission. `collect` retains the
actual report and detector evaluation. The report and observation timestamp is
the bounded retained-record read time. Its payload separately preserves the
receipt-bound `executor_observed_at_unix_ms`, and the detector uses that
original effect time for freshness; copying the record does not refresh it. Evidence
older than the profile's 60-second reliance interval yields
`cannot_evaluate`.

For a fresh admitted instance, `diagnostics execute` uses the same collection
and detector path while atomically retaining an `nq.diagnostic_execution.v2`
artifact. Reopen and qualify its returned `artifact_id` with:

```sh
target/debug/nq --config /absolute/cache-result.toml diagnostics execute synthetic-cache-result > diagnostic.json
target/debug/nq --config /absolute/cache-result.toml --json diagnostics inspect sha256:ARTIFACT
target/debug/nq --config /absolute/cache-result.toml --json diagnostics qualify sha256:ARTIFACT
```

Qualification establishes exact local NQ admission provenance, not freshness,
reliance, authorization, or action. Do not represent ordinary `collect`
output, a copied record, or a substitution fixture as that artifact.
