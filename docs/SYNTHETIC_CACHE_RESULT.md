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

From a clean candidate build, use the ordinary admitted watcher path:

```sh
target/debug/nq --config /absolute/cache-result.toml init
target/debug/nq --config /absolute/cache-result.toml watcher test synthetic-cache-result
target/debug/nq --config /absolute/cache-result.toml watcher admit synthetic-cache-result
target/debug/nq --config /absolute/cache-result.toml --json collect synthetic-cache-result
```

`watcher test` exercises acquisition without admission. `collect` retains the
actual report and detector evaluation. The detector uses the executor record's
original observation time; copying the record does not refresh it. Evidence
older than the profile's 60-second reliance interval yields
`cannot_evaluate`.

The current `diagnostics execute` artifact producer remains sealed to
`nq.host/v1`. Consequently this profile cannot yet produce the locally owned
`nq.diagnostic_execution.v2` artifact required by `diagnostics qualify` and
Nightshift's admission-provenance interface. Do not represent ordinary
`collect` output, a copied record, or a substitution fixture as that artifact.
