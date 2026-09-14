# Observe again without creating a new evidence owner

Use this bounded local profile when an admitted local watcher has already
produced a diagnostic and a workflow needs another observation from the same
store and configuration. It is not a scheduler or permission to act on a result.

Prerequisites: current schema13, the same admitted watcher and helper, retained
matching diagnostic history, and a caller-selected acquisition ID. This uses
the existing local helper path; it does not establish hardware or remote-host
provenance. The ordinary `diagnostics execute` entry point remains the initial
diagnostic path and refuses an incompatible prior-history shape.

```sh
nq --config /path/to/nq.toml diagnostics acquire-next-local host-local \
  --acquisition-id local-check-002 > observation.json
nq --config /path/to/nq.toml diagnostics replay-local-successor host-local \
  --acquisition-id local-check-002 > replay.json
cmp observation.json replay.json
artifact=$(jq -er .artifact_id observation.json)
nq --config /path/to/nq.toml --json diagnostics qualify "$artifact"
nq --config /path/to/nq.toml diagnostics export "$artifact" > exported.json
cmp observation.json exported.json
```

Replace the explicit config, watcher and acquisition ID with your own. Redirect
only into absent output files; retain the command status and original records.
These commands assume a previously initialized and admitted watcher; they do
not install, enroll, or start services. See [Operations](OPERATIONS.md).

The acquisition binds the ID to the exact watcher configuration, selection
rule, run and provider intake. The durable start record precedes helper
invocation. A completed ID reopens the exact retained artifact rather than
collecting again. Reusing it with changed watcher material refuses. A started
but unresolved acquisition also refuses; changing the ID is not recovery of
that acquisition. Inspect the retained run/intake and reconcile the original
producer before deciding whether a genuinely new observation is appropriate.

For this profile, evaluation selects exactly the newly admitted report. Prior
matching history remains retained for finding and watermark continuity, but
is excluded from this single-report detector invocation. Other ordinary
multi-report evaluation paths are unchanged. A consumer requiring the same
observation family must continue to bind store origin, subject, vantage,
configuration, evaluator identity and its own family coordinates explicitly.

`qualify` establishes retained admission provenance, not current freshness or
legitimate reliance. Replaying a completed observation does not make it current.
Use the artifact's actual timestamps and the consuming contract's currentness
policy. Missing, pending, unknown or contradictory history is not success.
Neither collection nor replay grants downstream authorization or continuation.

## Compatibility and qualification

Schema12 requires the verified backup and explicit12→13 upgrade described in
Operations. Keep immutable historical archives on their own embedded reader;
do not upgrade a sealed archive. Schema13 adds acquisition custody, not a new
component, service, package or binary identity.

Store tests cover exact bindings and malformed phase histories; core tests
cover a real local successor, byte-identical replay, changed configuration and
pending/unknown refusal. CLI tests cover required IDs and unsupported arguments.
These component checks do not establish that every Nightshift composition is
connected or qualified. Use a published integration manifest for an actually
tested cross-component combination.

Profile descriptor digests and evaluator semantic IDs are different. The latter
also bind the conservative source/dependency closure, so a dependency update
may rotate an ID without changing descriptor bytes. Do not replace a pinned
consumer expectation with whatever ID happened to arrive. Verify the new
source/runtime combination and explicitly enroll its identity in each consumer.
