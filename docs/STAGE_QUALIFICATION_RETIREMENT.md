# Native stage qualification and realization

CLASSIC-RETIREMENT implementation candidate, not deployment or M2 requalification.

Two compiled, read-only factual evaluators are exposed by `nq`:

```
nq campaign-stage-qualification evaluate --profile profile.json --evidence evidence.json --evaluated-at-unix-ms 110 --output receipt.json
nq campaign-stage-qualification replay --profile profile.json --evidence evidence.json --receipt receipt.json --output -
nq campaign-stage-realization evaluate --profile profile.json --evidence evidence.json --evaluated-at-unix-ms 110 --output receipt.json
nq campaign-stage-realization replay --profile profile.json --evidence evidence.json --receipt receipt.json --output -
```

Documents are bounded to 4 MiB; output paths must be absent. Replay preserves
the original evaluation time and requires the exact executing NQ-ng binary,
package version, and evaluator identity. Linux identity reads `/proc/self/exe`,
not a replaceable executable pathname. No classic executable is queried.

`stage_qualification` owns fixed predicates over exact repository/predecessor/
result identities, ordered fail-fast gates (including command context and
transcripts), artifact digests, workspace predicates and known cleanliness.
`stage_realization` additionally requires one exact reservation realization;
absence or multiple chains is indeterminate, never favorable selection. A
prior-stage predecessor must replay under the same evaluator build and bind
the same campaign/repository/ref, result objects and ordered time. At most 16
prior stages are accepted. These evaluators do not acquire observations or
validate that a Docket settlement grants authority: they qualify the exact
producer testimony against an identified consumer-selected contract.

Consumer-required field structures are adapted from the closed historical
stage contracts, not the classic runtime, database, plugin system, or registry.
Modern schemas and evaluator IDs use `nq-ng.campaign-stage-*`; they deliberately
do not admit classic receipts. Canonical identities use `nq_protocol`, including
its exact I-JSON integer bound. No new dependency or persistence layer was added.
Only predicate logic shared by the two contracts is reused. These are not the
repository-state or queue-predicate contract under another name.

`QUALIFIED`, `FAILED`, and `INDETERMINATE` retain distinct meanings. Every receipt
denies standing, authorization, successor choice, continuation, effects and
present applicability. Nightshift owns currentness/conflict retention; AG-ng
owns authorization; Docket owns execution custody. Qualification cannot create
any of those authorities.

Focused controls: `cargo test -p nq-core --lib stage_`. Real downstream witnesses
reside in Nightshift `repository_qualification_cross_office` and
`nq_ng_stage_realization`, explicitly supplied with this `nq` build. Initial
durable run 002 passed 12 native controls, 16 Nightshift filtered controls, the
Q4 basis witness and a real realization witness with positive, failed,
indeterminate, mismatched and stale cases. Independent exact integrated review
remains a separate release gate; local test success is not that acceptance.
