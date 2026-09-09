# Labelwatch cleanup prerequisite candidate

Bounded native/application qualification completed; deployment and integrated
AG/Docket/systemd qualification remain separate (see dated evidence below).

`labelwatch-cleanup` is a separately named compiled factual profile. It does not
change `labelwatch-relief` v1 or inherit its prior a94ca44 qualification. Its
request/observation/receipt schemas use `sqlite-cleanup` / `labelwatch-cleanup`
names, making the stronger prerequisite explicit rather than silently changing
the earlier `held_logical_cut_preserved` claim.

The profile composes the earlier held-cut qualification with independent reads
of the exact enrolled backup and restored SQLite files. It checks complete
logical/application-verification digests, schema/integrity, exact path and full
file identity, separate backup device from the replacement and restore on the
same enrolled backup device. Missing/unreadable copies remain NOT_OBSERVABLE;
changed content or an observed wrong device/identity is REFUTED. A malformed
observation or contradictory unknown accounting is an intake error. Replay binds
the original observation bytes and exact request.

The actual backup→restore operation remains in the bounded application helper;
this profile independently reopens both resulting files. It does not manufacture
an authenticated lineage receipt, independently rerun a restore, establish
power-loss/off-host backup custody, or grant deletion authority. The application
adapter must bind this exact factual receipt and request to the AG subject/scope
and immutable cleanup input. AG owns authorization; Docket owns execution custody.

The initial cleanup v1 candidate inherited the earlier 30-second bound. It is
superseded for this unqualified candidate by explicit cleanup **v2**, which
separates acquisition and currentness. Relief v1 still has its original30s bound.
The separately named held-acquisition profile reuses its factual checks but
qualifies only the retained acquisition interval, never present currentness.

Cleanup v2 requires a declared finite acquisition budget (1..7200 seconds), real
start/end/duration and exclusions, and a distinct final currentness witness aged
at most30s at evaluation. The application checks budget before further full-copy
reads; the enrolled capture process must have an external bounded timeout as
well. Over-budget or stale evidence cannot establish the prerequisite.

Opening and final witnesses bind the exact hold generation, source/original/
backup/restore device+inode+size+ownership+mode+mtime+ctime identities and actual
enrolled writer PID/start identities. Full content digests belong to the retained
acquisition interval. Final metadata equality does not mean the contents were
rescanned recently, and does not establish activity. Its continuity meaning
requires the explicitly enrolled all-writer quiescence, protected copy files and
stable directory custody. It is not protection against an excluded direct writer
or root changing custody. The AG adapter binds the resulting exact receipt to
subject/scope and cleanup input and does not extend the final witness's expiry.

Production-sized scans and helper re-verification have not been timed. The
7200s ceiling is a finite contract limit, not evidence that a production budget
is sufficient. Fixture unit25s/driver30s deadlines are also not production-ready
claims. Exact production measurement requires separately approved current access.

Initial candidate source2b7939d has focused policy controls plus app-side real-copy
observation controls. Its first build occurrence was refused before Cargo by the
explicit 8GiB free-space reserve; no test/build acceptance follows from that run.
At that earlier checkpoint the stronger v2 source also remained unbuilt. That
historical status is superseded by the following new occurrences, not rewritten
as acceptance of the failed initial run.

## 2026-09-09 bounded execution evidence

Runtime source `920dc7621f5cdf768473cef26311294fdf6cf61c` (format-only child of
`0f1a87b`) passed seven cleanup and three relief tests and an exact Rust1.94 native
build in `m3-nq-003`. Retained binary SHA256:
`fb1e1e513589d8d04661b89b80b58d90a229ff61e6e2e644df7267b179bcdab7`.
Application `17a2dedb2528025ec0c05b173d9be9b4b8b4ba53` passed43 cases/no skips in
`m3-matrix-006`, including real main/discovery held startup and actual native
cleanup/pre/post observations. `m3-admission-003` passed the resolver control
against those retained cleanup facts and AG5194005. `m3-capture-full-001` exercised
allthree app capture CLI phases with actual held fixture processes; effects in
that occurrence are explicitly developmental, not an AG/Docket showing.

Exact scripts, logs, terminal records, hashes and recovery identities are retained
under `/data/git/.campaign-artifacts/operator-beta-completion-20260908/`, with
`M3-NATIVE-003-READINESS.md` as the supervision index. Independent reviewer has
rederived the retained cleanup receipt with the pinned image; final scoped review
is recorded separately and does not transfer to later runtime edits.

These are bounded engineering results, not production dogfood, measured production
scan sufficiency, backup power-loss qualification, or integrated VM acceptance.
Guest-compatible packages, final driver and finite AG/Docket/systemd cases remain
required. This documentation-only descendant does not change the runtime pin.
