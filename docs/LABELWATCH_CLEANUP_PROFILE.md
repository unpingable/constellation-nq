# Labelwatch cleanup prerequisite candidate

Implementation candidate, not yet independently qualified or deployed.

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

The current profile inherits the earlier maximum 30-second observation-start to
evaluation bound. Small fixture reads fit that bound. Production-sized full
logical scans have not been timed, and may not fit. A production showing must not
replace the real start time or silently extend currentness. A measured, explicit
bounded acquisition/currentness contract remains necessary if those reads exceed
the current bound.

Candidate source2b7939d has focused policy controls plus app-side real-copy
observation controls. Its first build occurrence was refused before Cargo by the
explicit 8GiB free-space reserve; no test/build acceptance follows from that run.
Exact binary and integrated app/resolver review are still required.
