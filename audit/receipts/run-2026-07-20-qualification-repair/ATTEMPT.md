# Preserved audit attempt

This first AC-R4 attempt is retained as history. Its gate correctly failed,
but the initial `delete-detail` mutation replacement made the mutant fail to
compile. The framework records only the nonzero command exit and therefore
reported that mutation as biting. No result from this directory is used as the
authoritative qualification-repair verdict.

The manifest was corrected without changing product code and a new attempt
was written to
`../run-2026-07-20-qualification-repair-r2/refusal-audit/`. This directory and
its ledgers were not edited or replaced.

The r1 and r2 v1 ledgers are byte-identical because the schema records only a
nonzero mutation-command exit, not whether that exit came from compilation or
the named assertion. The compile-failure distinction above is a preserved
operator observation, not independently recoverable from either ledger, and no
authoritative blocked conclusion relies on it.
