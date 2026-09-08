# Repository-state implementation candidate

## Independent-review correction

The original fd2b299 candidate's focused tests missed two controls: a configured
Git clean filter could hide an equal-length content change (and execute a local
command), and sampling suppression flags only after status did not bind the
index used during that status. Its passing test logs remain historical evidence,
not acceptance of those gaps.

The corrected collector copies one bounded, opened regular index into a private
Git directory and uses that exact index for status and both suppression probes.
Its digest is retained and the copy is checked unchanged before export. Source
index changes/removal of flags after capture cannot alter the selected index.
The private config is fixed; no source/local/global/system filter command or
hook configuration is consulted by status. The original object store is a
read-only alternate. Submodule status recursion is disabled and submodules are
still refused by their index modes. Repository info/exclude is copied as bounded
data with its own digest; worktree .gitignore and built-in attribute normalization
remain part of Git's observation semantics. Source config-driven ignore/attribute
extensions are not silently imported. This remains Git-normalized status against
an exact captured index, not byte-for-byte filesystem or future-state truth.

New controls cover equal-length filtered content with a marker proving the filter
was not executed, and clearing flags on the source index after capture while the
copied index retains the original suppression state. Independent re-audit and
new producer/consumer fixtures are required after this correction.

2026-09-08, CLASSIC-RETIREMENT. This supersedes the implementation deferral in
REPOSITORY_STATE_PREREQUISITE.md for this bounded consumer contract only. M2
acceptance and fleet/production authority are unchanged.

`nq-profiles::repository_state` is a closed compiled factual profile, using
NQ-ng canonical JSON, semantic digests and evaluator source-closure identity.
`nq repository-state observe --worktree PATH --output ABSENT_FILE` runs fixed
Git acquisition; `replay --artifact FILE --producer-sha256 SHA256` independently
reopens exact canonical bytes, evaluator source, producer identity, subject,
raw evidence and derived disposition. It does not import classic receipts,
evaluate caller-supplied predicates, or provide automatic fallback.

Claim: one local non-bare enrolled worktree's Git porcelain response reported
no tracked/untracked changes, or reported changes, during the recorded interval.
Ignored contents are explicitly excluded. Submodules are unsupported and make
the result not-established. Unborn HEAD, command failures, bounds violations
and differing before/after HEAD cannot establish clean. This is neither an
atomic worktree snapshot nor a currentness/future-execution guarantee. Repeating
HEAD does not prove absence of concurrent writes. Codex owns freshness and
subject selection; AG owns authorization, Docket execution custody.

Environment assumptions: trusted installed `/usr/bin/git`, its runtime and
this enrolled local collector; no concurrent administrative replacement of
those installed components. Git aliases, system/global config, filesystem
monitor, optional locks and untracked cache are disabled. Repository-owned
configuration may only narrow this contract where explicitly addressed by
qualification; it must not silently suppress tracked changes. Every command
has a 4-second/1-MiB output bound; no raw stderr or command arguments are exported.
Repository paths themselves are operational metadata, not automatically safe
for public export. UTC values are local clock testimony, not a clock-error bound.

Digests establish exact content and semantic identity, not authentication.
Replay requires trusted local artifact custody and a separately enrolled
producer executable digest; an untrusted caller able to manufacture all input
bytes cannot establish producer origin by recomputing a hash. Consumer adapters
must call the pinned modern replayer, not trust JSON labels or hash shape.

Qualification candidate: three profile controls plus real Git integration
(clean, tracked, staged, untracked, ignored, unborn and historical replay)
passed in durable run003; earlier runs001/002 exposed compile/file-offset
defects and remain in campaign logs. Independent review still required.
