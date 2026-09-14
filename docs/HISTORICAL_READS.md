# Inspect saved checks in a sealed archive

Keep an old result available without treating it as the condition of the system
now. NQ can archive a compatible store together with its exact verifier binary,
then read saved-check definitions, results, maintenance and notification records
from that archive. This is historical inspection, not restoration or retention
rollover. It does not start a monitor, repeat a check or deliver a message.

## Prerequisites and ownership

The exercised runtime is public commit
`e259852ed58b8c0bf65a629b3c494afba28d9ce9`, Rust 1.94.0, Linux x86_64.
The [objective saved-check profile](https://unpingable.com/constellation/releases/0.1.0-alpha.3/guide.html)
provides a disposable populated store and matching component pins. Its immutable
release did not qualify archive inspection; this guide records an additional
check of the same NQ runtime, not a replacement release manifest.

Use a configuration and store you own. For a stable comparison, stop new
submissions and reconcile unfinished work first. An archive is not evidence that
an attempt settled. Archive creation uses NQ's verified SQLite backup, not a raw
copy of a running database; preserve database and WAL relationships. The archive
contains retained records and configuration: keep it private and inspect those
contents before sharing anything. It includes no general redaction step.

## Create and verify

Choose an absent destination with enough space for the database, verifier and
temporary construction copy. These variables refer to your actual local paths:

```sh
NQ=/absolute/path/to/matching/nq
SOURCE_CONFIG=/absolute/path/to/nq.toml
ARCHIVE=/absolute/path/to/new-archive
"$NQ" --config "$SOURCE_CONFIG" --json admin archive --destination "$ARCHIVE"
"$ARCHIVE/bin/nq" --json admin archive-verify "$ARCHIVE"
```

Expect `nq.cold_archive.v1`, `source_openable: true` from creation, and
`integrity_verified: true` plus `historical_database_verified: true` from
verification. Check the actual exit code and structured result. An incompatible
store may be preserved with `source_openable: false`; that is custody of bytes,
not verified historical meaning. A failed or uncertain creation must be inspected
at its exact destination before considering another command.

Verification does not require the live configuration. Use the archived binary;
a different executing binary is rejected even if its package version matches.
Do not edit, add files inside, or reseal the archive to make a failed check pass.
The seal detects changed bytes and file sets; it is not a filesystem write lock.
Keep ordinary ownership controls, and use a read-only mount when appropriate.

## Read the archived database explicitly

The sealed `config/nq.toml` retains its source database location. Running the
archived binary with that configuration could read the live source, not the
archive. Create a **separate configuration outside the archive**, pointing to
the absolute archived database path:

```toml
schema = "nq.config.v1"
database_path = "/absolute/path/to/new-archive/db/nq.db"
socket_path = "/absolute/path/to/separate-inspection/nq.sock"
admissions_dir = "/absolute/path/to/separate-inspection/admissions"
helper_runtime_dir = "/absolute/path/to/separate-inspection/helper-runtime"
watchers = []
notification_routes = []
```

For these read-only commands no socket, admitted helper or delivery route is
needed. Do not initialize or upgrade the archived store. Substitute the exact
reference and evaluation ID from your retained run, not a guessed latest result:

```sh
READ_CONFIG=/absolute/path/to/separate-inspection/nq.toml
REFERENCE=disposable.queue.nonempty
EVALUATION_ID=sha256:YOUR_RETAINED_EVALUATION_ID
"$ARCHIVE/bin/nq" --config "$READ_CONFIG" --json saved-check inspect "$REFERENCE"
"$ARCHIVE/bin/nq" --config "$READ_CONFIG" --json saved-check result --evaluation-id "$EVALUATION_ID"
"$ARCHIVE/bin/nq" --config "$READ_CONFIG" --json maintenance list
"$ARCHIVE/bin/nq" --config "$READ_CONFIG" --json notification inspect
AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$ARCHIVE/bin/nq" --config "$READ_CONFIG" --json saved-check condition \
  --evaluation-id "$EVALUATION_ID" --component disposable-queue \
  --kind saved-check --subject queue --at "$AT"
```

The target coordinates above belong to the disposable example; use your actual
declared coordinates for other checks. `condition` compares a recorded observation
and maintenance declaration with the supplied time. It does not observe the
source again. A failed result stays failed when it becomes stale; maintenance
does not erase it. A delivery record does not prove a human received the message.
Missing IDs, unreadable files or rejected schemas are not successful inspection.
Preserve the error and record identity; do not substitute another result silently.

## Verified behavior and limits

A disposable populated store was archived and verified with the exact public
binary. Five supported reads—definition, exact result, condition at one common
time, maintenance list and notification list—returned equal JSON from the source
copy and archive. The archive was mounted read-only. Its complete sealed file
set and bytes remained unchanged; original owner database and sidecar bytes also
remained unchanged. No source acquisition, evaluation or notification delivery
was repeated.

A disposable live WAL-mode copy could not open on a fully read-only mount.
Making only that source-copy directory writable allowed SQLite's sidecar/open
mechanics and fixed the comparison without changing its main database bytes.
The source copy's sidecar bytes were not compared. The sealed archive uses DELETE
journal mode and required no write access. Do not generalize the archive's
read-only mount behavior to an arbitrary live WAL database.

`archive-verify` checks the sealed bytes, database schema and its implemented
historical validators. At this pin it does **not** exhaustively traverse typed
saved-check, maintenance or notification histories. The five reader comparisons
above exercise specific records; they are not a substitute for that missing
whole-history semantic check. Archive-based rollover, cross-store lookup,
automatic disposal, restoration and rollback are not established by this check.

Keep the archive and matching inspection configuration while they are needed for
recovery or investigation. Removing disposable inspection outputs does not remove
the archive; deleting an archive destroys historical records and requires its own
ownership and recovery decision. See [Operations](OPERATIONS.md#cold-archive-and-historical-reopen)
and the [support and redaction guide](https://unpingable.com/constellation/troubleshooting.html).
