# Operator-controlled archive rollover

This procedure preserves a sealed historical store and prepares a separate,
inactive successor store. Historical reads continue to name the archive
explicitly; NQ does not search old and new stores as one logical database.
Rollover does not start `nqd`, activate the successor configuration, repeat an
evaluation, deliver a notification, delete the source, or grant authority.

The procedure is qualified for a schema-12 source upgraded by the implemented
backup protocol to schema 13. Other source versions must follow their supported
upgrade path; do not reinterpret an older database with a current-schema reader.

## 1. Establish the operator boundary

Stop submissions and schedules, stop the owning service, and reconcile every
known operation. Record the service state, source configuration and database
path, NQ binary digest, database/WAL/SHM inventory, and chosen UTC inspection
coordinate. The scanner reports typed retained state; it explicitly does **not**
prove process quiescence.

Use absent destinations for the upgrade backup, archive, and successor store.
Keep all three on operator-owned storage with enough free blocks and inodes.
After an interruption, inspect those exact destinations before issuing another
command. Do not replace or reseal an existing archive.

```sh
NQ=/absolute/path/to/current/nq
SOURCE_CONFIG=/absolute/path/to/source.toml
UPGRADE_BACKUPS=/absolute/path/to/absent-upgrade-backups
ARCHIVE=/absolute/path/to/absent-archive
SUCCESSOR_CONFIG=/absolute/path/to/successor.toml
INSPECTED_AT=2026-09-14T16:30:00Z
```

## 2. Upgrade through an explicit backup when required

For a schema-12 source, run the current binary against the stopped source:

```sh
"$NQ" --config "$SOURCE_CONFIG" --json admin upgrade \
  --backup-directory "$UPGRADE_BACKUPS"
```

Require `from_schema_version:12`, `schema_version:13`, `result:"migrated"`, a
backup pathname and digest, and
`historical_local_successor_acquisitions:"absent_not_synthesized"`. Preserve
the backup and command result. This upgrades the selected source; it does not
activate a successor or convert an existing sealed archive.

## 3. Create, verify, and inspect the archive

```sh
"$NQ" --config "$SOURCE_CONFIG" --json admin archive \
  --destination "$ARCHIVE"
"$ARCHIVE/bin/nq" --json admin archive-verify "$ARCHIVE"
"$NQ" --json admin rollover-inspect "$ARCHIVE/db/nq.db" \
  --inspected-at "$INSPECTED_AT"
```

Run the embedded archived binary for `archive-verify`. Require the verification
fields in [Historical reads](HISTORICAL_READS.md), then require inspection schema
`nq.rollover-inspection/v1`, `eligible:true`, no `refusals`,
`snapshot.opened_immutable:true`, and `grants_authority:false`.
`snapshot.archive_verification_claimed:false` is intentional: the scanner reads
the selected immutable database but does not replace independent seal
verification.

The scanner validates every definition and exact identity, saved-check terminal
outcome, notification terminal state, local-successor acquisition phase, and
maintenance declaration. `current_maintenance` is evaluated at `INSPECTED_AT`.
Pending, claimed-only, missing, malformed, contradictory, or unknown retained
state refuses eligibility. Preserve this JSON as the transfer inventory.

Record a before/after archive inventory and require every sealed path and byte
to remain unchanged. The seal detects content mutation; it is not a filesystem
write lock, so keep the archive read-only and its namespace stable.

## 4. Prepare the inactive successor

Create a new configuration whose `database_path` names an absent database and
whose socket, admissions, helper-runtime and route paths are new. Initialize
only that selected store:

```sh
"$NQ" --config "$SUCCESSOR_CONFIG" --json init
```

For each `definitions[]` entry, write its nested `definition` object as canonical
JSON to an operator-owned file, verify `definition_digest`, retain the old
`definition_id`, and install and inspect the exact definition:

```sh
"$NQ" --config "$SUCCESSOR_CONFIG" --json saved-check install \
  --definition /absolute/path/to/one-definition.json
"$NQ" --config "$SUCCESSOR_CONFIG" --json saved-check inspect REFERENCE
```

Record old and new definition IDs, reference, and common definition digest.
Installation does not copy evaluation history. Historical evaluation IDs remain
readable only by explicitly querying the archive.

Carry each `current_maintenance[]` entry with a new destination ID:

```sh
"$NQ" --config "$SUCCESSOR_CONFIG" --json maintenance carry-from-archive \
  --archive "$ARCHIVE" \
  --source-maintenance-id SOURCE_ID \
  --new-maintenance-id NEW_SUCCESSOR_ID
```

The command verifies the archive and preserves exact start, end, component,
kind, subject, actor, and reason. It records source ID/digest and archive
lineage. Run it while the source declaration is still active: carry performs a
fresh contemporaneous inspection rather than reusing `INSPECTED_AT`. Missing,
future, expired, or reused identities refuse. Repeating the identical successful
command returns `inserted:false`; this is idempotent readback, not a new
declaration or window renewal.

```sh
"$NQ" --config "$SUCCESSOR_CONFIG" --json maintenance list
"$NQ" --config "$SUCCESSOR_CONFIG" --json notification inspect
```

An empty successor notification list is expected: delivery custody remains in
the archive. Do not copy notification rows or saved-check results by hand.

## 5. Retain evidence; decide activation separately

Retain the upgrade result and backup, archive creation and verification,
rollover inspection, definition mapping, maintenance receipts, successor
configuration, and readbacks. Record locations and digests without publishing
retained private data.

The qualified disposable occurrence verified one definition, terminal saved-
check and notification history, one active maintenance carry, unchanged
archives, five explicit archive reads, and an inactive successor. Actual
missing/future/expired/same-ID maintenance carries refused. Product unit tests
cover pending and unknown retained-state refusal; that negative case was not
manufactured by interrupting the disposable occurrence.

Activation, service restart, scheduling, archive disposal, restoration, and
rollback are separate operator decisions. Eligibility and successor preparation
authorize none of them.
