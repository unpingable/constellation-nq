# Check a local source and keep the result

Use saved checks when you already have a SQLite observation source and want to
retain one bounded check result. You do not need a model, daemon or full
Constellation deployment for this local read.

This is an experimental local capability, not a complete recurring monitoring
profile. A successful query does not establish legitimate reliance on its source.

## Run the disposable example

Public prerequisites: this repository, Rust1.94.0/Cargo, a C compiler for bundled
SQLite, Python3.10 or newer, and Linux. No private source, credentials or background
services are required. Rust dependency downloads use the committed Cargo.lock.

```sh
git clone https://github.com/unpingable/constellation-nq.git
cd constellation-nq
# For repeatable deployment, check out the exact public revision you selected.
cargo build --locked -p nq-app --bin nq
python3 examples/saved-check-local.py \
  --nq "$PWD/target/debug/nq" \
  --root /tmp/nq-saved-check-cli-001-example
```

The root must not already exist. The example creates only its own NQ store and
SQLite source, then checks exact-install replay, result inspection, duplicate
evaluation after source change/removal, stale/future observation refusal, and
maintenance coverage/overrun. Success prints `"result": "qualified"` with the
retained transcript location. No message, provider or production action occurs.

The central caller boundary uses actual supported commands:

```sh
nq --config ./nq.toml --json saved-check install --definition ./check.json
nq --config ./nq.toml --json saved-check inspect capacity
nq --config ./nq.toml --json saved-check evaluate capacity \
  --evaluation-id check-001 --target /absolute/path/source.sqlite \
  --source-observed-at 2026-09-14T00:00:00Z
nq --config ./nq.toml --json saved-check result --evaluation-id check-001
```

Those four commands illustrate adaptation; use the complete example for working
configuration and inputs. Its date is intentionally supplied by the caller:
substitute a real source observation, not the current time merely to pass freshness.

```mermaid
sequenceDiagram
    participant Caller
    participant NQ as NQ CLI and store
    participant Source as SQLite source
    Caller->>NQ: Install exact definition
    Caller->>NQ: Occurrence ID, target and source-time assertion
    NQ->>NQ: Retain exact claim
    NQ->>Source: One bounded read-only query
    Source-->>NQ: Rows or failure
    NQ->>NQ: Retain terminal result
    Caller->>NQ: Inspect existing occurrence
    NQ-->>Caller: Result or missing/indeterminate state
```

## What the result means

Definitions use `nq.saved-check-definition/v1`. `non_empty` fails if any rows
exist; `empty` fails if no rows exist; `threshold` fails if a named finite numeric
column exceeds its threshold. A refused query is not a failed predicate. SQL
errors, unsupported statements, stale source assertions, invalid result shapes
and exceeded limits yield explicit refusals.

The caller owns collection, source identity and source observation time. NQ
records `source_observed_at_assertion` separately from `read_attempted_at`.
Neither a file's modification time nor a successful read proves current contents
or upstream provenance. New observations use new occurrence IDs; they do not
rewrite old results or permanently change an installed definition's freshness.

Exact duplicate requests reopen the existing occurrence without reading the
source, even after the source disappears. Changed definition/target/time material
under the same occurrence ID refuses. A claim without a terminal result remains
indeterminate; inspect it before considering another occurrence. No automatic
claim reclamation, retry or inferred success exists.

Limits include1024rows,256KiB aggregate returned values and per-value limits,
a2-second SQLite progress deadline and bounded lock waits. These are not a hard
wall-clock guarantee for a stalled filesystem; use bounded process supervision
where a whole-command deadline is necessary.

## Maintenance and lifecycle

`maintenance declare` accepts `nq.maintenance-declaration/v1`: a future increasing
UTC window, exact component/kind, optional subject pattern and operator identity.
An exact duplicate reopens the original declaration; changed material refuses.
There are no update, cancel, clear or extend verbs.

`maintenance inspect --component NAME --kind KIND --subject SUBJECT --at TIME`
returns covered, overrun or uncovered for that caller-supplied condition and time.
Invalid retained declarations refuse instead of fabricating uncovered state.
Coverage never removes the condition, proves resolution or grants permission.
An attention owner must use this annotation before deciding whether to interrupt
a person; declaring maintenance does not by itself suppress a notification.

Normal operation retains the NQ database, configuration, definitions and source
observation references. Stop the invoking scheduler before an upgrade/backup and
use [NQ's backup, doctor and explicit upgrade procedures](OPERATIONS.md), not a
raw copy omitting SQLite WAL state. The public v5→v12 upgrade verifies a separate
backup and adds empty custody tables; it does not synthesize historical checks.
Versions6–11 belong to a separate development schema line and are not accepted
by this migration. They must retain their matching verifier and recovery tools;
changing a version number is not migration. Downgrade and in-place rollback are
not advertised.

The example retains state for investigation. Only after inspecting its result,
remove the exact disposable example directory if no longer needed. Do not apply
tutorial cleanup to user records. If interrupted, inspect the recorded occurrence
with `saved-check result` first; stopping a process does not complete its work.

Recurring Monitor/NQ/Nightshift admission and attention binding remain incomplete.
This local example does not qualify legacy monitoring retirement, live delivery,
federation or the full multi-component integration profile.
