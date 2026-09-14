#!/usr/bin/env python3
"""Local saved-check CLI qualification fixture.

This script is intentionally not self-cleaning.  Its --root directory is a
recovery artifact containing the NQ database, fixture source, JSON inputs, and
bounded command transcript.  It never uses a default configuration path and
never invokes a network, provider, monitor, notification route, or Nightshift.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import selectors
import signal
import time
from typing import Any


COMMAND_TIMEOUT_SECONDS = 30
COMMAND_OUTPUT_LIMIT = 1_048_576
ROOT_PREFIX = "nq-saved-check-cli-001-"


class QualificationFailure(RuntimeError):
    """One deterministic qualification assertion failed."""


def utc_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationFailure(message)


def invoke(
    nq: Path,
    config: Path,
    root: Path,
    transcript: Path,
    *arguments: str,
) -> Any:
    """Run one explicit JSON CLI command with bounded time and output."""
    command = [str(nq), "--config", str(config), "--json", *arguments]
    process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            cwd=str(root),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as poll:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                poll.register(pipe, selectors.EVENT_READ, name)
            while poll.get_map():
                if time.monotonic() >= deadline:
                    raise QualificationFailure("command time limit exceeded; no automatic retry")
                for key, _ in poll.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        poll.unregister(key.fileobj)
                        continue
                    if len(output[key.data]) + len(chunk) > COMMAND_OUTPUT_LIMIT:
                        raise QualificationFailure("command output limit exceeded; no automatic retry")
                    output[key.data].extend(chunk)
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        process.stdout.close()
        process.stderr.close()
    entry = {
        "command": command,
        "returncode": process.returncode,
        "stdout": output["stdout"].decode("utf-8", "replace"),
        "stderr": output["stderr"].decode("utf-8", "replace"),
    }
    with transcript.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
    if process.returncode != 0:
        raise QualificationFailure(
            f"command failed ({process.returncode}): {command!r}; "
            f"stderr={entry['stderr']!r}"
        )
    try:
        return json.loads(entry["stdout"])
    except json.JSONDecodeError as error:
        raise QualificationFailure(f"command did not emit one JSON document: {command!r}") from error


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nq", required=True, type=Path, help="absolute reviewed nq executable")
    parser.add_argument(
        "--root",
        required=True,
        type=Path,
        help=f"absent disposable directory whose basename begins {ROOT_PREFIX!r}",
    )
    arguments = parser.parse_args()

    require(arguments.nq.is_absolute(), "--nq must be absolute")
    require(arguments.root.is_absolute(), "--root must be absolute")
    nq = arguments.nq.resolve()
    root = arguments.root.resolve()
    require(nq.is_file(), "--nq must name an existing file")
    require(os.access(nq, os.X_OK), "--nq must be executable")
    require(root.name.startswith(ROOT_PREFIX), f"--root basename must begin {ROOT_PREFIX!r}")
    require(not root.exists(), "--root must be absent; this fixture never overwrites a prior occurrence")
    require(root.parent.is_dir(), "--root parent must already exist")

    root.mkdir(mode=0o700)
    admissions = root / "admissions"
    helper_runtime = root / "helper-runtime"
    admissions.mkdir(mode=0o700)
    helper_runtime.mkdir(mode=0o700)
    config = root / "nq.toml"
    nq_database = root / "nq.db"
    socket = root / "nq.sock"
    target = root / "source.sqlite"
    definition_path = root / "definition.json"
    maintenance_path = root / "maintenance.json"
    transcript = root / "command-transcript.jsonl"

    config.write_text(
        "\n".join(
            [
                'schema = "nq.config.v1"',
                f'database_path = "{nq_database}"',
                f'socket_path = "{socket}"',
                f'admissions_dir = "{admissions}"',
                f'helper_runtime_dir = "{helper_runtime}"',
                "watchers = []",
                "notification_routes = []",
                "",
            ]
        ),
        encoding="utf-8",
    )

    invoke(nq, config, root, transcript, "init")
    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE fixture_state (value INTEGER)")

    definition = {
        "schema": "nq.saved-check-definition/v1",
        "reference": "fixture.empty-state",
        "source_identity": "local-disposable-sqlite-fixture",
        "currentness_seconds": 300,
        "name": "fixture empty state",
        "sql_text": "SELECT value FROM fixture_state",
        "mode": "non_empty",
        "threshold": None,
        "column": None,
        "description": "local disposable qualification fixture",
    }
    write_json(definition_path, definition)
    installed = invoke(nq, config, root, transcript, "saved-check", "install", "--definition", str(definition_path))
    require(installed["result"] == "installed", "initial saved-check install did not report installed")
    initial_definition = invoke(nq, config, root, transcript, "saved-check", "inspect", definition["reference"])
    replayed_install = invoke(nq, config, root, transcript, "saved-check", "install", "--definition", str(definition_path))
    require(replayed_install == installed, "exact saved-check install must return the same public identity")
    inspected = invoke(nq, config, root, transcript, "saved-check", "inspect", definition["reference"])
    require(inspected == initial_definition, "exact install must not replace retained definition custody")
    require(inspected["definition"] == definition, "inspect did not return exact installed definition")

    observed_now = utc_timestamp(dt.datetime.now(dt.timezone.utc))
    evaluation_id = "fixture-evaluation-replay-001"
    first = invoke(
        nq, config, root, transcript, "saved-check", "evaluate", definition["reference"],
        "--evaluation-id", evaluation_id, "--target", str(target),
        "--source-observed-at", observed_now,
    )
    require(first["outcome"] == "passed" and first["retained"] is False, "fresh current evaluation must pass")
    first_result = invoke(nq, config, root, transcript, "saved-check", "result", "--evaluation-id", evaluation_id)
    require(first_result["outcome"] == "passed" and first_result["indeterminate"] is False, "result must expose retained terminal")

    with sqlite3.connect(target) as connection:
        connection.execute("INSERT INTO fixture_state(value) VALUES (1)")
    target.unlink()
    replayed = invoke(
        nq, config, root, transcript, "saved-check", "evaluate", definition["reference"],
        "--evaluation-id", evaluation_id, "--target", str(target),
        "--source-observed-at", observed_now,
    )
    require(replayed["outcome"] == "passed" and replayed["retained"] is True, "exact replay must not reopen changed or removed target")

    for evaluation, asserted_at in (
        ("fixture-evaluation-stale-001", "2000-01-01T00:00:00Z"),
        ("fixture-evaluation-future-001", "2099-01-01T00:00:00Z"),
    ):
        refused = invoke(
            nq, config, root, transcript, "saved-check", "evaluate", definition["reference"],
            "--evaluation-id", evaluation, "--target", str(target),
            "--source-observed-at", asserted_at,
        )
        require(refused["outcome"] == "refused", f"{evaluation} must retain refusal")
        require(refused["detail"]["refusal_reason"] == "source_not_current", f"{evaluation} must refuse source currentness")
        result = invoke(nq, config, root, transcript, "saved-check", "result", "--evaluation-id", evaluation)
        require(result["outcome"] == "refused", f"{evaluation} result must replay terminal refusal")

    now = dt.datetime.now(dt.timezone.utc)
    maintenance = {
        "schema": "nq.maintenance-declaration/v1",
        "maintenance_id": "fixture-maintenance-001",
        "declared_by": "local-fixture",
        "start_at": utc_timestamp(now + dt.timedelta(minutes=2)),
        "end_at": utc_timestamp(now + dt.timedelta(minutes=3)),
        "component": "fixture-component",
        "kind": "fixture-kind",
        "subject": "fixture-subject",
        "reason": "local disposable qualification fixture",
    }
    write_json(maintenance_path, maintenance)
    declared = invoke(nq, config, root, transcript, "maintenance", "declare", "--declaration", str(maintenance_path))
    require(declared["result"] == "declared", "initial maintenance declaration did not report declared")
    replayed_declaration = invoke(nq, config, root, transcript, "maintenance", "declare", "--declaration", str(maintenance_path))
    require(replayed_declaration.get("retained") is True, "exact maintenance declaration must replay retained custody")
    declarations = invoke(nq, config, root, transcript, "maintenance", "list")
    require(len(declarations) == 1 and declarations[0]["declaration"] == maintenance, "maintenance list must preserve exact declaration")
    covered_at = utc_timestamp(now + dt.timedelta(minutes=2, seconds=30))
    overrun_at = utc_timestamp(now + dt.timedelta(minutes=3, seconds=30))
    for asserted_at, expected in ((covered_at, "covered"), (overrun_at, "overrun")):
        inspection = invoke(
            nq, config, root, transcript, "maintenance", "inspect",
            "--component", maintenance["component"], "--kind", maintenance["kind"],
            "--subject", maintenance["subject"], "--at", asserted_at,
        )
        require(inspection["maintenance_state"] == expected, f"maintenance inspect must report {expected}")
        require(inspection["condition_source"] == "caller_assertion", "inspection must remain a caller assertion")

    # These are caller-selected projection times, not assertions that the
    # removed SQLite source is currently healthy. The retained terminal result
    # remains the original passed evaluation throughout.
    def project(evaluation: str, at: str) -> dict[str, Any]:
        return invoke(
            nq, config, root, transcript, "saved-check", "condition",
            "--evaluation-id", evaluation,
            "--component", maintenance["component"],
            "--kind", maintenance["kind"],
            "--subject", maintenance["subject"],
            "--at", at,
        )

    covered_projection = project(evaluation_id, covered_at)
    require(covered_projection["schema"] == "nq.saved-check-condition/v1", "condition must identify its schema")
    require(covered_projection["original_result"]["outcome"] == "passed", "condition must retain original outcome")
    require(covered_projection["maintenance"]["state"] == "covered", "condition must retain coverage annotation")
    require(covered_projection["source_assertion"]["state"] == "fresh", "covered projection must retain source-time state")

    overrun_projection = project(evaluation_id, overrun_at)
    require(overrun_projection["original_result"]["outcome"] == "passed", "overrun must not rewrite original result")
    require(overrun_projection["maintenance"]["state"] == "overrun", "condition must retain overrun annotation")

    stale_projection = project(evaluation_id, utc_timestamp(now + dt.timedelta(minutes=6)))
    require(stale_projection["original_result"]["outcome"] == "passed", "stale projection must retain original result")
    require(stale_projection["source_assertion"]["state"] == "stale", "condition must report stale source assertion")

    missing_projection = project("fixture-evaluation-missing-001", covered_at)
    require(missing_projection["projection_state"] == "refused", "missing result must refuse projection")
    require(missing_projection["refusal_reason"] == "evaluation_missing", "missing result must be explicit")

    print(json.dumps({"result": "qualified", "root": str(root), "transcript": str(transcript)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationFailure as error:
        print(f"qualification failed: {error}", file=sys.stderr)
        print("recovery artifacts retained; inspect the supplied --root directory", file=sys.stderr)
        raise SystemExit(1)
