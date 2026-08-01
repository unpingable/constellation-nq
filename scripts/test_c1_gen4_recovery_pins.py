#!/usr/bin/env python3
"""Focused refusal and sensitivity controls for the Gen4 pin auditor."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest


sys.dont_write_bytecode = True
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
ROOT = SCRIPT_DIRECTORY.parent


def load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPT_DIRECTORY / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


auditor = load_script(
    "nq_c1_gen4_recovery_pin_auditor", "verify-c1-gen4-recovery-pins.py"
)


def raw_inventory() -> dict:
    data = (ROOT / auditor.INVENTORY_PATH).read_bytes()
    return auditor.load_json(data, auditor.INVENTORY_PATH)


def group(inventory: dict, group_id: str) -> dict:
    return next(item for item in inventory["pin_groups"] if item["id"] == group_id)


class C1Gen4RecoveryPinAuditorTest(unittest.TestCase):
    def test_actual_scaffold_is_structurally_valid_and_unminted(self) -> None:
        data = (ROOT / auditor.INVENTORY_PATH).read_bytes()
        receipt = auditor.scaffold_audit(data, auditor.INVENTORY_PATH)
        self.assertEqual(receipt["status"], auditor.AUDIT_STATUS)
        self.assertFalse(receipt["freeze_minted"])
        self.assertFalse(receipt["qualification_earned"])
        self.assertFalse(receipt["paths_read"])

    def test_check_scaffold_cli_remains_unminted(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = auditor.main(["--repo", str(ROOT), "--check-scaffold"])
        self.assertEqual(result, 0, stderr.getvalue())
        receipt = json.loads(stdout.getvalue())
        self.assertEqual(receipt["result"], "STRUCTURALLY-VALID-INVENTORY-NOT-A-FREEZE")
        self.assertFalse(receipt["freeze_minted"])

    def test_unsafe_explicit_path_refuses(self) -> None:
        inventory = copy.deepcopy(raw_inventory())
        group(inventory, "gen4-production-resolution")["paths"].append("../escape")
        with self.assertRaisesRegex(auditor.Refusal, "forbidden path component"):
            auditor.validate_inventory(inventory)

    def test_path_duplicated_across_explicit_groups_refuses(self) -> None:
        inventory = copy.deepcopy(raw_inventory())
        group(inventory, "gen4-production-resolution")["paths"].append(
            auditor.PREVIOUS_NINE[0]
        )
        with self.assertRaisesRegex(auditor.Refusal, "duplicated across groups"):
            auditor.validate_inventory(inventory)

    def test_required_pin_cannot_be_removed_from_policy(self) -> None:
        inventory = copy.deepcopy(raw_inventory())
        group(inventory, "gen4-production-resolution")["paths"].remove(
            "crates/nq-store/src/writer_session.rs"
        )
        with self.assertRaisesRegex(auditor.Refusal, "omits required paths"):
            auditor.validate_inventory(inventory)

    def test_inventory_cannot_embed_an_authority_claim(self) -> None:
        inventory = copy.deepcopy(raw_inventory())
        inventory["freeze_minted"] = True
        with self.assertRaisesRegex(auditor.Refusal, "unexpected=.*freeze_minted"):
            auditor.validate_inventory(inventory)

    def test_closed_compile_fail_population_requires_diagnostic_pairs(self) -> None:
        inventory = auditor.validate_inventory(raw_inventory())
        available = {
            path for paths in inventory["_parsed_groups"].values() for path in paths
        }
        available.update(
            {
                "crates/nq-runtime-dependency-authority/src/lib.rs",
                "crates/nq-store/src/custody_arena/recovery.rs",
                "crates/nq-store/tests/ui/gen4/unpaired.rs",
                "crates/nq-store/tests/ui/gen4/also_unpaired.rs",
                "crates/nq-store/tests/ui/r0b/paired.rs",
                "crates/nq-store/tests/ui/r0b/paired.stderr",
                "crates/nq-store/tests/ui/writer/paired.rs",
                "crates/nq-store/tests/ui/writer/paired.stderr",
                "crates/nq-store/tests/isolated/r0b-control/Cargo.toml",
            }
        )
        with self.assertRaisesRegex(auditor.Refusal, "incomplete diagnostic pair"):
            auditor.expand_pin_set(inventory, available)

    def test_resolver_mutation_is_a_stop_not_a_repin(self) -> None:
        with self.assertRaisesRegex(auditor.Refusal, "resolver continuity STOP"):
            auditor.assert_resolver_continuity(b"synthetic changed resolver")

    def test_exact_gen3_resolver_reproduces_continuity_digest(self) -> None:
        repo = auditor.exact_repo(ROOT)
        commit = auditor.resolve_commit(repo, auditor.GEN3_COMMIT, "Gen3")
        entries = auditor.git_tree_entries(repo, commit)
        resolver = auditor.git_blob(repo, commit, auditor.RESOLVER_PATH, entries)
        self.assertEqual(
            auditor.assert_resolver_continuity(resolver), auditor.RESOLVER_SHA256
        )

    def test_duplicate_json_key_refuses(self) -> None:
        with self.assertRaisesRegex(auditor.Refusal, "duplicate JSON key"):
            auditor.load_json(b'{"schema":"one","schema":"two"}', "duplicate")


if __name__ == "__main__":
    unittest.main()
