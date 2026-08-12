#!/usr/bin/env python3
"""Focused controls for the C1 generation identity tools."""

from __future__ import annotations

import contextlib
import importlib.util
import io
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


reanchor = load_script("nq_c1_reanchor", "reanchor-c1-generation.py")
verifier = load_script("nq_c1_identity_verifier", "verify-c1-generation-identity.py")


class C1GenerationIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = reanchor.resolve_repo(ROOT)
        cls.gen3 = reanchor.resolve_commit(cls.repo, reanchor.GEN3_COMMIT)
        cls.baseline = reanchor.load_git_bundle(cls.repo, cls.gen3)
        cls.old_engine = reanchor.sha256_bytes(
            reanchor.git_object(cls.repo, cls.gen3, reanchor.ENGINE_PATH)
        )

    def synthetic_review_binding(self, new_engine: str) -> dict:
        manifest = reanchor.load_json(
            self.baseline[reanchor.MANIFEST_V2_PATH], "synthetic review manifest"
        )
        manifest = reanchor.copy.deepcopy(manifest)
        reanchor.replace_engine_bindings(
            manifest, self.old_engine, new_engine, "synthetic review manifest"
        )
        basis = reanchor.qualification_basis(manifest)
        carrier = reanchor.load_json(
            self.baseline[reanchor.CARRIER_PATH], "synthetic review carrier"
        )
        carrier = reanchor.copy.deepcopy(carrier)
        carrier["qualification_basis"]["digest"] = basis
        pre_review = reanchor.pre_review_projection(carrier)
        return {
            "schema": reanchor.REVIEW_BINDING_SCHEMA,
            "status": reanchor.REVIEW_BINDING_STATUS,
            "generation": "c1.generation.4",
            "authority_effect": "none",
            "reviewed_source": {
                "commit": "1" * 40,
                "tree": "2" * 40,
                "qualification_basis_sha256": basis,
                "pre_review_projection_sha256": pre_review,
                "evaluator_path": reanchor.EVALUATOR_PATH,
                "evaluator_sha256": reanchor.sha256_bytes(b"synthetic evaluator"),
                "canonical_serializer_path": reanchor.SERIALIZER_PATH,
                "canonical_serializer_sha256": reanchor.sha256_bytes(
                    b"synthetic serializer"
                ),
            },
            "records_repository": {"commit": "3" * 40, "tree": "4" * 40},
            "review_receipt": {
                "identity": "nq.c1-gen4.synthetic-cap-h14-review.v1",
                "verdict": reanchor.REVIEW_VERDICT,
                "receipt_path": "audits/synthetic-review.v1.json",
                "receipt_sha256": reanchor.sha256_bytes(b"synthetic receipt"),
                "report_path": "audits/synthetic-review.md",
                "report_sha256": reanchor.sha256_bytes(b"synthetic report"),
            },
        }

    def test_exact_gen3_chain_reproduces_known_receipt(self) -> None:
        receipt = reanchor.verify_chain(
            self.baseline, self.old_engine, label="test Gen3"
        )
        for field, expected in reanchor.GEN3_RECEIPT.items():
            self.assertEqual(receipt[field], expected, field)
        self.assertEqual(
            receipt["engine_binding_replacements"],
            {"manifest_v1": 91, "manifest_v2": 91},
        )

    def test_git_object_verifier_and_controls_reproduce_gen3(self) -> None:
        chain = verifier.verify_chain(self.repo, verifier.GEN3_COMMIT)
        self.assertEqual(chain.tree, verifier.GEN3_TREE)
        controls = verifier.run_controls(chain, chain)
        self.assertTrue(controls["old_manifest_new_carrier_rejected"])
        self.assertTrue(controls["new_manifest_old_carrier_rejected"])
        self.assertEqual(
            controls["cross_pair_source"], "deterministic-synthetic-successor"
        )

    def test_synthetic_successor_matches_independent_formulas(self) -> None:
        new_engine = reanchor.sha256_bytes(b"nq.c1.test-successor-engine.v1")
        review_binding = self.synthetic_review_binding(new_engine)
        generated, receipt = reanchor.reanchor_bundle(
            self.baseline,
            self.old_engine,
            new_engine,
            review_binding=review_binding,
        )
        manifest_v1 = verifier.load_json(
            generated[verifier.MANIFEST_V1_PATH], "generated manifest v1"
        )
        manifest_v2 = verifier.load_json(
            generated[verifier.MANIFEST_V2_PATH], "generated manifest v2"
        )
        carrier = verifier.load_json(
            generated[verifier.CARRIER_PATH], "generated carrier"
        )

        self.assertEqual(verifier.engine_census(manifest_v1, new_engine, "v1"), 91)
        self.assertEqual(verifier.engine_census(manifest_v2, new_engine, "v2"), 91)
        self.assertEqual(
            verifier.basis_digest(manifest_v2), receipt["qualification_basis_sha256"]
        )
        self.assertEqual(
            verifier.pre_review_digest(carrier), receipt["pre_review_projection_sha256"]
        )
        self.assertEqual(
            verifier.carrier_identity(carrier), receipt["qualification_id"]
        )
        verifier.validate_pair(
            manifest_v2,
            carrier,
            generated[verifier.CARRIER_PATH],
            "generated pair",
        )

        self.assertEqual(
            carrier["implementation_bindings"]["post_acceptance_review"],
            reanchor.carrier_review_from_binding(review_binding),
        )

        extension = verifier.load_json(
            generated[verifier.EXTENSION_PATH], "generated extension"
        )
        rows = verifier.extension_rows(extension)
        for identity, path in verifier.STATIC_ASSETS.items():
            self.assertEqual(
                rows[identity]["sha256"], verifier.sha256_bytes(generated[path])
            )

    def test_changed_cut_cannot_retarget_unchanged_review(self) -> None:
        new_engine = reanchor.sha256_bytes(b"nq.c1.stale-review-control.v1")
        with self.assertRaisesRegex(
            reanchor.Refusal, "without a fresh independent review binding"
        ):
            reanchor.reanchor_bundle(self.baseline, self.old_engine, new_engine)

    def test_review_preparation_is_explicit_and_updates_evaluator_family(self) -> None:
        old_evaluator = reanchor.sha256_bytes(
            reanchor.git_object(self.repo, self.gen3, reanchor.EVALUATOR_PATH)
        )
        new_evaluator = reanchor.sha256_bytes(b"review-preparation-evaluator")
        generated, receipt = reanchor.reanchor_bundle(
            self.baseline,
            self.old_engine,
            self.old_engine,
            old_evaluator_digest=old_evaluator,
            new_evaluator_digest=new_evaluator,
            prepare_review=True,
        )
        carrier = reanchor.load_json(
            generated[reanchor.CARRIER_PATH], "prepared carrier"
        )
        implementation = carrier["implementation_bindings"]
        for field in ("evaluator", "independent_arithmetic", "test_source"):
            self.assertEqual(implementation[field]["sha256"], new_evaluator)
        self.assertEqual(
            carrier["qualification_budget"]["enforcement_binding"]["sha256"],
            new_evaluator,
        )
        review = implementation["post_acceptance_review"]
        self.assertEqual(
            review["pre_review_projection_sha256"],
            reanchor.pre_review_projection(carrier),
        )
        self.assertEqual(
            receipt["review_disposition"],
            "prepared-pre-review-projection-old-verdict-is-not-evidence",
        )

    def test_review_preparation_refreshes_only_exact_censused_source_bindings(
        self,
    ) -> None:
        source_path = "crates/nq-core/src/identity.rs"
        old_digest = reanchor.sha256_bytes(
            reanchor.git_object(self.repo, self.gen3, source_path)
        )
        new_digest = reanchor.sha256_bytes(b"candidate identity implementation")
        generated, receipt = reanchor.reanchor_bundle(
            self.baseline,
            self.old_engine,
            self.old_engine,
            source_binding_replacements=(
                (source_path, old_digest, new_digest, 11),
            ),
            prepare_review=True,
        )
        for manifest_path in (
            reanchor.MANIFEST_V1_PATH,
            reanchor.MANIFEST_V2_PATH,
        ):
            manifest = reanchor.load_json(
                generated[manifest_path], "refreshed source-binding manifest"
            )
            nodes = reanchor.source_binding_nodes(manifest, source_path)
            self.assertEqual(len(nodes), 11)
            self.assertEqual(
                {node["source_sha256"] for node in nodes}, {new_digest}
            )
        self.assertEqual(
            receipt["exact_source_binding_replacements"][source_path],
            {
                "baseline_sha256": old_digest,
                "candidate_sha256": new_digest,
                "binding_replacements": {
                    "manifest_v1": 11,
                    "manifest_v2": 11,
                    "assets_rs": 1,
                },
            },
        )
        assets_rs = generated[reanchor.ASSETS_RS_PATH].decode("utf-8")
        self.assertEqual(
            assets_rs.count(reanchor.source_closure_pin(source_path, new_digest)), 1
        )
        self.assertNotIn(reanchor.source_closure_pin(source_path, old_digest), assets_rs)

    def test_source_binding_refresh_refuses_an_inexact_census(self) -> None:
        source_path = "crates/nq-core/src/identity.rs"
        old_digest = reanchor.sha256_bytes(
            reanchor.git_object(self.repo, self.gen3, source_path)
        )
        manifest = reanchor.load_json(
            self.baseline[reanchor.MANIFEST_V1_PATH], "source-binding census control"
        )
        with self.assertRaisesRegex(reanchor.Refusal, "expected exactly 12"):
            reanchor.replace_exact_source_bindings(
                manifest,
                source_path,
                old_digest,
                reanchor.sha256_bytes(b"replacement"),
                12,
                "source-binding census control",
            )

    def test_source_binding_refresh_refuses_duplicate_or_noop_specs(self) -> None:
        source_path = "crates/nq-core/src/identity.rs"
        old_digest = reanchor.sha256_bytes(
            reanchor.git_object(self.repo, self.gen3, source_path)
        )
        replacement = (source_path, old_digest, reanchor.sha256_bytes(b"new"), 11)
        with self.assertRaisesRegex(reanchor.Refusal, "must be unique"):
            reanchor.reanchor_bundle(
                self.baseline,
                self.old_engine,
                self.old_engine,
                source_binding_replacements=(replacement, replacement),
                prepare_review=True,
            )
        with self.assertRaisesRegex(reanchor.Refusal, "is a no-op"):
            reanchor.reanchor_bundle(
                self.baseline,
                self.old_engine,
                self.old_engine,
                source_binding_replacements=((source_path, old_digest, old_digest, 11),),
                prepare_review=True,
            )

    def test_check_mode_selects_no_write_path(self) -> None:
        def baseline_file(_repo: Path, relative: str) -> bytes:
            if relative in (reanchor.ENGINE_PATH, reanchor.EVALUATOR_PATH):
                return reanchor.git_object(self.repo, self.gen3, relative)
            return self.baseline[relative]

        def baseline_bundle(_repo: Path) -> dict[str, bytes]:
            return dict(self.baseline)

        def forbidden_write(*_args, **_kwargs) -> None:
            self.fail("--check reached the write implementation")

        original_file = reanchor.read_worktree_file
        original_bundle = reanchor.read_worktree_bundle
        original_write = reanchor.write_bundle_atomically
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            reanchor.read_worktree_file = baseline_file
            reanchor.read_worktree_bundle = baseline_bundle
            reanchor.write_bundle_atomically = forbidden_write
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = reanchor.main(
                    [
                        "--repo",
                        str(ROOT),
                        "--baseline-commit",
                        reanchor.GEN3_COMMIT,
                        "--check",
                    ]
                )
            self.assertEqual(result, 0, stderr.getvalue())
        finally:
            reanchor.read_worktree_file = original_file
            reanchor.read_worktree_bundle = original_bundle
            reanchor.write_bundle_atomically = original_write

    def test_missing_git_commit_refuses(self) -> None:
        with self.assertRaisesRegex(verifier.Refusal, "Git failed"):
            verifier.resolve_commit(
                self.repo,
                "0000000000000000000000000000000000000000",
                "missing test commit",
            )

    def test_duplicate_json_key_refuses(self) -> None:
        with self.assertRaisesRegex(reanchor.Refusal, "duplicate JSON object key"):
            reanchor.load_json(b'{"a":1,"a":2}', "duplicate control")


if __name__ == "__main__":
    unittest.main()
