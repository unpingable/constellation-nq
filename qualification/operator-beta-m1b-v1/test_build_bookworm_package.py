import copy
import importlib.util
import pathlib
import tempfile
import unittest

PATH = pathlib.Path(__file__).with_name("build_bookworm_package.py")
SPEC = importlib.util.spec_from_file_location("nq_bookworm_builder", PATH)
assert SPEC and SPEC.loader
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class BuilderTests(unittest.TestCase):
    def test_vendor_tree_digest_changes_and_refuses_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "crate").mkdir()
            source = root / "crate/lib.rs"
            source.write_text("one\n")
            first = BUILDER.tree_digest(root)
            source.write_text("two\n")
            self.assertNotEqual(first, BUILDER.tree_digest(root))
            (root / "link").symlink_to(source)
            with self.assertRaisesRegex(BUILDER.Refusal, "non-regular"):
                BUILDER.tree_digest(root)

    def test_build_command_closes_network_paths_and_environment(self) -> None:
        command = BUILDER.build_command(pathlib.Path("/source"), pathlib.Path("/vendor-input"), pathlib.Path("/case"))
        self.assertIn("none", command)
        self.assertIn("never", command)
        self.assertIn("1000:1000", command)
        self.assertIn("/source:/src:ro", command)
        self.assertIn("/vendor-input:/vendor:ro", command)
        self.assertIn("/case/cargo-home:/cargo-home:rw", command)
        self.assertIn("/case/build:/build:rw", command)
        self.assertEqual(command[-8:], ["cargo", "build", "--workspace", "--release", "--locked", "--offline", "--jobs", "4"])
        normalized = BUILDER.normalized_build_command()
        self.assertIn("<SOURCE>:/src:ro", normalized)
        self.assertIn("<BUILD>:/build:rw", normalized)
        self.assertEqual(BUILDER.BUILD_ENV["CARGO_INCREMENTAL"], "0")
        self.assertEqual(BUILDER.BUILD_ENV["SOURCE_DATE_EPOCH"], "1700000000")

    def test_build_records_the_pinned_source_commit_in_every_binary(self) -> None:
        # The assembler refuses binaries without one shared 40-hex source
        # commit, and the receipt records BUILD_ENV, so the pinned head is the
        # commit each packaged binary reports.
        self.assertRegex(BUILDER.SOURCE_HEAD, r"^[0-9a-f]{40}$")
        self.assertEqual(BUILDER.BUILD_ENV["NQ_SOURCE_COMMIT"], BUILDER.SOURCE_HEAD)
        command = BUILDER.build_command(pathlib.Path("/source"), pathlib.Path("/vendor-input"), pathlib.Path("/case"))
        self.assertIn(f"NQ_SOURCE_COMMIT={BUILDER.SOURCE_HEAD}", command)
        self.assertIn(f"NQ_SOURCE_COMMIT={BUILDER.SOURCE_HEAD}", BUILDER.normalized_build_command())

    def test_closed_receipt_refuses_identity_substitutions(self) -> None:
        receipt = {key: {} for key in BUILDER.RECEIPT_KEYS}
        for key in ("source", "builder", "binaries", "artifacts", "qualification"):
            changed = copy.deepcopy(receipt)
            changed[key] = {"substituted": True}
            with self.assertRaisesRegex(BUILDER.Refusal, "differs"):
                BUILDER.compare_receipt(receipt, changed)
        changed = copy.deepcopy(receipt)
        changed["unexpected"] = True
        with self.assertRaisesRegex(BUILDER.Refusal, "not closed"):
            BUILDER.compare_receipt(receipt, changed)


if __name__ == "__main__":
    unittest.main()
