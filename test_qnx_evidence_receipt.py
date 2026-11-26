import copy
from pathlib import Path
import tempfile
import unittest

from qnx_evidence_receipt import create_receipt, verify_receipt, digest, source_manifest, unique_pairs
from qnx_migration_audit import MAX_FILE_BYTES


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.src = self.root / "source"
        self.src.mkdir()
        (self.src / "build").write_text("io-pkt-v6-hc\n")
        self.new = self.root / "new"
        self.new.mkdir()
        (self.new / "build").write_text("io-sock\n")
        self.sdk = self.root / "sdk"
        self.target = self.sdk / "target/qnx/x86_64"
        self.target.mkdir(parents=True)
        (self.target / "io-sock").write_bytes(b"fake artifact")

    def create(self):
        return create_receipt(self.src, self.sdk, compare=self.new)

    def verify(self, receipt, expected=None):
        return verify_receipt(receipt, self.src, self.sdk, compare=self.new, expected=expected)

    def test_repeatable(self):
        a = self.create()
        self.assertEqual(a, self.create())
        self.assertTrue(self.verify(a, a["sha256"])[0])

    def test_tamper(self):
        a = self.create()
        a["payload"]["report"]["source"]["findings"].clear()
        self.assertIn("digest mismatch", self.verify(a)[1])

    def test_rehashed_tamper(self):
        a = self.create()
        expected = a["sha256"]
        a["payload"]["report"]["source"]["findings"].clear()
        a["sha256"] = digest(a["payload"])
        self.assertIn("independent digest mismatch", self.verify(a, expected)[1])
        self.assertIn("replay mismatch", self.verify(a)[1])

    def test_source_drift_without_rule_change(self):
        a = self.create()
        (self.src / "build").write_text("io-pkt-v6-hc\n# comment\n")
        self.assertIn("source_manifest", self.verify(a)[1])

    def test_sdk_binary_drift(self):
        a = self.create()
        (self.target / "io-sock").write_bytes(b"different artifact")
        self.assertIn("report", self.verify(a)[1])

    def test_comparison_drift(self):
        a = self.create()
        (self.new / "build").write_text("io-pkt-v6-hc\n")
        self.assertIn("comparison_manifest", self.verify(a)[1])

    def test_skipped_files(self):
        (self.src / "big.c").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        (self.src / "bad.c").write_bytes(b"\xff")
        rows = {v["path"]: v for v in source_manifest(self.src)}
        self.assertEqual(rows["big.c"]["status"], "oversize_skipped")
        self.assertEqual(rows["bad.c"]["status"], "non_utf8_skipped")
        self.assertNotIn("sha256", rows["big.c"])

    def test_portable_paths(self):
        a = self.create()
        moved = self.root / "moved"
        moved.mkdir()
        (moved / "build").write_bytes((self.src / "build").read_bytes())
        self.assertEqual(a, create_receipt(moved, self.sdk, compare=self.new))

    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError):
            unique_pairs([("a", 1), ("a", 2)])


if __name__ == "__main__":
    unittest.main()
