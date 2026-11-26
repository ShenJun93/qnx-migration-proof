import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qnx_migration_report import inventory, main, make_report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "old"
        self.src.mkdir()
        (self.src / "build").write_text("io-pkt-v6-hc\ndevnp-e1000.so\ndhclient\n")
        self.new = self.root / "new"
        self.new.mkdir()
        (self.new / "build").write_text("io-sock\ndevs-vtnet_pci.so\ndhcpcd\n")
        self.sdk = self.root / "sdk"
        self.target = self.sdk / "target" / "qnx" / "x86_64"
        self.target.mkdir(parents=True)
        (self.target / "io-sock").touch()

    def test_without_sdk(self):
        r = make_report(self.src)
        self.assertIsNone(r["sdk_inventory"])
        self.assertEqual(len(r["source"]["findings"]), 3)
        self.assertTrue(all(g["project_evidence"] == "static_candidate" for g in r["rule_groups"]))
        self.assertNotIn("inventory_context", r["rule_groups"][0])

    def test_paired_counts_and_inventory(self):
        r = make_report(self.src, self.sdk, compare=self.new)
        self.assertEqual(len(r["comparison"]["findings"]), 0)
        self.assertEqual(len(r["rule_groups"]), 3)
        self.assertTrue(all(g["comparison_count"] == 0 for g in r["rule_groups"]))
        a = r["sdk_inventory"]["artifacts"]
        self.assertEqual(a["io-pkt-v6-hc"]["status"], "not_found")
        self.assertEqual(a["io-sock"]["status"], "present")

    def test_legacy_present_not_assumed_absent(self):
        (self.target / "io-pkt-v6-hc").touch()
        self.assertEqual(inventory(self.sdk, "x86_64")["artifacts"]["io-pkt-v6-hc"]["status"], "present")

    def test_missing_target_rejected(self):
        with self.assertRaises(ValueError):
            inventory(self.sdk, "aarch64le")

    def test_incomplete_inventory_does_not_assert_absence(self):
        def broken_walk(target, followlinks, onerror):
            onerror(PermissionError("denied"))
            yield str(target), [], ["io-sock"]
        with patch("qnx_migration_report.os.walk", broken_walk):
            r = inventory(self.sdk, "x86_64")
        self.assertFalse(r["complete_for_named_files"])
        self.assertEqual(r["artifacts"]["io-pkt-v6-hc"]["status"], "unknown")

    def test_fixture_context_not_project_build(self):
        (self.src / "driver.c").write_text("int f(void){return InterruptAttach(0,0,0,0,0);}")
        r = make_report(self.src)
        g = next(g for g in r["rule_groups"] if g["rule_id"] == "QNX8-SRC-001")
        self.assertFalse(g["historical_fixture_context"]["applies_to_scanned_project"])
        self.assertEqual(g["project_evidence"], "static_candidate")
        self.assertIn("runtime_unverified", g["historical_fixture_context"]["observation"])

    def test_comparison_only_candidate(self):
        (self.new / "build").write_text("[data=c]")
        r = make_report(self.src, compare=self.new)
        g = next(g for g in r["rule_groups"] if g["rule_id"] == "QNX8-BLD-001")
        self.assertEqual((g["count"], g["comparison_count"]), (0, 1))

    def test_json_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main([str(self.src), "--format", "json"]), 0)
        self.assertEqual(json.loads(out.getvalue())["schema"], "qnx-migration-report/v0.1")


if __name__ == "__main__":
    unittest.main()
