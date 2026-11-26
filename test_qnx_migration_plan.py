from pathlib import Path
import tempfile
import unittest

from qnx_migration_plan import make_plan, literal_reference, CHECKS
from qnx_migration_audit import RULES, MAX_FILE_BYTES
from qnx_evidence_receipt import digest


class PlanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.old = self.root / "old"
        self.new = self.root / "new"
        self.old.mkdir()
        self.new.mkdir()
        (self.old / "build").write_text("io-pkt-v6-hc\ndevnp-e1000.so\ndhclient\n")
        (self.new / "build").write_text("io-sock\ndhcpcd\n")
        self.sdk = self.root / "sdk"
        target = self.sdk / "target/qnx/x86_64"
        target.mkdir(parents=True)
        (target / "io-sock").write_bytes(b"test")

    def plan(self, compare=True):
        return make_plan(self.old, self.sdk, compare=self.new if compare else None)

    def test_all_rules_have_checklists(self):
        self.assertEqual(set(CHECKS), {r.id for r in RULES})

    def test_no_false_validation_claims(self):
        b = self.plan()
        for t in b["plan"]["tasks"]:
            self.assertEqual(t["validation_state"], "not_run")
            self.assertEqual(t["review_state"], "not_observed_in_comparison")
            self.assertFalse(t["automatic_edit"])
            self.assertTrue(t["locations"][0]["source_sha256"])

    def test_digest_binding(self):
        b = self.plan()
        self.assertEqual(b["plan_sha256"], digest(b["plan"]))
        self.assertEqual(b["plan"]["receipt_sha256"], digest(b["receipt"]["payload"]))
        self.assertEqual(b, self.plan())

    def test_no_source_mutation(self):
        before = (self.old / "build").read_bytes()
        self.plan()
        self.assertEqual(before, (self.old / "build").read_bytes())

    def test_literal_inventory(self):
        t = next(t for t in self.plan()["plan"]["tasks"] if t["rule_id"] == "QNX8-NET-001")
        self.assertEqual(t["locations"][0]["literal_inventory_context"][0]["sdk_observation"]["status"], "not_found")
        self.assertFalse(literal_reference("dhclient", "dhclient-script"))
        self.assertTrue(literal_reference("dhclient", "/var/dhclient/leases"))
        self.assertFalse(literal_reference("devnp-e1000.so", "devnp-e1000.so.sym"))

    def test_incomplete_comparison(self):
        (self.new / "big.c").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        self.assertTrue(all(t["review_state"] == "comparison_incomplete" for t in self.plan()["plan"]["tasks"]))

    def test_baseline_only(self):
        self.assertTrue(all(t["review_state"] == "baseline_only" for t in self.plan(False)["plan"]["tasks"]))

    def test_remaining_and_comparison_only(self):
        (self.new / "build").write_text("dhclient\n[data=c]\n")
        tasks = {t["rule_id"]: t for t in self.plan()["plan"]["tasks"]}
        self.assertEqual(tasks["QNX8-NET-003"]["review_state"], "candidates_remain_in_comparison")
        self.assertEqual(tasks["QNX8-BLD-001"]["review_state"], "comparison_only_candidate")


if __name__ == "__main__":
    unittest.main()
