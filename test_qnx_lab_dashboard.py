import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from qnx_lab_dashboard import load_verified_lab, stage_html, lab_html
from qnx_evidence_receipt import digest
import json

class LabDashboardTests(unittest.TestCase):
    def test_stage_escapes_untrusted_log(self):
        row=dict(stdout="<script>alert(1)</script>",stderr="",exit_code=1,findings=["x"],command="qcc",binary_sha256=None)
        page=stage_html("Before",row)
        self.assertNotIn("<script>",page)
        self.assertIn("&lt;script&gt;",page)
    def test_bad_digest_rejected_before_read(self):
        with self.assertRaises(ValueError):
            load_verified_lab(Path("missing"),Path("sdk"),"invalid")
    def test_failed_verification_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"lab.json").write_text("{}")
            with patch("qnx_lab_dashboard.verify_lab",return_value=(False,"changed")):
                with self.assertRaisesRegex(ValueError,"changed"):
                    load_verified_lab(root,root,"a"*64)
    def test_digest_and_snapshot_match(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            payload={"cases":[]}
            pin=digest(payload)
            bundle={"payload":payload,"sha256":pin}
            (root/"lab.json").write_text(json.dumps(bundle))
            with patch("qnx_lab_dashboard.verify_lab",return_value=(True,"match")):
                self.assertEqual(load_verified_lab(root,root,pin),bundle)
                with self.assertRaisesRegex(ValueError,"digest changed"):
                    load_verified_lab(root,root,"b"*64)
    def test_scope_explicit(self):
        page=lab_html({"payload":{"cases":[]},"sha256":"test"})
        self.assertIn("NOT a build of the project",page)
        self.assertIn("runtime NOT RUN",page)
        self.assertIn("does not verify live",page)
