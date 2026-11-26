import tempfile
import unittest
from pathlib import Path
from qnx_migration_lab import CASES, classify, files_manifest

class LabTests(unittest.TestCase):
    def row(self, name, before):
        return {"findings":[CASES[name][0]] if before else [],
                "exit_code":0,"stderr":"","binary_sha256":"same"}
    def test_compiler_failure_requires_specific_diagnostic(self):
        a,b=self.row("auxbase",True),self.row("auxbase",False)
        a["exit_code"]=1
        a["stderr"]="compiler unavailable"
        self.assertEqual(classify("auxbase",a,b),"unexpected_observation")
        a["stderr"]="cc1: error: unrecognized command-line option '-auxbase'"
        self.assertEqual(classify("auxbase",a,b),"compiler_failure_to_success")
    def test_data_warning_not_build_failure(self):
        a,b=self.row("data",True),self.row("data",False)
        a["stderr"]="The 'data=' attribute is no longer supported."
        self.assertEqual(classify("data",a,b),"image_warning_to_clean")
        b["binary_sha256"]="different"
        self.assertEqual(classify("data",a,b),"unexpected_observation")
    def test_interrupt_build_is_not_runtime_proof(self):
        a,b=self.row("interrupt",True),self.row("interrupt",False)
        self.assertEqual(classify("interrupt",a,b),"both_compile_runtime_unverified")
    def test_scan_regression_rejected(self):
        a,b=self.row("stack",True),self.row("stack",False)
        a["exit_code"]=1
        a["stderr"]="Host file 'io-pkt-v6-hc' not available"
        b["findings"]=[CASES["stack"][0]]
        self.assertEqual(classify("stack",a,b),"unexpected_observation")
    def test_manifest_detects_artifact_change(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            f=root/"output"
            f.write_bytes(b"before")
            before=files_manifest(root)
            (root/"lab.json").write_text("{}")
            self.assertEqual(before,files_manifest(root))
            f.write_bytes(b"after")
            self.assertNotEqual(before,files_manifest(root))
