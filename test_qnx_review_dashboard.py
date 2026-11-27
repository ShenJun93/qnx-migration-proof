import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from qnx_review_dashboard import render, main
from qnx_migration_plan import make_plan

class DashboardTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.src=self.root/"source"
        self.src.mkdir()
        (self.src/"build").write_text("io-pkt-v6-hc <script>alert(1)</script>\n")
    def test_escaped_excerpt_and_offline(self):
        page=render(make_plan(self.src))
        self.assertNotIn("<script>alert(1)</script>",page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;",page)
        self.assertIn("default-src 'none'",page)
        self.assertNotIn("<script src=",page)
    def test_evidence_boundaries(self):
        b=make_plan(self.src)
        page=render(b)
        self.assertIn(b["receipt"]["sha256"],page)
        self.assertIn("PROJECT VALIDATION: NOT RUN",page)
        self.assertIn("SDK inventory not requested",page)
        self.assertIn("Unsigned snapshot",page)
    def test_no_overwrite(self):
        out=self.root/"review.html"
        out.write_text("existing")
        stderr=io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            main([str(self.src),"--output",str(out)])
        self.assertEqual(raised.exception.code,2)
        self.assertIn("error:",stderr.getvalue())
        self.assertEqual(out.read_text(),"existing")
    def test_empty(self):
        (self.src/"build").write_text("io-sock")
        self.assertIn("No scoped migration candidates observed",render(make_plan(self.src)))
    def test_creates_page(self):
        out=self.root/"review.html"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.src),"--output",str(out)]),0)
        self.assertTrue(out.read_text().startswith("<!doctype html>"))
if __name__=="__main__":
    unittest.main()
