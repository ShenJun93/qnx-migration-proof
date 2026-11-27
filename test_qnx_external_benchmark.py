"""Original regression fixtures derived from observed public code patterns."""
from pathlib import Path
import tempfile
import unittest
from qnx_migration_audit import scan
from qnx_migration_plan import make_plan

class ExternalBenchmarkRegression(unittest.TestCase):
    def test_isr_variants_and_event_exclusions(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"driver.c"
            p.write_text("InterruptAttach_r(1,h,a,0,0);\nInterruptAttachArray(2,h,a,0,0);\nInterruptAttachArray_r\n(3,h,a,0,0);\nInterruptAttachEvent_r(4,&e,0);\nInterruptAttachThread(5,0);\n// InterruptAttach_r(6,h,a,0,0)\n",encoding="utf8")
            f,_=scan(Path(d))
            self.assertEqual([(x.line,x.rule_id) for x in f],[(1,"QNX8-SRC-001"),(2,"QNX8-SRC-001"),(3,"QNX8-SRC-001")])
    def test_coverage_flags_are_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"Makefile"
            p.write_text("CFLAGS += -Wc,-auxbase-strip,$@\nCFLAGS += -Wc,-auxbase,name\nCFLAGS += -auxbase-custom\n",encoding="utf8")
            f,_=scan(Path(d))
            self.assertEqual([(x.line,x.rule_id) for x in f],[(1,"QNX8-CC-001"),(2,"QNX8-CC-001")])
    def test_language_flag_medium_and_plan(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"common.mk"
            p.write_text("CXX = qcc -lang-c++\nLDFLAGS += -lang-c++ -lsocket\n# -lang-c++\nCXX = qcc -lang-c++custom\n",encoding="utf8")
            f,_=scan(Path(d))
            self.assertEqual([(x.line,x.rule_id,x.severity) for x in f],[(1,"QNX8-CC-002","medium"),(2,"QNX8-CC-002","medium")])
            t=make_plan(Path(d))["plan"]["tasks"]
            self.assertEqual(len(t),1)
            self.assertEqual(t[0]["validation_state"],"not_run")
            self.assertFalse(t[0]["automatic_edit"])
