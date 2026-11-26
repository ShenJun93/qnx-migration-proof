import tempfile
import unittest
from pathlib import Path
from qnx_migration_audit import scan_detailed, MAX_FILE_BYTES
from qnx_evidence_receipt import create_receipt, verify_receipt

class HardeningTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
    def put(self, name, text):
        p = self.root/name
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(text if isinstance(text,bytes) else text.encode())
    def test_inline_comments_and_quoted_tokens(self):
        self.put("flags.mk","CFLAGS = -O2 # old -auxbase\n")
        self.put("start.sh",'echo "# dhclient"\n# dhclient\n')
        f,_=scan_detailed(self.root)
        self.assertEqual([(x.path,x.line,x.rule_id) for x in f],[("start.sh",1,"QNX8-NET-003")])
    def test_multiline_preserves_position(self):
        self.put("src/build/driver.c","// old\n  InterruptAttach\n   /* comment */ (0,0,0,0,0);\n")
        f,c=scan_detailed(self.root)
        self.assertEqual(c["inspected_files"],1)
        self.assertEqual([(x.line,x.column,x.rule_id) for x in f],[(2,3,"QNX8-SRC-001")])
    def test_exact_stack_names(self):
        self.put("image.bld","io-pkt-v6-hc-custom\nio-pkt-v6-hc\nio-pkt-v4-lite\nio-pkt\n")
        f,_=scan_detailed(self.root)
        self.assertEqual([x.line for x in f],[2,3,4])
    def test_skips_exposed_in_receipt(self):
        self.put("bad.c",b"\xff")
        self.put("large.c",b"x"*(MAX_FILE_BYTES+1))
        self.put("good.c","int main(void){return 0;}\n")
        f,c=scan_detailed(self.root)
        self.assertEqual(f,[])
        self.assertEqual(c,{"recognized_files":3,"inspected_files":1,"skipped_files":2,"skip_reasons":{"non_utf8_skipped":1,"oversize_skipped":1}})
        r=create_receipt(self.root)
        self.assertEqual(r["payload"]["report"]["source"]["coverage"],c)
        self.assertTrue(verify_receipt(r,self.root)[0])
    def test_conditional_code_remains_candidate(self):
        self.put("driver.c","#if 0\nInterruptAttach(0,0,0,0,0);\n#endif\n")
        f,_=scan_detailed(self.root)
        self.assertEqual(len(f),1)
