"""Self-contained host tests. Fixtures are SYNTHETIC migration examples, not QNX runtime captures."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from qnx_migration_audit import inspect_file, main, mask_c_comments_and_strings, scan


class QnxMigrationAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, name, contents):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents, encoding="utf-8")
        return p

    def ids(self):
        findings, count = scan(self.root)
        return [f.rule_id for f in findings], count, findings

    def test_legacy_io_pkt(self):
        self.put("bsp.bld", "io-pkt-v6-hc\n")
        ids, count, results = self.ids()
        self.assertIn("QNX8-NET-001", ids)
        self.assertEqual(results[0].line, 1)
        self.assertEqual(count, 1)

    def test_devnp_network_driver(self):
        self.put("image.bld", "devnp-e1000.so\n")
        self.assertIn("QNX8-NET-002", self.ids()[0])

    def test_removed_dhcp_utilities(self):
        self.put("start.sh", "dhclient\nrtsold\nautoipd\n")
        ids, _, _ = self.ids()
        self.assertEqual(ids.count("QNX8-NET-003"), 3)

    def test_unsupported_data_attribute(self):
        self.put("image.build", "[data=c] libc.so\n")
        self.assertIn("QNX8-BLD-001", self.ids()[0])

    def test_qnx_extensionless_buildfile_is_scanned(self):
        self.put("src/hardware/startup/boards/imx8/build", "[data=c]\nio-pkt-v6-hc\n")
        ids, inspected, findings = self.ids()
        self.assertEqual(inspected, 1)
        self.assertIn("QNX8-BLD-001", ids)
        self.assertIn("QNX8-NET-001", ids)
        self.assertTrue(all(f.path.endswith("/build") for f in findings))

    def test_directory_named_build_can_contain_source(self):
        self.put("build/legacy.c", "InterruptAttach(5, handler, arg, 0, 0);\n")
        self.assertEqual(self.ids()[0], ["QNX8-SRC-001"])
        self.assertEqual(self.ids()[1], 1)

    def test_extensionless_build_file_at_root_is_scanned(self):
        self.put("build", "[data=c]\n")
        self.assertEqual(self.ids()[0], ["QNX8-BLD-001"])
    def test_unrelated_extensionless_file_is_not_scanned(self):
        self.put("src/NOT_A_BUILD_FILE", "[data=c]\nio-pkt-v6-hc\n")
        self.assertEqual(self.ids(), ([], 0, []))

    def test_config_not_reported_as_buildfile_for_data_attribute(self):
        self.put("flags.mk", "[data=c]\n")
        self.assertNotIn("QNX8-BLD-001", self.ids()[0])

    def test_qcrypto_two_path_occurrences_one_finding_per_line(self):
        self.put("qcrypto.conf", "/usr/lib/qcrypto-openssl.so=qcrypto-openssl.so\n")
        ids, _, _ = self.ids()
        self.assertEqual(ids.count("QNX8-CRYPTO-001"), 1)
    def test_old_qcrypto(self):
        self.put("qcrypto.conf", "qcrypto-openssl.so\n")
        self.assertIn("QNX8-CRYPTO-001", self.ids()[0])

    def test_interrupt_attach_in_c(self):
        self.put("driver.c", "int id = InterruptAttach(5, handler, arg, 0, 0);\n")
        self.assertIn("QNX8-SRC-001", self.ids()[0])

    def test_new_interrupt_api_is_not_flagged(self):
        self.put("driver.c", "int id = InterruptAttachEvent(5, &event, 0);\n")
        self.assertEqual(self.ids()[0], [])

    def test_i2c_commands(self):
        self.put("i2c.c", "devctl(fd, DCMD_I2C_MASTER_SEND, &msg, 0, 0);\n")
        self.assertIn("QNX8-SRC-003", self.ids()[0])

    def test_login_header(self):
        self.put("driver.h", "#include <login.h>\n")
        self.assertIn("QNX8-SRC-002", self.ids()[0])

    def test_comments_and_strings_are_ignored_for_source(self):
        self.put("sample.c",
                 "// InterruptAttach(1, x)\n"
                 "/* DCMD_I2C_MASTER_SEND\n"
                 " InterruptAttach(5, handler) */\n"
                 'char *s = "InterruptAttach(3, h)";\n'
                 "int y = InterruptAttachEvent(3, &e, 0);\n")
        self.assertEqual(self.ids()[0], [])

    def test_buildfile_comments_are_ignored(self):
        self.put("image.bld", "# io-pkt-v6\n  # devnp-e1000.so\nio-sock\n")
        self.assertEqual(self.ids()[0], [])

    def test_removed_auxbase_compiler_flag(self):
        self.put("Makefile", "CFLAGS += -auxbase version\n")
        self.assertIn("QNX8-CC-001", self.ids()[0])

    def test_non_code_docs_are_ignored(self):
        self.put("README.md", "io-pkt devnp-e1000 InterruptAttach DCMD_I2C_MASTER_SEND")
        self.assertEqual(self.ids(), ([], 0, []))

    def test_skips_generated_directories(self):
        self.put(".git/legacy.c", "InterruptAttach(1, 2)\n")
        self.put("node_modules/a.c", "InterruptAttach(1, 2)\n")
        self.put("src/main.c", "InterruptAttachEvent(1, &e, 0)\n")
        self.assertEqual(self.ids(), ([], 1, []))

    def test_line_number_and_relative_path(self):
        self.put("bsp/image.bld", "# old\n\n  devnp-foo.so\n")
        ids, _, findings = self.ids()
        self.assertIn("QNX8-NET-002", ids)
        item = next(x for x in findings if x.rule_id == "QNX8-NET-002")
        self.assertEqual((item.path, item.line, item.column), ("bsp/image.bld", 3, 3))

    def test_json_output_includes_clear_proof_boundary(self):
        self.put("bsp.bld", "io-pkt-v6\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exitcode = main([str(self.root), "--format", "json"])
        result = json.loads(output.getvalue())
        self.assertEqual(exitcode, 0)
        self.assertIn("not a QNX build", result["claim"])
        self.assertEqual(result["findings"][0]["rule_id"], "QNX8-NET-001")

    def test_fail_on_high(self):
        self.put("bsp.bld", "io-pkt-v6\n")
        with contextlib.redirect_stdout(io.StringIO()):
            exitcode = main([str(self.root), "--fail-on", "high"])
        self.assertEqual(exitcode, 1)

    def test_medium_only_does_not_fail_high_gate(self):
        self.put("qcrypto.conf", "qcrypto-openssl.so\n")
        with contextlib.redirect_stdout(io.StringIO()):
            exitcode = main([str(self.root), "--fail-on", "high"])
        self.assertEqual(exitcode, 0)

    def test_repeated_scan_is_deterministic(self):
        self.put("bsp.bld", "devnp-a.so\nio-pkt-v6\n")
        one = scan(self.root)
        two = scan(self.root)
        self.assertEqual(one, two)

    def test_size_limit_skips_large_source(self):
        self.put("huge.c", "InterruptAttach(1, 2);\n" + " " * 1024 * 1024)
        self.assertEqual(self.ids()[0], [])

    def test_multiline_block_comment_is_not_reported(self):
        self.put("main.cpp", "/* x \n InterruptAttach(2, y);\n*/\nint main(){ return 0; }\n")
        self.assertEqual(self.ids()[0], [])

    def test_exact_line_preserved_after_comment_masking(self):
        self.put("main.c", "/* old InterruptAttach(x) */\nint x=InterruptAttach(4,h,p,0,0);\n")
        _, _, findings = self.ids()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)


if __name__ == "__main__":
    unittest.main()
