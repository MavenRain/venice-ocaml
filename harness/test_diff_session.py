#!/usr/bin/env python3
"""Negative controls for the M29 source and executable-output oracle."""

import hashlib
import importlib.util
import pathlib
import subprocess
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("session_oracle", ROOT / "harness/diff_session.py")
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class SessionOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = ORACLE.vectors()
        cls.source = (ROOT / "test/test_sessx.ml").read_text()
        cls.executable = ROOT / "_build/default/test/test_sessx.exe"
        result = subprocess.run([str(cls.executable)], text=True, capture_output=True,
                                check=False, timeout=180)
        if result.returncode != 0:
            raise RuntimeError(result.stdout + result.stderr)
        cls.output = result.stdout

    def test_published_self_checks(self):
        ORACLE.self_check()

    def test_actual_executable_outputs(self):
        ORACLE.verify_output(self.output, self.expected)

    def test_source_pins(self):
        ORACLE.verify_pins(self.source, self.expected)

    def test_modified_runtime_client_ciphertext_and_tag(self):
        row = self.expected[0]
        for field in ("client", "ct", "tag"):
            with self.subTest(field=field):
                altered = "00" + row[field][2:]
                self.assertNotEqual(altered, row[field])
                with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                    ORACLE.verify_output(self.output.replace(row[field], altered), self.expected)

    def test_missing_runtime_row(self):
        altered = "\n".join(line for line in self.output.splitlines()
                            if not line.startswith("SESSION_KAT\tone\t"))
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(altered, self.expected)

    def test_duplicate_runtime_row(self):
        row = next(line for line in self.output.splitlines() if line.startswith("SESSION_KAT\t"))
        with self.assertRaisesRegex(ValueError, "duplicate executable KAT"):
            ORACLE.verify_output(self.output + row + "\n", self.expected)

    def test_unknown_runtime_row(self):
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(self.output + "SESSION_KAT\tunknown\t00\t00\t00\n", self.expected)

    def test_malformed_runtime_row(self):
        with self.assertRaisesRegex(ValueError, "malformed executable KAT"):
            ORACLE.verify_output(self.output + "SESSION_KAT\tbroken\n", self.expected)

    def test_no_runtime_rows(self):
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output("38/38 ok\n", self.expected)

    def test_source_pin_in_comment_is_rejected(self):
        needle = f'~ct:"{self.expected[0]["ct"]}"'
        altered = self.source.replace(needle, f'(* {needle} *) ~ct:"00"', 1)
        with self.assertRaisesRegex(ValueError, "absent from a KAT row"):
            ORACLE.verify_pins(altered, self.expected)

    def test_source_pin_in_label_is_rejected(self):
        needle = f'~ct:"{self.expected[0]["ct"]}"'
        altered = self.source.replace(needle, '~ct:"00"', 1)
        altered = altered.replace('"sessx: key schedule one"',
                                  '"' + needle.replace('"', '\\"') + '"', 1)
        with self.assertRaisesRegex(ValueError, "absent from a KAT row"):
            ORACLE.verify_pins(altered, self.expected)

    def test_source_pin_in_unused_definition_is_rejected(self):
        needle = f'~ct:"{self.expected[0]["ct"]}"'
        altered = self.source.replace(needle, '~ct:"00"', 1)
        altered += '\nlet unused = "' + needle.replace('"', '\\"') + '"\n'
        with self.assertRaisesRegex(ValueError, "absent from a KAT row"):
            ORACLE.verify_pins(altered, self.expected)

    def test_commented_suite_is_not_a_source_pin(self):
        with self.assertRaisesRegex(ValueError, "absent from a KAT row"):
            ORACLE.verify_pins("(* " + self.source + " *)", self.expected)

    def test_comment_stripping_preserves_literals_and_nesting(self):
        source = 'let s = "(* text *)" (* outer (* inner *) *)\n'
        self.assertEqual(ORACLE.strip_comments(source), 'let s = "(* text *)"   \n')
        for malformed in ('(* unfinished', '"unfinished'):
            with self.subTest(source=malformed), self.assertRaises(ValueError):
                ORACLE.strip_comments(malformed)

    def check_wrong_key(self, row, key):
        ct, tag = ORACLE.seal(key)
        self.assertNotEqual((ct.hex(), tag.hex()), (row["ct"], row["tag"]))
        altered = self.output.replace(row["ct"], ct.hex()).replace(row["tag"], tag.hex())
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(altered, self.expected)

    def test_wrong_info_and_salt_are_detected_in_runtime_output(self):
        row = self.expected[0]
        ikm = bytes.fromhex(row["ikm"])
        for info, salt in ((b"", b""), (b"ecdsa_encryption\x00", b""),
                           (b"ECDSA_encryption", b""), (ORACLE.INFO, b"salt")):
            with self.subTest(info=info, salt=salt):
                self.check_wrong_key(row, ORACLE.derive(ikm, info, salt))

    def test_wrong_ecdh_representations_are_detected_in_runtime_output(self):
        row = self.expected[0]
        shared = bytes.fromhex(row["shared"])
        ikm = bytes.fromhex(row["ikm"])
        compressed = bytes([2 | (shared[-1] & 1)]) + ikm
        for value in (shared, shared[1:], compressed, ikm.hex().encode(),
                      hashlib.sha256(ikm).digest()):
            with self.subTest(length=len(value)):
                self.check_wrong_key(row, ORACLE.derive(value))

    def test_leading_zero_secret_must_not_be_trimmed(self):
        row = self.expected[-1]
        ikm = bytes.fromhex(row["ikm"])
        self.assertEqual(len(ikm), 32)
        self.assertEqual(ikm[0], 0)
        self.assertNotEqual(ikm[1], 0)
        self.check_wrong_key(row, ORACLE.derive(ikm.lstrip(b"\x00")))

    def test_using_raw_secret_or_expand_without_extract_is_detected(self):
        row = self.expected[0]
        ikm = bytes.fromhex(row["ikm"])
        self.check_wrong_key(row, ikm)
        expanded_raw = ORACLE.hmac.new(ikm, ORACLE.INFO + b"\x01", hashlib.sha256).digest()
        self.check_wrong_key(row, expanded_raw)

    def test_run_rejects_modified_output_with_source_pins_intact(self):
        output = self.output.replace(self.expected[0]["tag"], "00" * 16)
        result = subprocess.CompletedProcess([str(self.executable)], 0, output, "")
        with mock.patch.object(ORACLE.subprocess, "run", return_value=result) as execute:
            with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                ORACLE.run(self.executable, ROOT / "test/test_sessx.ml")
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[0], [str(self.executable)])

    def test_run_rejects_nonzero_exit_even_with_correct_output(self):
        result = subprocess.CompletedProcess([str(self.executable)], 1, self.output, "failure")
        with mock.patch.object(ORACLE.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "OCaml suite failed"):
                ORACLE.run(self.executable, ROOT / "test/test_sessx.ml")

    def test_run_rejects_fail_text_even_with_success_exit(self):
        result = subprocess.CompletedProcess([str(self.executable)], 0,
                                             self.output + "FAIL admission\n", "")
        with mock.patch.object(ORACLE.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "OCaml suite failed"):
                ORACLE.run(self.executable, ROOT / "test/test_sessx.ml")


if __name__ == "__main__":
    unittest.main()
