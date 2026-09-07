#!/usr/bin/env python3
"""Negative controls for the M30 executable encryption-frame oracle."""

import importlib.util
import pathlib
import subprocess
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("encrypt_oracle", ROOT / "harness/diff_encrypt.py")
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


def output_of(rows):
    return "".join(f"ENCRYPT_KAT\t{name}\t{plaintext}\t{frame}\n"
                   for name, (plaintext, frame) in rows.items())


class EncryptOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = ORACLE.vectors()
        cls.output = output_of(cls.expected) + "4/4 ok\n"
        cls.executable = ROOT / "_build/default/test/test_encryptx.exe"

    def test_published_self_check(self):
        ORACLE.self_check()

    def test_self_check_rejects_wrong_primitive(self):
        with mock.patch.object(ORACLE, "seal", return_value=(bytes(16), bytes(16))):
            with self.assertRaisesRegex(ValueError, "published vector"):
                ORACLE.self_check()

    def test_exact_expected_inputs(self):
        self.assertEqual(ORACLE.MESSAGES, {
            "empty": b"", "zero16": bytes(16),
            "utf8": "hi\U0001f30a".encode("utf-8"),
            "binary": b"\x00\x01\xff\x80\x7f\x10\x00\x0a\x0d\x5c\x22",
        })

    def test_complete_runtime_rows(self):
        ORACLE.verify_output(self.output, self.expected)

    def test_actual_executable_outputs(self):
        self.assertEqual(ORACLE.run(self.executable), 4)

    def test_modified_public_key_nonce_ciphertext_and_tag(self):
        plaintext, frame_hex = self.expected["zero16"]
        for field, offset in (("public key", 1), ("nonce", 65),
                              ("ciphertext", 77), ("tag", 93)):
            with self.subTest(field=field):
                frame = bytearray.fromhex(frame_hex)
                frame[offset] ^= 1
                altered = self.expected | {"zero16": (plaintext, frame.hex())}
                with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                    ORACLE.verify_output(output_of(altered), self.expected)

    def test_modified_plaintext_is_rejected(self):
        plaintext, frame = self.expected["utf8"]
        altered = self.expected | {"utf8": ("00" + plaintext[2:], frame)}
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(output_of(altered), self.expected)

    def test_modified_plaintext_with_matching_frame_is_rejected(self):
        message = b"different but correctly encrypted"
        ct, tag = ORACLE.seal(message)
        frame = ORACLE.CLIENT + ORACLE.NONCE + ct + tag
        altered = self.expected | {"utf8": (message.hex(), frame.hex())}
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(output_of(altered), self.expected)

    def test_tag_first_swap_is_rejected(self):
        plaintext, frame_hex = self.expected["zero16"]
        frame = bytes.fromhex(frame_hex)
        swapped = frame[:77] + frame[-16:] + frame[77:-16]
        self.assertNotEqual(swapped, frame)
        altered = self.expected | {"zero16": (plaintext, swapped.hex())}
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(output_of(altered), self.expected)

    def test_empty_or_no_runtime_rows_are_rejected(self):
        for output in ("", "4/4 ok\n"):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                    ORACLE.verify_output(output, self.expected)

    def test_each_missing_runtime_row_is_rejected(self):
        for missing in self.expected:
            with self.subTest(missing=missing):
                altered = {name: row for name, row in self.expected.items() if name != missing}
                with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                    ORACLE.verify_output(output_of(altered), self.expected)

    def test_duplicate_runtime_row_is_rejected(self):
        row = output_of({"empty": self.expected["empty"]})
        with self.assertRaisesRegex(ValueError, "duplicate executable KAT"):
            ORACLE.verify_output(self.output + row, self.expected)

    def test_unexpected_runtime_row_is_rejected(self):
        altered = self.expected | {"unknown": self.expected["empty"]}
        with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
            ORACLE.verify_output(output_of(altered), self.expected)

    def test_malformed_runtime_row_is_rejected(self):
        for row in ("ENCRYPT_KAT\tbroken\n", "ENCRYPT_KAT empty\t\t00\n",
                    "ENCRYPT_KAT\tempty\t\t00\textra\n"):
            with self.subTest(row=row):
                with self.assertRaisesRegex(ValueError, "malformed executable KAT"):
                    ORACLE.verify_output(self.output + row, self.expected)

    def test_truncated_or_extended_frame_is_rejected(self):
        plaintext, frame = self.expected["empty"]
        for bad_frame in ("", frame[:-2], frame + "00"):
            with self.subTest(frame=bad_frame):
                altered = self.expected | {"empty": (plaintext, bad_frame)}
                with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                    ORACLE.verify_output(output_of(altered), self.expected)

    def test_run_checks_actual_executable_output(self):
        result = subprocess.CompletedProcess([str(self.executable)], 0, self.output, "")
        with mock.patch.object(ORACLE.subprocess, "run", return_value=result) as execute:
            self.assertEqual(ORACLE.run(self.executable), 4)
            execute.assert_called_once_with([str(self.executable)], text=True,
                                            capture_output=True, check=False, timeout=180)

    def test_run_rejects_nonzero_exit_with_correct_output(self):
        result = subprocess.CompletedProcess([str(self.executable)], 1, self.output, "failure")
        with mock.patch.object(ORACLE.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "OCaml suite failed"):
                ORACLE.run(self.executable)

    def test_run_rejects_fail_on_either_stream_with_success_exit(self):
        for stdout, stderr in ((self.output + "FAIL admission\n", ""),
                               (self.output, "FAIL admission\n")):
            with self.subTest(stderr=bool(stderr)):
                result = subprocess.CompletedProcess([str(self.executable)], 0, stdout, stderr)
                with mock.patch.object(ORACLE.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(ValueError, "OCaml suite failed"):
                        ORACLE.run(self.executable)

    def test_run_rejects_empty_output_with_success_exit(self):
        result = subprocess.CompletedProcess([str(self.executable)], 0, "", "")
        with mock.patch.object(ORACLE.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "executable KAT mismatch"):
                ORACLE.run(self.executable)


if __name__ == "__main__":
    unittest.main()
