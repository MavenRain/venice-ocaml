#!/usr/bin/env python3
"""Adversarial tests of independently recomputed M31 transcript evidence."""

import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "venice_m31_oracle", pathlib.Path(__file__).with_name("diff_e2ee.py"))
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = oracle.synthetic_fixture()
        cls.request = bytes.fromhex(cls.fixture["request_body_hex"])
        cls.response = bytes.fromhex(cls.fixture["response_body_hex"])
        cls.chunks = [oracle.strict_json(event[6:]) for event in cls.response.split(b"\n\n")[:-2]]
        cls.frame = cls.chunks[0]["choices"][0]["delta"]["content"]

    def verify(self, receipt=None, request=None, response=None, key=None, address=None):
        oracle.verify_receipt(
            self.fixture["receipt"] if receipt is None else receipt,
            self.request if request is None else request,
            self.response if response is None else response,
            self.fixture["signing_key"] if key is None else key,
            self.fixture["signing_address"] if address is None else address)

    def stream(self, chunks=None):
        return b"".join(b"data: " + json.dumps(c, separators=(",", ":")).encode() + b"\n\n"
                        for c in (self.chunks if chunks is None else chunks)) + b"data: [DONE]\n\n"

    def rejected_delta(self, delta):
        chunks = copy.deepcopy(self.chunks)
        chunks[0]["choices"][0]["delta"] = delta
        with self.assertRaises(ValueError):
            oracle.parse_stream(self.stream(chunks))

    def test_checked_in_fixture_and_independent_primitives(self):
        oracle.self_check()
        self.assertIn("SYNTHETIC", oracle.check_fixture(oracle.ROOT / "fixtures/e2ee_synthetic.json"))
        self.assertEqual(oracle.public_key(1), oracle._session.sec1(oracle.G).hex())

    def test_public_key_raw_xy_and_sec1(self):
        key = oracle.public_key(7)
        self.assertEqual(oracle.parse_public_key(key), oracle.parse_public_key(key[2:]))
        self.assertEqual(oracle.parse_public_key(key.upper()), oracle.parse_public_key(key))
        # lib/attestx.ml and harness/diff_quote.py both strip a 0x prefix here.
        self.assertEqual(oracle.parse_public_key("0x" + key), oracle.parse_public_key(key))
        self.assertEqual(oracle.parse_public_key("0x" + key[2:]), oracle.parse_public_key(key))

    def test_public_key_rejects_invalid_encoding_and_points(self):
        key = oracle.public_key(7)
        invalid = ["", "0x", " " + key, key + "\n", "02" + key[2:66],
                   "05" + key[2:], key[:-1], "00" * 64, "ff" * 64, "gg" * 64,
                   (oracle.P.to_bytes(32, "big") + bytes(32)).hex(), None, 7]
        for value in invalid:
            with self.subTest(value=repr(value)[:24]), self.assertRaises(ValueError):
                oracle.parse_public_key(value)

    def test_private_scalars_and_nonce_bounds(self):
        for scalar in (0, -1, oracle.N, oracle.N + 1, True, "3"):
            with self.subTest(scalar=scalar), self.assertRaises(ValueError):
                oracle.public_key(scalar)
        for nonce in (b"", bytes(11), bytes(13), "0" * 12):
            with self.subTest(length=len(nonce)), self.assertRaises(ValueError):
                oracle.seal_frame(3, oracle.public_key(7), nonce, b"test")

    def test_frame_93_byte_floor_and_empty_authenticated_plaintext(self):
        frame = oracle.seal_frame(13, oracle.public_key(3), bytes(12), b"")
        self.assertEqual(len(bytes.fromhex(frame)), 93)
        self.assertEqual(oracle.decrypt_frame(3, frame), b"")
        for length in (0, 64, 65, 76, 77, 91, 92):
            with self.subTest(length=length), self.assertRaises(ValueError):
                oracle.decrypt_frame(3, frame[:length * 2])

    def test_frame_mutated_key_nonce_ciphertext_and_tag(self):
        original = bytes.fromhex(self.frame)
        for label, at in (("nonce", 65), ("ciphertext", 77), ("tag", len(original) - 1)):
            changed = bytearray(original)
            changed[at] ^= 1
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "authentication"):
                oracle.decrypt_frame(3, changed.hex())
        changed = oracle.public_key(7) + self.frame[130:]
        with self.assertRaisesRegex(ValueError, "authentication"):
            oracle.decrypt_frame(3, changed)
        for key in ("00" * 65, "04" + "ff" * 64, "02" + self.frame[2:130]):
            with self.subTest(key=key[:4]), self.assertRaises(ValueError):
                oracle.decrypt_frame(3, key + self.frame[130:])

    def test_response_uses_embedded_peer_not_prompt_attestation_key(self):
        self.assertEqual(oracle.decrypt_frame(3, self.frame), b"Synthetic answer.")
        self.assertEqual(self.frame[:130], oracle.public_key(13))
        for substituted in (7, 11):
            with self.subTest(substituted=substituted), self.assertRaisesRegex(ValueError, "authentication"):
                oracle.decrypt_frame(3, oracle.public_key(substituted) + self.frame[130:])
        with self.assertRaisesRegex(ValueError, "authentication"):
            oracle.decrypt_frame(4, self.frame)
        prompt = oracle.strict_json(self.request)["messages"][0]["content"]
        self.assertEqual(oracle.decrypt_frame(7, prompt), b"SYNTHETIC prompt")

    def test_stream_both_delta_fields_and_role_terminal_events(self):
        request_id, frames = oracle.parse_stream(self.response)
        self.assertEqual(request_id, "SYNTHETIC-request-1")
        self.assertEqual([oracle.decrypt_frame(3, f) for f in frames],
                         [b"Synthetic answer.", b"Synthetic reasoning."])
        chunks = copy.deepcopy(self.chunks[:2])
        role = copy.deepcopy(chunks[0])
        role["choices"][0]["delta"] = {"role": "assistant", "content": ""}
        terminal = copy.deepcopy(role)
        terminal["choices"][0]["delta"] = {}
        terminal["choices"][0]["finish_reason"] = "stop"
        self.assertEqual(oracle.parse_stream(self.stream([role] + chunks + [terminal]))[1], frames)

    def test_stream_requires_done_and_rejects_trailing_or_partial_data(self):
        malformed = [self.response[:-14], self.response[:-1], self.response + b" ",
                     self.response + b"\n\n", self.response + b"data: [DONE]\n\n",
                     self.response + self.response, b"data: [DONE]\n\n", b""]
        for body in malformed:
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                oracle.parse_stream(body)

    def test_stream_rejects_plaintext_and_wrong_delta_types(self):
        for field in ("content", "reasoning_content"):
            for value in ("secret plaintext", None, 0, [], {}, "00" * 93):
                with self.subTest(field=field, value=value):
                    self.rejected_delta({field: value})
        for delta in ({"tool_calls": []}, {"role": "user"}, {"metadata": "private"}, [], None):
            self.rejected_delta(delta)

    def test_stream_rejects_unstable_or_missing_identity(self):
        for field in ("id", "model"):
            for value in ("different", "", None, "a b", "x" * 201):
                chunks = copy.deepcopy(self.chunks)
                chunks[1][field] = value
                with self.subTest(field=field, value=str(value)[:12]), self.assertRaises(ValueError):
                    oracle.parse_stream(self.stream(chunks))
            chunks = copy.deepcopy(self.chunks)
            del chunks[0][field]
            with self.assertRaises(ValueError):
                oracle.parse_stream(self.stream(chunks))

    def test_stream_rejects_malformed_shapes_and_extra_metadata(self):
        for choices in ([], [{"index": 0, "delta": {}}] * 2, None, {},
                        [{"index": True, "delta": {}}], [{"index": 1, "delta": {}}],
                        [{"index": 0, "delta": {}, "finish_reason": "unknown"}],
                        [{"index": 0, "delta": {}, "logprobs": "private"}]):
            chunks = copy.deepcopy(self.chunks)
            chunks[0]["choices"] = choices
            with self.subTest(choices=choices), self.assertRaises(ValueError):
                oracle.parse_stream(self.stream(chunks))
        for field, value in (("system_fingerprint", "private message"), ("metadata", "private"),
                             ("created", True), ("object", "private"),
                             ("usage", {"prompt_tokens": "private"}),
                             ("usage", {"unknown": 1})):
            chunks = copy.deepcopy(self.chunks)
            chunks[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                oracle.parse_stream(self.stream(chunks))
        for prefix in (b": comment\n\n", b"event: message\n", b"id: private\n", b"retry: 1000\n"):
            with self.assertRaises(ValueError):
                oracle.parse_stream(prefix + self.response)

    def test_stream_requires_finish_then_only_usage_and_done(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            oracle.parse_stream(self.stream(self.chunks[:2]))
        with self.assertRaisesRegex(ValueError, "after finish"):
            oracle.parse_stream(self.stream(self.chunks + [self.chunks[0]]))
        usage = {"id": "SYNTHETIC-request-1", "model": "SYNTHETIC-model", "choices": [],
                 "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
                 "system_fingerprint": "fp_synthetic_1"}
        self.assertEqual(oracle.parse_stream(self.stream(self.chunks + [usage])),
                         oracle.parse_stream(self.response))
        with self.assertRaises(ValueError):
            oracle.parse_stream(self.stream([usage] + self.chunks))
        empty = copy.deepcopy(self.chunks)
        empty[0]["choices"][0]["delta"] = {"content": ""}
        empty[1]["choices"][0]["delta"] = {"reasoning_content": ""}
        with self.assertRaisesRegex(ValueError, "incomplete"):
            oracle.parse_stream(self.stream(empty))

    def test_raw_whitespace_and_sse_framing_changes_invalidate_receipt(self):
        self.verify()
        for response in (self.response.replace(b"\n", b"\r\n"),
                         self.response.replace(b"data: ", b"data:"),
                         self.response.replace(b'"id":', b'"id" : ')):
            self.assertEqual(oracle.parse_stream(response), oracle.parse_stream(self.response))
            with self.assertRaisesRegex(ValueError, "transcript binding"):
                self.verify(response=response)
        for request in (b" " + self.request, self.request + b"\n",
                        json.dumps(oracle.strict_json(self.request), indent=2).encode()):
            with self.assertRaisesRegex(ValueError, "transcript binding"):
                self.verify(request=request)

    def test_receipt_wrong_request_response_and_signed_text(self):
        for request, response in ((b"other", self.response), (self.request, b"other"),
                                  (self.response, self.request), (self.request, self.response[:-14])):
            with self.assertRaisesRegex(ValueError, "transcript binding"):
                self.verify(request=request, response=response)
        receipt = dict(self.fixture["receipt"], text="0" * 64 + ":" + "0" * 64)
        with self.assertRaisesRegex(ValueError, "transcript binding"):
            self.verify(receipt=receipt)
        # Repainting the expected text still requires a new cryptographic signature.
        receipt["text"] = oracle.signed_text(b"other", self.response)
        with self.assertRaisesRegex(ValueError, "signature verification"):
            self.verify(receipt=receipt, request=b"other")

    def test_receipt_signer_key_address_and_optional_key_mismatches(self):
        other = oracle.public_key(17)
        address = "0x" + oracle._address(oracle.parse_public_key(other)).hex()
        for kwargs in ({"key": other}, {"address": address},
                       {"key": other, "address": address,
                        "receipt": dict(self.fixture["receipt"], signing_address=address)},
                       {"receipt": dict(self.fixture["receipt"], signing_address=address)},
                       {"receipt": dict(self.fixture["receipt"], signing_key=other)}):
            with self.subTest(fields=list(kwargs)), self.assertRaises(ValueError):
                self.verify(**kwargs)

    def test_receipt_required_field_types_algorithms_and_encoding(self):
        for field in ("text", "signature", "signing_algo", "signing_address"):
            receipt = dict(self.fixture["receipt"])
            del receipt[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.verify(receipt=receipt)
            receipt[field] = 3
            with self.subTest(non_string=field), self.assertRaises(ValueError):
                self.verify(receipt=receipt)
        for algorithm in ("ECDSA", "secp256k1", "ed25519", "", "rsa"):
            with self.subTest(algorithm=algorithm), self.assertRaises(ValueError):
                self.verify(receipt=dict(self.fixture["receipt"], signing_algo=algorithm))
        for signature in ("", "00" * 64, "00" * 66,
                          self.fixture["receipt"]["signature"] + "\n", "gg" * 65):
            with self.subTest(length=len(signature)), self.assertRaises(ValueError):
                self.verify(receipt=dict(self.fixture["receipt"], signature=signature))

    def test_recovery_id_and_signature_scalars_are_verified(self):
        original = bytes.fromhex(self.fixture["receipt"]["signature"][2:])
        for recovery in (2, 3, 26, 29, 35, 255, original[-1] ^ 1):
            # Toggle valid 27/28 explicitly below; xor may leave that range.
            receipt = dict(self.fixture["receipt"], signature=(original[:-1] + bytes([recovery])).hex())
            with self.subTest(recovery=recovery), self.assertRaises(ValueError):
                self.verify(receipt=receipt)
        flipped = 28 if original[-1] == 27 else 27
        with self.assertRaisesRegex(ValueError, "signature verification"):
            self.verify(receipt=dict(self.fixture["receipt"],
                                     signature=(original[:-1] + bytes([flipped])).hex()))
        self.verify(receipt=dict(self.fixture["receipt"],
                                 signature=(original[:-1] + bytes([original[-1] - 27])).hex()))
        for part in (0, 1):
            for value in (0, oracle.N):
                changed = bytearray(original)
                changed[part * 32:(part + 1) * 32] = value.to_bytes(32, "big")
                with self.subTest(part=part, value=value), self.assertRaises(ValueError):
                    self.verify(receipt=dict(self.fixture["receipt"], signature=changed.hex()))
        # A high-s malleation of the committed signature must not verify.
        low = int.from_bytes(original[32:64], "big")
        malleated = original[:32] + (oracle.N - low).to_bytes(32, "big") + bytes([55 - original[-1]])
        self.assertLessEqual(low, oracle.N // 2)
        self.assertGreater(int.from_bytes(malleated[32:64], "big"), oracle.N // 2)
        with self.assertRaisesRegex(ValueError, "signature encoding"):
            self.verify(receipt=dict(self.fixture["receipt"], signature=malleated.hex()))

    def test_ecdsa_uses_eip191_not_bare_sha256(self):
        text = oracle.signed_text(self.request, self.response)
        z = int.from_bytes(oracle.hashlib.sha256(text.encode()).digest(), "big")
        k = 19
        x, y = oracle.multiply(k)
        r = x % oracle.N
        s = pow(k, -1, oracle.N) * (z + r * 11) % oracle.N
        recovery = y % 2
        # Normalize to low s so the rejection is the digest, not the encoding.
        if s > oracle.N // 2:
            s, recovery = oracle.N - s, recovery ^ 1
        signature = (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recovery])).hex()
        with self.assertRaisesRegex(ValueError, "signature verification"):
            self.verify(receipt=dict(self.fixture["receipt"], signature=signature))

    def test_eip191_unicode_length_counts_encoded_bytes(self):
        self.assertEqual(oracle._eip191("caf\u00e9"),
                         oracle._keccak(b"\x19Ethereum Signed Message:\n5caf\xc3\xa9"))
        self.assertNotEqual(oracle._eip191("caf\u00e9"),
                            oracle._keccak(b"\x19Ethereum Signed Message:\n4caf\xc3\xa9"))

    def test_ed25519_positive_and_adversarial_receipts(self):
        ed = self.fixture["ed25519"]
        def verify(receipt=None, key=None, address=None, request=None):
            oracle.verify_receipt(ed["receipt"] if receipt is None else receipt,
                                  self.request if request is None else request, self.response,
                                  ed["signing_key"] if key is None else key,
                                  ed["signing_address"] if address is None else address)
        verify()
        original = bytes.fromhex(ed["receipt"]["signature"])
        changed = bytes([original[0] ^ 1]) + original[1:]
        for signature in (changed.hex(), original[:-1].hex(), (original + b"\0").hex(),
                          "0x" + original.hex(), original.hex() + " ", "00" * 64):
            with self.subTest(length=len(signature)), self.assertRaises(ValueError):
                verify(receipt=dict(ed["receipt"], signature=signature))
        for key in ("00" * 32, "0x" + ed["signing_key"], ed["signing_key"][:-2]):
            with self.subTest(key=key[:8]), self.assertRaises(ValueError):
                verify(key=key)
        with self.assertRaises(ValueError):
            verify(address="00" * 32)
        with self.assertRaises(ValueError):
            verify(receipt=dict(ed["receipt"], signing_address="00" * 32))
        with self.assertRaises(ValueError):
            verify(receipt=dict(ed["receipt"], signing_key="00" * 32))
        with self.assertRaises(ValueError):
            verify(receipt=dict(ed["receipt"], signing_algo="ecdsa"))
        with self.assertRaisesRegex(ValueError, "transcript binding"):
            verify(request=b"other")
        with self.assertRaisesRegex(ValueError, "signature verification"):
            verify(receipt=dict(ed["receipt"], text=oracle.signed_text(b"other", self.response)),
                   request=b"other")

    def test_ed25519_published_rfc8032_empty_message_vector(self):
        # RFC 8032 section 7.1, TEST 1. This is independent of fixture signing.
        # https://www.rfc-editor.org/rfc/rfc8032#section-7.1
        key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        oracle._verify_ed25519(key, b"", signature)
        with self.assertRaises(ValueError):
            oracle._verify_ed25519(key, b"changed", signature)

    def test_ed25519_rejects_identity_forgery_and_other_torsion_signers(self):
        # Each expected reason names this oracle's own guard, never PyCryptodome.
        forged = bytes.fromhex("58" + "66" * 31) + (1).to_bytes(32, "little")
        keys = [((1).to_bytes(32, "little"), "subgroup or scalar"),
                (bytes(32), "subgroup or scalar"),
                ((oracle.ED_P - 1).to_bytes(32, "little"), "subgroup or scalar"),
                ((oracle.ED_P + 1).to_bytes(32, "little"), "noncanonical point"),
                (((1 << 255) + 1).to_bytes(32, "little"), "invalid point")]
        for key, reason in keys:
            receipt = {"text": oracle.signed_text(self.request, self.response),
                       "signature": forged.hex(), "signing_algo": "ed25519",
                       "signing_address": key.hex()}
            with self.subTest(key=key.hex()[:8]), self.assertRaisesRegex(ValueError, reason):
                oracle.verify_receipt(receipt, self.request, self.response, key.hex(), key.hex())
        ed = self.fixture["ed25519"]
        original = bytes.fromhex(ed["receipt"]["signature"])
        text = oracle.signed_text(self.request, self.response).encode()
        for commitment in (bytes(32), (oracle.ED_P - 1).to_bytes(32, "little")):
            with self.subTest(commitment=commitment.hex()[:8]), \
                    self.assertRaisesRegex(ValueError, "subgroup or scalar"):
                oracle._verify_ed25519(bytes.fromhex(ed["signing_key"]), text,
                                       commitment + original[32:])
        with self.assertRaisesRegex(ValueError, "subgroup or scalar"):
            oracle._verify_ed25519(bytes.fromhex(ed["signing_key"]), text,
                                   original[:32] + oracle.ED_L.to_bytes(32, "little"))
        # The valid signature malleated by S + L over the same signed text.
        scalar = int.from_bytes(original[32:], "little") + oracle.ED_L
        oracle._verify_ed25519(bytes.fromhex(ed["signing_key"]), text, original)
        with self.assertRaisesRegex(ValueError, "subgroup or scalar"):
            oracle._verify_ed25519(bytes.fromhex(ed["signing_key"]), text,
                                   original[:32] + scalar.to_bytes(32, "little"))

    def test_json_duplicate_malformed_nonfinite_and_trailing(self):
        for body in (b'{"id":1,"id":2}', b'{"receipt":{"text":1,"text":2}}',
                     b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}',
                     b'{"value":-1e999}', b'{"value":[1,{"deep":1e999}]}',
                     b'{}{}', b'\xff', b'{',
                     b'[' * 2000 + b']' * 2000):
            with self.subTest(body=body[:32]), self.assertRaises(ValueError):
                oracle.strict_json(body)
        duplicate_stream = self.response.replace(b'"id":', b'"id":"duplicate","id":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            oracle.parse_stream(duplicate_stream)

    def test_finite_byte_limits(self):
        with self.assertRaisesRegex(ValueError, "byte limit"):
            oracle.signed_text(b"x" * (oracle.MAX_REQUEST + 1), self.response)
        with self.assertRaisesRegex(ValueError, "byte limit"):
            oracle.parse_stream(b"x" * (oracle.MAX_RESPONSE + 1))
        with self.assertRaisesRegex(ValueError, "byte limit"):
            oracle.signed_text(self.request, b"x" * (oracle.MAX_RESPONSE + 1))

    def diagnostic_capture(self):
        return {"schema": "venice-e2ee-diagnostic-v1", "request_id": "SYNTHETIC-request-1",
                "model": "SYNTHETIC-model", "challenge_hex": "ab" * 32,
                "request_body_hex": self.request.hex(), "response_body_hex": self.response.hex(),
                "receipt": self.fixture["receipt"], "signing_key": self.fixture["signing_key"],
                "signing_address": self.fixture["signing_address"],
                "checks": {"reportdata": "structural-only", "gcm_authenticated_frames": 2,
                           "plaintext_bytes": 37},
                "digests": {"request_sha256": oracle.hashlib.sha256(self.request).hexdigest(),
                            "response_sha256": oracle.hashlib.sha256(self.response).hexdigest()}}

    def test_capture_summary_fields_are_recomputed_not_trusted(self):
        base = self.diagnostic_capture()
        mutations = [
            ("capture digests", dict(base, digests=dict(base["digests"], request_sha256="00" * 32))),
            ("capture digests", dict(base, digests=dict(base["digests"], response_sha256="00" * 32))),
            ("capture digests", dict(base, digests={})),
            ("capture digests", dict(base, digests=dict(base["digests"], extra="00" * 32))),
            ("capture checks", dict(base, checks=dict(base["checks"], gcm_authenticated_frames=999))),
            ("capture checks", dict(base, checks=dict(base["checks"], gcm_authenticated_frames="2"))),
            ("capture checks", dict(base, checks=dict(base["checks"], reportdata="full TDX quote"))),
            ("capture checks", dict(base, checks=dict(base["checks"], plaintext_bytes=-1))),
            ("capture checks", dict(base, checks=dict(base["checks"], plaintext_bytes=38))),
            ("capture checks", dict(base, checks="structural-only")),
            ("malformed hex", dict(base, challenge_hex="zz" * 32)),
            ("hex length", dict(base, challenge_hex="ab" * 31)),
            ("capture fields", {k: v for k, v in base.items() if k != "digests"}),
            ("capture fields", {k: v for k, v in base.items() if k != "checks"}),
            ("capture fields", {k: v for k, v in base.items() if k != "challenge_hex"}),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "capture.json"
            path.write_text(json.dumps(base))
            self.assertIn("cannot be replayed", oracle.check_fixture(path))
            for index, (reason, capture) in enumerate(mutations):
                path.write_text(json.dumps(capture))
                with self.subTest(case=index, reason=reason), \
                        self.assertRaisesRegex(ValueError, reason):
                    oracle.check_fixture(path)

    def test_capture_replay_recomputes_evidence_and_rejects_saved_claims(self):
        capture = self.diagnostic_capture()
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "capture.json"
            path.write_text(json.dumps(capture))
            message = oracle.check_fixture(path)
            self.assertIn("cannot be replayed", message)
            self.assertIn("attestation is not verified", message)
            capture["request_body_hex"] = b"changed".hex()
            path.write_text(json.dumps(capture))
            with self.assertRaisesRegex(ValueError, "transcript binding"):
                oracle.check_fixture(path)

    def test_capture_rejects_signed_invalid_request_and_model_tampering(self):
        base = {"schema": "venice-e2ee-diagnostic-v1", "request_id": "SYNTHETIC-request-1",
                "model": "SYNTHETIC-model", "request_body_hex": self.request.hex(),
                "response_body_hex": self.response.hex(), "receipt": self.fixture["receipt"],
                "signing_key": self.fixture["signing_key"],
                "signing_address": self.fixture["signing_address"]}
        mutations = [b"not JSON", b'{"model":"SYNTHETIC-model","model":"SYNTHETIC-model"}']
        for field, value in (("model", "another-model"), ("stream", False),
                             ("messages", []), ("messages", [{"role": "user", "content": "plaintext"}]),
                             ("messages", [{"role": "assistant", "content": self.frame}])):
            request = oracle.strict_json(self.request)
            request[field] = value
            mutations.append(json.dumps(request).encode())
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "capture.json"
            for request in mutations:
                capture = dict(base, request_body_hex=request.hex(),
                               receipt=oracle._synthetic_ecdsa_receipt(
                                   oracle.signed_text(request, self.response)))
                path.write_text(json.dumps(capture))
                with self.subTest(request=request[:30]), self.assertRaises(ValueError):
                    oracle.check_fixture(path)
            path.write_text(json.dumps(dict(base, model="another-model")))
            with self.assertRaisesRegex(ValueError, "request model"):
                oracle.check_fixture(path)


if __name__ == "__main__":
    unittest.main()
