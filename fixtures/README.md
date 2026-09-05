# TDX attestation fixtures (M22)

This directory holds the byte-identical fixture copies the M22 sourced
probe landed, and the collateral that pairs with them.  Nothing here was
re-encoded, reformatted or stripped.  `harness/diff_quote.py` reads
every file in this directory on every gate run and pins its sha256 and
its byte count, so a corrupted or a truncated copy makes `./gates.sh`
RED at M22 and not at a later milestone.

## Attribution

Copied from Phala-Network/dcap-qvl, commit
7cb5caceb9dcce345a7d1413110c69df3a907479, paths sample/tdx_quote,
sample/tdx_quote_outdated, sample/tdx_quote_collateral.json and
src/TrustedRootCA.der, MIT licence, Copyright (c) 2026 Phala Network.

The MIT licence requires the copyright notice AND the permission notice
in every copy of a substantial portion of the software, so the full
licence text sits beside these files as `LICENSE.dcap-qvl`, itself a
byte-identical copy of `dcap-qvl/LICENSE`.  The permission notice is the
sentence of that file that begins "The above copyright notice and this
permission notice shall be included in all copies or substantial
portions of the Software."

No CODE was copied from dcap-qvl, from go-tdx-guest, from dstack, from
private-ml-sdk or from any other project.  Those projects are cited by
file and line as evidence.  The GPL project venice-e2ee contributes no
byte and no line to this repository at all.

## Provenance

| file | source repo | commit | upstream path | sha256 | bytes | licence |
| ---- | ----------- | ------ | ------------- | ------ | ----- | ------- |
| `tdx_quote_v4.bin` | Phala-Network/dcap-qvl | `7cb5caceb9dcce345a7d1413110c69df3a907479` | `sample/tdx_quote` | `c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db` | 5006 | MIT |
| `tdx_quote_v5.bin` | Phala-Network/dcap-qvl | `7cb5caceb9dcce345a7d1413110c69df3a907479` | `sample/tdx_quote_outdated` | `4c453ea417a7863ed67c215fe4735d91e26f359c760e5984a277866d8d5758e9` | 5006 | MIT |
| `collateral/tdx_quote_collateral.json` | Phala-Network/dcap-qvl | `7cb5caceb9dcce345a7d1413110c69df3a907479` | `sample/tdx_quote_collateral.json` | `b0a5f5fd620a8881b1eda45261fdf30dd930b49aff93231556645c81fcb4c0bc` | 16072 | MIT |
| `collateral/TrustedRootCA.der` | Phala-Network/dcap-qvl | `7cb5caceb9dcce345a7d1413110c69df3a907479` | `src/TrustedRootCA.der` | `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3` | 659 | MIT |
| `LICENSE.dcap-qvl` | Phala-Network/dcap-qvl | `7cb5caceb9dcce345a7d1413110c69df3a907479` | `LICENSE` | `f77e71ba8380d395e78485302cc4beccab400b9a01648e2acaf26085fe65bd7f` | 1070 | MIT |

Real versus test, one clause each.  `tdx_quote_v4.bin` is a REAL
Intel-signed production TDX quote, and the TRUST section below names the
five legs that prove it.  `tdx_quote_v5.bin` is a real quote too, of the
older version-5 shape, and it is the REJECT fixture: M23 must refuse it
by VERSION.  `collateral/tdx_quote_collateral.json` is the Intel PCS
collateral Phala captured for the v4 quote, and its `tcb_info` member
decodes to id TDX, version 3, fmspc `B0C06F000000` and
tcbEvaluationDataNumber 17, while its `qe_identity` member decodes to id
TD_QE with isvprodid 2.  `collateral/TrustedRootCA.der` is the Intel SGX
Root CA certificate in DER form, the trust anchor the chain of the v4
quote verifies to.

The collateral file is ONE JSON object with nine string members, not a
directory of files: `pck_crl`, `pck_crl_issuer_chain`, `qe_identity`,
`qe_identity_issuer_chain`, `qe_identity_signature`, `root_ca_crl`,
`tcb_info`, `tcb_info_issuer_chain` and `tcb_info_signature`.  The
`tcb_info` and `qe_identity` members carry JSON documents as STRINGS, so
M27 parses each one a second time.

The durable sources are the upstream repositories at the commits this
table names.  The working notes of the probe are
`/Users/oobi/Documents/venice-m22-research-a.md` and
`/Users/oobi/Documents/venice-m22-research-b.md`, which stay outside the
repository and mean nothing to a reader who does not have this machine;
every fact they carry is also carried by an upstream commit above.

## Decoded fields of `tdx_quote_v4.bin`

Every offset is ABSOLUTE from byte 0 and every value below was decoded
from the fixture bytes by `harness/diff_quote.py`, which pins each row
on every gate run.  The header is 48 bytes at 0, the TD report 1.0 body
is 584 bytes at 48, and `report_data` ends at 632.

| field | offset | size | value |
| ----- | ------ | ---- | ----- |
| version | 0 | 2 | `0400` (4) |
| att_key_type | 2 | 2 | `0200` (2, ECDSA-256 with P-256) |
| tee_type | 4 | 4 | `81000000` (0x00000081) |
| header_u16_at_8 | 8 | 2 | `0000` |
| header_u16_at_10 | 10 | 2 | `0000` |
| qe_vendor_id | 12 | 16 | `939a7233f79c4ca9940a0db3957f0607` |
| user_data | 28 | 20 | `889b7d6ff9df2405b240a830e73faf3d00000000` |
| tee_tcb_svn | 48 | 16 | `06010300000000000000000000000000` |
| mr_seam | 64 | 48 | `5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1` |
| mrsigner_seam | 112 | 48 | 48 zero bytes |
| seam_attributes | 160 | 8 | `0000000000000000` |
| td_attributes | 168 | 8 | `0000001000000000` |
| xfam | 176 | 8 | `e702060000000000` |
| mr_td | 184 | 48 | `91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7` |
| mr_config_id | 232 | 48 | 48 zero bytes |
| mr_owner | 280 | 48 | 48 zero bytes |
| mr_owner_config | 328 | 48 | 48 zero bytes |
| rt_mr0 | 376 | 48 | `44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0` |
| rt_mr1 | 424 | 48 | `0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378` |
| rt_mr2 | 472 | 48 | `d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132` |
| rt_mr3 | 520 | 48 | 48 zero bytes |
| report_data | 568 | 64 | `9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20` |
| signature_data_len | 632 | 4 | 4300 |

The two u16 fields at offsets 8 and 10 are recorded RAW and interpreted
by nobody.  The two code sources swap the labels: dcap-qvl
`src/quote.rs:92-93` calls offset 8 `qe_svn` and offset 10 `pce_svn`,
while go-tdx-guest `abi/abi.go:100-103` calls offset 8 `PceSvn` and
offset 10 `QeSvn`.  The BYTE ranges agree and no Intel header settles
the names, so this repository calls them `header_u16_at_8` and
`header_u16_at_10` and reads no meaning into either.  Both read 0 here.
M27 must take its PCE SVN from the PCK certificate extension and must
not read these bytes until a source pins their names.

The DEBUG bit is bit 0 of byte 0 of td_attributes, mask 0x01, so
`0000001000000000` has DEBUG CLEAR and bit 28, SEPT_VE_DISABLE, set.

Length and padding.  636 + 4300 = 4936, the file is 5006 bytes, the
surplus is 70 bytes and every one of them is zero.  A strict decoder
that demands 636 + signature_data_len == length breaks on this real
quote, which is exactly why rule 4 below is an inequality.

Signature section and certification chain, absolute offsets again.  The
ECDSA signature is 64 bytes at 636.  The attestation public key is 64
bytes at 700, raw X || Y with no 0x04 prefix.  cert_key_type is 6 at
764 with size 4166 at 766, and its body opens at 770.  For type 6 that
body is the 384-byte QE report at 770, whose `report_data` is its LAST
64 bytes at absolute 1090, then the QE report signature 64 bytes at
1154, then the auth-data size 32 at 1218 and the 32 auth bytes at 1220,
then the inner certification type 5 at 1252, its size 3678 at 1254 and
the PEM chain at 1258.  The PEM opens with `-----BEGIN CERTIFICATE-----`
and holds THREE certificates.  The ISV-signed region is `quote[0..632]`.

The QE binding recomputes on every gate run:
sha256(attestation_key || qe_auth_data) is
`c936492a774946af9b588f6b3bd8beddc5957d1761ded2c0bb61d7b64de5b324`, and
that is exactly `qe_report_data[0..32]`.

## Decoded fields of `tdx_quote_v5.bin`

A version-5 quote inserts a 6-byte body descriptor between the header
and the report, so every TD 1.0 field shifts by 6.  body_type is 3 at
48 and body size is 648 at 50, which is TD 1.0 plus tee_tcb_svn2 16 and
mr_servicetd 48.  td_attributes sits at 174 reading `0000001000000000`
with DEBUG clear, xfam at 182 reading `e718060000000000`, report_data at
574, tee_tcb_svn2 at 638 reading `0d010300000000000000000000000000`,
mr_servicetd at 654 as 48 zero bytes and signature_data_len 4300 at 702.
706 + 4300 = 5006, which is the file length exactly, so this fixture
carries NO trailing padding and the v4 fixture alone exercises rule 4.

## Which milestone consumes which file

| file | consumer |
| ---- | -------- |
| `tdx_quote_v4.bin` | M22 gate pins, M23 quotex header and body decode, M24 policy DEBUG reject, M25 sigx signature section and QE binding, M26 derx PCK chain, M28 attestx end to end |
| `tdx_quote_v5.bin` | M22 gate pins, M23 quotex REJECT case, the version-5 typed refusal |
| `collateral/tdx_quote_collateral.json` | M22 gate pins, M27 tcbx TCB Info and QE Identity |
| `collateral/TrustedRootCA.der` | M22 gate pins, M26 derx pinned Intel SGX Root CA |
| `LICENSE.dcap-qvl` | the MIT permission notice these copies require |

The ISV P-256 signature over `quote[0..632]` is NOT verified by
`harness/diff_quote.py`, because the gate interpreter carries no P-256
library.  M25 owns that check in OCaml.  The chain to the pinned Intel
root is not verified there either;  M26 owns it.

## TRUST

This fixture proves the LAYOUT and the REALITY of an Intel-signed
production TDX quote.  It does NOT prove Venice's binding.  Its
`report_data` is Phala's and not a Venice REPORTDATA, so nothing in this
directory shows that Venice builds `report_data` the way W1 of the M22
brief says it does.  The single most likely misreading of this milestone
is that the repository now holds a Venice attestation.  It does not.

Five legs carry the REAL claim and the M22 drafting stage re-ran all
five.  (1) The ISV ECDSA-P256 signature over `quote[0..632]` verifies
under the embedded attestation key;  `openssl dgst -sha256 -verify`
printed `Verified OK`.  (2) The QE report signature at 1154, over the
384-byte QE report at 770, verifies under the public key of the PCK
leaf, which is the only leg that binds the attestation key to Intel;
`openssl dgst -sha256 -verify` printed `Verified OK`.  (3) The QE
binding holds, because sha256(attestation_key || auth_data) equals
`qe_report_data[0..32]`.  (4) The embedded chain runs PCK leaf to PCK
Platform CA to Intel SGX Root CA, and `openssl verify` against
`collateral/TrustedRootCA.der` printed `OK` with exit 0.  (5) The leaf
carries the Intel SGX extension OID 1.2.840.113741.1.13.1 and is valid
from 2025-02-06 to 2032-02-06.  Leg 2 is the one that cannot be forged
around: without it an attacker key, a chosen `report_data`, a
recomputed `qe_report_data[0..32]` and a copied chain would pass the
other four.

The one thing this fixture cannot show is the W1 formula on real bytes,
that is `report_data = address20 || 0x00 x 12 || nonce32` for a quote
the Venice endpoint actually returned.  The section 2 threat row of
DESIGN.md carries the same byte positions, so a reader who starts at the
threat model reaches this same fact.

## LIVE DEBT

M22 is a SOURCED probe, not a live one.  No `VENICE_API_KEY` was in the
environment when it landed and no outbound request was permitted, so no
Venice attestation body was captured, and the W1 formula stands on
producer source plus a synthetic control and not on a live quote.

One command closes that debt, `scripts/probe_attestation.sh`, which
mints a 32-byte nonce, captures one attestation body into this directory
and CHECKS it in the same run, so a capture cannot sit here unverified:

```
VENICE_API_KEY=... scripts/probe_attestation.sh <model-id>
```

The script refuses with exit 2 and one line when the key is unset, it
never puts the key in argv, in a log or in the captured file, it
captures the BODY only because the balance headers are the user's
private numbers, and it prints the command that deletes its own capture
when the pins it fed are recorded in FACTS.md.  The capture lands at
`fixtures/attestation_<model>_<utcdate>.json` and is not a committed
fixture.

## PARSER RULES

These are the eight rules M22 hands to M23.  No code implements them
yet.  The M23 row of DESIGN.md carries the same eight rules in the same
order, so the row and this section read identically, and a lens can
attack a rule now rather than after the decoder lands.

1. Version 4 only.
2. att_key_type 2 only.
3. tee_type 0x00000081 only.
4. `636 + signature_data_len <= length`, with the surplus recorded and
   never consumed.
5. cert_key_type 6 with inner type 5 only, and every other type a TYPED
   reject.
6. The PEM chain split on the certificate markers, which the fixture
   shows to be three certificates.
7. Version 5 rejected by VERSION with a typed reason, the W4 delta
   recorded for a later milestone.
8. Fixtures `tdx_quote_v4.bin` and `tdx_quote_v5.bin`, the accept case
   and the reject case of the same decoder.

Rule 4 is an inequality and not an equality because the v4 fixture
carries 70 zero bytes of trailing padding after its structure ends.
Rule 7 is the reason `tdx_quote_v5.bin` sits here at all: a decoder
that never sees a version it must refuse has no evidence that it
refuses one.
