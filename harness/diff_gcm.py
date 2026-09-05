#!/usr/bin/env python3
"""M21 differential oracle over test/test_aesx.ml and test/test_gcmx.ml
(DESIGN.md section 8).

It recomputes every constant the two suites pin and requires each one to
sit inside a CHECK ROW of its suite, never merely somewhere in the file.
The suite matcher is the M20 one: strip_ocaml_comments, check_rows, the
LABEL pattern, BODIES, pin and require are copied from
harness/diff_secp.py (lines 755, 781, 818, 822 and 835) with the name of
this harness in their messages, except that BODIES is a DICT of the two
suite bodies and pin takes the suite name as its first argument.

The arithmetic shares NO formula with the OCaml units. lib/aesx.ml
COMPUTES the S-box on every call as the GF(2^8) inverse a^254 through a
chain of eleven multiplications, and keeps the state in packed 32-bit
columns; this file builds a log and antilog TABLE over the generator 3,
takes the inverse as antilog[255 - log[a]] and keeps the state as a list
of 16 bytes. lib/gcmx.ml runs GHASH over a pair of Int64 halves with
masked selects; this file runs it over ONE python integer with the
0xe1 reduction. The two implementations agree only when both are right.

Provenance of the embedded Wycheproof subset. The file is
/Users/oobi/Documents/signatures/thirdparty/wycheproof/testvectors_v1/aes_gcm_test.json,
algorithm "AES-GCM", schema "aead_test_schema_v1.json", numberOfTests
316. It carries NO generatorVersion key. The checkout commit is
0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45
(git -C /Users/oobi/Documents/signatures/thirdparty/wycheproof
rev-parse HEAD, describe wycheproof-v0-vectors-40-g0fd0ec1), and
git -C /Users/oobi/Documents/signatures submodule status prints nothing,
so that directory's own HEAD is the provenance. The corpus is
Apache-2.0
(/Users/oobi/Documents/signatures/thirdparty/wycheproof/LICENSE lines 2
and 3), and the checkout carries no NOTICE file, so section 4(d) owes
nothing and this header is the whole attribution.

When that file sits on disk the oracle also CROSS-CHECKS every embedded
record against it by tcId, so a typo in a literal below is caught at its
source. When it is absent the embedded subset stands alone and the
oracle says so, because a pin must not depend on a checkout the gate
does not own. The LNSym AES-GCM spec test file is a second, INDEPENDENT
corroboration of the four SP 800-38D cases and is optional in the same
way.

Before any pin is read the file SELF-CHECKS in six parts, in this order:
the S-box and the two published AES-256 ciphertexts, the four SP
800-38D cases with their roundtrips, the LNSym corroboration, the
embedded Wycheproof subset (every valid vector reproduces its ct and
tag, every ModifiedTag vector does not, and every length reject carries
a key or an iv this surface refuses), the corpus cross-check and the
pycryptodome cross-check. A mismatch exits 1 on the spot, so a python
bug cannot certify an OCaml bug.

Everything here comes from the standard library. pycryptodome is
OPTIONAL and its whole leg sits inside one try.
"""

import hashlib
import json
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent
aes_suite_path = root / "test" / "test_aesx.ml"
gcm_suite_path = root / "test" / "test_gcmx.ml"

wycheproof_path = pathlib.Path(
    "/Users/oobi/Documents/signatures/thirdparty/wycheproof/testvectors_v1"
    "/aes_gcm_test.json"
)
lnsym_path = pathlib.Path(
    "/Users/oobi/Documents/LNSym/Tests/AES-GCM/AESGCMSpecTest.lean"
)

fail = 0

# ---------- AES-256, as tables and bytes ----------

LOG = [0] * 256
ALOG = [0] * 256


def _build_tables() -> None:
    """log and antilog of GF(2^8) over the generator 3."""
    x = 1
    for i in range(255):
        ALOG[i] = x
        LOG[x] = i
        x = x ^ ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0)


_build_tables()


def gf_inv(a: int) -> int:
    """The GF(2^8) inverse through the tables, with 0 mapped to 0."""
    return 0 if a == 0 else ALOG[(255 - LOG[a]) % 255]


def rotl8(b: int, n: int) -> int:
    return ((b << n) | (b >> (8 - n))) & 0xFF


def sbox(a: int) -> int:
    """The FIPS 197 S-box: the inverse, then the affine map."""
    b = gf_inv(a & 0xFF)
    return b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63


SBOX = [sbox(i) for i in range(256)]


def gf_mul(a: int, b: int) -> int:
    """The GF(2^8) product through the tables."""
    if a == 0 or b == 0:
        return 0
    return ALOG[(LOG[a] + LOG[b]) % 255]


def key_expansion(key: bytes) -> list:
    """The Nk = 8, Nr = 14 schedule as 60 four-byte words."""
    words = [list(key[4 * i : 4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(words[i - 1])
        if i % 8 == 0:
            t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            t[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        elif i % 8 == 4:
            t = [SBOX[x] for x in t]
        words.append([words[i - 8][j] ^ t[j] for j in range(4)])
    return words


def add_round_key(state: list, words: list, r: int) -> list:
    flat = [x for w in words[4 * r : 4 * r + 4] for x in w]
    return [state[i] ^ flat[i] for i in range(16)]


def shift_rows(state: list) -> list:
    """Row r of the column-major state rotates left by r."""
    return [state[(i % 4) + 4 * (((i // 4) + (i % 4)) % 4)] for i in range(16)]


def mix_columns(state: list) -> list:
    out = []
    for c in range(4):
        col = state[4 * c : 4 * c + 4]
        for r in range(4):
            out.append(
                gf_mul(col[r], 2)
                ^ gf_mul(col[(r + 1) % 4], 3)
                ^ col[(r + 2) % 4]
                ^ col[(r + 3) % 4]
            )
    return out


def aes_encrypt_block(words: list, block: bytes) -> bytes:
    state = add_round_key(list(block), words, 0)
    for r in range(1, 14):
        state = [SBOX[x] for x in state]
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, words, r)
    state = [SBOX[x] for x in state]
    state = shift_rows(state)
    return bytes(add_round_key(state, words, 14))


# ---------- AES-256-GCM, as one 128-bit integer ----------

R128 = 0xE1 << 120


def gf128_mul(x: int, y: int) -> int:
    """The GHASH product of SP 800-38D Algorithm 1, bit by bit."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R128 if v & 1 else v >> 1
    return z


def pad16(s: bytes) -> bytes:
    return s + b"\x00" * ((16 - len(s) % 16) % 16)


def ghash(h: int, aad: bytes, ct: bytes) -> int:
    """GHASH over the padded AAD, the padded ciphertext and the lengths."""
    data = (
        pad16(aad)
        + pad16(ct)
        + (8 * len(aad)).to_bytes(8, "big")
        + (8 * len(ct)).to_bytes(8, "big")
    )
    y = 0
    for i in range(0, len(data), 16):
        y = gf128_mul(y ^ int.from_bytes(data[i : i + 16], "big"), h)
    return y


def ctr_pass(words: list, iv: bytes, s: bytes) -> bytes:
    """The counter pass from the first DATA counter, which is 2."""
    out = bytearray()
    for i in range(0, len(s), 16):
        counter = 2 + i // 16
        block = aes_encrypt_block(words, iv + (counter & 0xFFFFFFFF).to_bytes(4, "big"))
        chunk = s[i : i + 16]
        out.extend(bytes(a ^ b for a, b in zip(chunk, block)))
    return bytes(out)


def gcm_seal(key: bytes, iv: bytes, aad: bytes, msg: bytes) -> tuple:
    """The AES-256-GCM ciphertext and tag under a 96-bit nonce."""
    words = key_expansion(key)
    h = int.from_bytes(aes_encrypt_block(words, b"\x00" * 16), "big")
    ct = ctr_pass(words, iv, msg)
    j0 = aes_encrypt_block(words, iv + b"\x00\x00\x00\x01")
    tag = (ghash(h, aad, ct) ^ int.from_bytes(j0, "big")).to_bytes(16, "big")
    return ct, tag


def gcm_unseal(key: bytes, iv: bytes, aad: bytes, ct: bytes, tag: bytes):
    """The plaintext of a MATCHING tag, and None otherwise."""
    words = key_expansion(key)
    h = int.from_bytes(aes_encrypt_block(words, b"\x00" * 16), "big")
    j0 = aes_encrypt_block(words, iv + b"\x00\x00\x00\x01")
    want = (ghash(h, aad, ct) ^ int.from_bytes(j0, "big")).to_bytes(16, "big")
    return ctr_pass(words, iv, ct) if want == tag else None


def hx(s: bytes) -> str:
    return s.hex()


def uh(s: str) -> bytes:
    return bytes.fromhex(s)


# ---------- the published vectors, as derivations ----------

ZERO_KEY = b"\x00" * 32
ZERO_IV = b"\x00" * 12

CASE15_KEY = uh("feffe9928665731c6d6a8f9467308308" * 2)
CASE15_IV = uh("cafebabefacedbaddecaf888")
CASE15_MSG = uh(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
CASE16_MSG = CASE15_MSG[:60]
CASE16_AAD = uh("feedfacedeadbeeffeedfacedeadbeefabaddad2")

# The GENERATED vector of D11, recomputed from its derivations and never
# quoted: a mistyped literal here cannot agree with the suite by luck.
GEN_KEY = hashlib.sha256(b"venice-ocaml m21 gcmx key").digest()
GEN_IV = hashlib.sha256(b"venice-ocaml m21 gcmx nonce").digest()[:12]
GEN_AAD = b"venice-ocaml m21 aad"
GEN_MSG = (b"venice-ocaml m21 gcmx plaintext " * 4)[:100]

FIPS197_KEY = uh("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
FIPS197_MSG = uh("00112233445566778899aabbccddeeff")
F15_KEY = uh("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
F15_MSG = uh("6bc1bee22e409f96e93d7e117393172a")

MAX_LEN = (2 ** 32 - 2) * 16


# ---------- the embedded Wycheproof subset, resolved by tcId ----------
#
# Each row is (tcId, key, iv, aad, msg, ct, tag, result). Twenty-one
# valid rows, ten ModifiedTag rows and five LENGTH rejects whose key or
# iv this surface refuses (D12).

WYCHEPROOF = [
    (91, "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20", "00112233445566778899aabb", "00000000ffffffff", "00010203040506070809", "e27abdd2d2a53d2f136b", "9a4a2579529301bcfb71c78d4060f52c", "valid"),
    (92, "29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123", "00112233445566778899aabb", "aabbccddeeff", "", "", "2a7d77fa526b8250cb296078926b5020", "valid"),
    (93, "80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0", "4da5bf8dfd5852c1ea12379d", "", "", "", "4771a7c404a472966cea8f73c8bfe17a", "valid"),
    (94, "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273", "99e23ec48985bccdeeab60f1", "", "2a", "06", "633c1e9703ef744ffffb40edf9d14355", "valid"),
    (96, "67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb", "68ab7fdbf61901dad461d23c", "", "51f8c1f731ea14acdb210a6d973e07", "43fc101bff4b32bfadd3daf57a590e", "ec04aacb7148a8b8be44cb7eaf4efa69", "valid"),
    (97, "59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a", "2fcb1b38a99e71b84740ad9b", "", "549b365af913f3b081131ccb6b825588", "f58c16690122d75356907fd96b570fca", "28752c20153092818faba2a334640d6e", "valid"),
    (98, "3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011", "45aaa3e5d16d2d42dc03445d", "", "3ff1514b1c503915918f0c0c31094a6e1f", "73a6b6f45f6ccc5131e07f2caa1f2e2f56", "2d7379ec1db5952d4e95d30c340b1b1d", "valid"),
    (104, "6efca98126918ab564d88c6bec02e8998b2be50e3f906ff9adfdd185f373e756", "4abd6cfc83bd06b11efaa2a7", "", "bbec79c086d41e602d090f7e40494d6bf3faa1dc6df0ab8a88ea5d35d426b248c2ad880351e223f6170d37cc9655e10459e59cbd6d1c092ed31d72ccc7af20", "97b4c73a4d8b5b21bc4b50dbb70dfa77b1a7bf0bbe7cf16ecf5bb60ba8070acc5740780435ed145a62a613dd9881b721168fbb3f5af385ee5d4f856cf93cba", "27ac8c4010d8e81b7051ceb06b30fe2d", "valid"),
    (105, "5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701", "d61040a313ed492823cc065b", "", "d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82", "c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112b038845720e02c061179a8836f02b93fa7008379a6bf", "f15612f6c40f2e0db6dc76fc4822fcfe", "valid"),
    (106, "81b6b27e5ed90ab99fe6756d4cb41e3f07269687f5afabdb426e29096b5e4466", "13e727486031cca21f733375", "", "9a95a23cfb1e35d89a7597570df0fb0efcbb7429f53bebcbbfa49fa247b251a8508ad497066855d08688576188e4ffb12d1d084dcabec3d57806daf215dcc97edd", "7ede7368bca3c93d9f1d7f7750d6e44b1cb92c30e3c9834b0b69efd2470911644ae6f6d75715e13aea8781f8da611a13ac6364c406c1a715b7e97acb22b6e6156e", "74e20a93802f43407c8989a37f013802", "valid"),
    (110, "01e75ae803d3045e6b28b7f67937eee2d8d98f77b4892d48ab1f15f57fa88bbe", "6902e8f0ef1e9ec60a3e46f0", "", "32dde3b9bc671fad1265b26cad3d8dd0f099134f6755f98613024e1bd10da9a62bad01a997f973101e855ee1c7e60e6b6aa1df9d80fa567d0ccca0f956680be76ed37c71fdedef560e2523e8c5fdb9516250017304f8ff416b9b8e5d17c1f062ded4616ea9d462ed6ca0dfddb9f5295b7a127c0825ffab56ea4983c01eec867f93e24a18be48ceb540986c530104fd466318eb812eb42fd04355615f92503e53799742cdc71830eaa44aeec914b6ff1cbb4f6f81ab595078331d645c8d083b469731174a706b1666e5e450cb62671067032a566f597b9866b71514a409e38fcabe844964581b3ab5152696b76e49ace66581d21f512e28e077c44948a65260", "6323ddbf9eb0463714d5857d1841a9f65529516c2f412956bc835f4f252d22a2ce743f21767fcb28859882b570ca053970b72e86f451ff0c77e87f3a03c0536b3859394fce324442ac197874f81a2ce649b99feb442e23123f7ab361d2ce6768a1badb30c509e79bee9277d378fadaa64e77e26f726df86110526530cd439429b017ae2bcec8cc24f994f5885a8a76fab6339c7054df76aa6f450193a635d21d22f71f1ae6856036e6caaeed8840bbfbc8236c25a31e775cba5f6e189fcbc3e96970ca5378fd5c29a712f5dc17641ad88ab566d8c78fff1bb57f9b2f7c9db838b4307c63e04a73d3ef8121f48932ec318dffaead58a83a7f79bc44a1587990", "0c92bb5291e981bf562293877f4ddb5f", "valid"),
    (111, "dc4dbf811f9509e33a45a8a0743e9391de333f69c56ee4f0fe90ce21c238ee59", "1859d3ba4710cdd300baa029", "", "df91c48591f4cae8c4d659d024dfd0a3535981487764bf19b012713e6ac6d578aa0b3a51d7ac97cd503fdc8682cabdb6a5256e9890458356f39b9749f6ab158112fbe4f91acd333477998b9f0d7cc0be2d40acfa5103adc1b0d0a5cc94733d703e0d8c26e09e9d079fa6a65cf35240a16280826ab7c0d8ac5882c89e58444233c2f60aaae0cbd1a7ed850065242a9378c340232fd86f1fd52a92c960a9a86f529f431acf3aa94133785803f4ac1a22378332daa22dea3d34d2fdb7c308fa44ab93b3fb02f428be22fad6c0b10c138af97b92a199296dd947c93fbc40674c34c5623d26d9c90dc6b3357018b9f9250fb4dd5c11518191a236745a2bd42f863766", "9c511d08f244cb6971a39b70639c4a53ae48254fcb3d2eea4796ecc996f1fe26a8e30932258a48fe4237e5bfb0e1320dc591256dc83cd56dbf5d9b377b7805b7fac0497b2f99e3310e9e2cc8009141a82f26f8a02299d64138bb1fe8a1243df3e9fb37b52bd3c2cc19f543b3f4928e5a73730a7a6e6d75919d117d3dfe10e863a9846b2ca260de5dddba7ceac37019e615b89a2ab94df8d1a790749998cb8531fef1ef5f8a28a8ad60e813f7e78412ca4d95b9604a24a16e4a3ca8ee33bfbb7809048014943e5fd7966a7db214e052d1cc546a6da72ec89d1c3398aefdcb881dfc3d800b7323abcd7583e9c8a31f03b6995d4aeac17c5a56d8af492a2b108fe3", "17090ce50e35244a59bafc80eba5dae5", "valid"),
    (112, "317ba331307f3a3d3d82ee1fdab70f62a155af14daf631307a61b187d413e533", "a6687cf508356b174625deaa", "", "32c1d09107c599d3cce4e782179c966c6ef963689d45351dbe0f6f881db273e54db76fc48fdc5d30f089da838301a5f924bba3c044e19b3ed5aa6be87118554004ca30e0324337d987839412bf8f8bbdd537205d4b0e2120e965373235d6cbd2fb3776ba0a384ec1d9b7c631a0379ff997c3f974a6f7bbf4fd23016211f5fc10acadb5e400d2ff0fdfd193f5c6fc6d4f7271dfd1349ed80fbedaebb155b9b02fb3074495d55f9a2455f59bf6f113191a029c6b0ba75d97cdc0c84f131836337f29f9d96ca448eec0cc46d1ca8b3735661979d83302fec08fffcf5e58f12b1e7050657b1b97c64a4e07e317f554f8310b6ccb49f36d48c57816d24952aada711d4f", "d7eebc9587aa21136fa38b41cf0e2db03a7ea2ba9eaddf83d33f781093617bf50f49b2bfe2f7173b113912e2e1775f40edfed8b3b0099b9e1c220dd103be6166210b01029feb24ed9e20614eddc3cebe41b0079a9a8c117b596c90288effd3796fbd0c7e8eab00609a64be3ad9597cdbf3a818c260cd938bdf232e4059ae35a2571a838887fc196912179486e046a62227a4caddce38cbbc37587bb9439ec637602b6818c5cbe3c71a7c4143960533dc74174bd315c8db227b69b55bb7fc30ba1d5213a752ec33925043cefbc1a62943ee5f34d5da01799e69094d732aef52f8e036980d0070e22e173c67c4bbcca61cc1eedbd6016516c592144819df13204dee", "bf0540d34b20f761101bc608b02458f2", "valid"),
    (100, "b279f57e19c8f53f2f963f5f2519fdb7c1779be2ca2b3ae8e1128b7d6c627fc4", "98bc2c7438d5cd7665d76f6e", "c0", "fcc515b294408c8645c9183e3f4ecee5127846d1", "eb5500e3825952866d911253f8de860c00831c81", "ecb660e1fb0541ec41e8d68a64141b3a", "valid"),
    (102, "f32364b1d339d82e4f132d8f4a0ec1ff7e746517fa07ef1a7f422f4e25a48194", "5a86a50a0e8a179c734b996d", "ab2ac7c44c60bdf8228c7884adb20184", "43891bccb522b1e72a6b53cf31c074e9d6c2df8e", "43dda832e942e286da314daa99bef5071d9d2c78", "c3922583476ced575404ddb85dd8cd44", "valid"),
    (116, "0f112e59cdccd851c3b8e76c9f05a3b7c2e4feca5846afeb351c1cbcace82f04", "7147973339d86789a2c9a958", "37128be45f0a7f329546e1492c3c9c2d2534d5b1f5147e49ab91221e7c3edea21bbe47bfe3619437ce3c61e6e946c504f348296918219e51bf2c5598589cff", "102e5804dda1fb5d656077edb15cadb5d0bdee8c", "618ac626ae0e8d06c2fd2fb66be253dc26ed6e38", "d8d93ff975cb988f09174dcd439cb6a4", "valid"),
    (117, "2ce6b4c15f85fb2da5cc6c269491eef281980309181249ebf2832bd6d0732d0b", "c064fae9173b173fd6f11f34", "498d3075b09fed998280583d61bb36b6ce41f130063b80824d1586e143d349b126b16aa10fe57343ed223d6364ee602257fe313a7fc9bf9088f027795b8dc1d3", "f8a27a4baf00dc0555d222f2fa4fb42dc666ea3c", "aed58d8a252f740dba4bf6d36773bd5b41234bba", "01f93d7456aa184ebb49bea472b6d65d", "valid"),
    (118, "52350da5a572911ee0e0fcedb115af6f4570fbf9c74a11bc184444d6a621d60f", "d68ad045c1b9c2923cf5404c", "03a94b3841292d9bbf72f413c09167c54ee10537c049afe2bbcec43b18f3890b2fcdd3bb31e6d709274e199c0c4648eb3d8b38e0c1bf7f309443bef6937cde4123", "4e6e6dad2c16cfc6e7cac03636a4a6d88bd6a13e", "c7764411be13cfeaaece761bd3bb13552f088048", "bcc2544e79f34ea1076a12b76441d6fa", "valid"),
    (123, "7ec20e38aa1b1f018d79903fc1cf6e260cec3733a19ad9e30f60b54e2ea6ebcc", "5ccd9cdcf97ac61364687bbb", "d9d2ee145b5c31a17dce932538c7e45da1c82abb80b0553251e442dbc5af9c126d3a76a24767c39b229bec8976a0df89fa70ea9ad872aa36d6b8b09aaa54698e7f29c2c2d12efb0b301cfb97076473dfa7ec030350e26839fbb7e1612dad93ff08e1119168c5fca56816c62b042f06d89e5a95da6a615e13ba4cad9f942534c539520d00509d0d4ac6d80c59e769d7e1aa7e12987ee05fb6a19b383c3348df6cbdcff604ef218338910a8e275d9a62b802cb07ec9249c9635e2437f8339dff3e21f79e9eb2acc2bbbadd520a84c58f0ddaaf8c32496d173b6b8c0c274352d40d47bfbd93069abdcc3d21c2cd330a8c16847f0e5299beb6a2d33be746de5c71f2", "bab28e0987509b1d6f9cf3aa90030795f125ee44", "ce4c58d3c7354d2d27e3bb41a62e5941fb1e39f3", "e177391d5e2cefa2f7d35e33a76566aa", "valid"),
    (128, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f", "000000000000000000000000", "", "561008fa07a68f5c61285cd013464eaf", "23293e9b07ca7d1b0cae7cc489a973b3", "ffffffffffffffffffffffffffffffff", "valid"),
    (129, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f", "ffffffffffffffffffffffff", "", "c6152244cea1978d3e0bc274cf8c0b3b", "7cb6fc7c6abc009efe9551a99f36a421", "00000000000000000000000000000000", "valid"),
    (130, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "9de8fef6d8ab1bf1bf887232eab590dd", "invalid"),
    (137, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "9ce8fef6d8ab1b71bf887232eab590dd", "invalid"),
    (138, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "9ce8fef6d8ab1bf1be887232eab590dd", "invalid"),
    (148, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "9ce8fef6d8ab1bf1bf887232eab5905d", "invalid"),
    (149, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "9de8fef6d8ab1bf1be887232eab590dd", "invalid"),
    (152, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "631701092754e40e40778dcd154a6f22", "invalid"),
    (153, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "00000000000000000000000000000000", "invalid"),
    (154, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "ffffffffffffffffffffffffffffffff", "invalid"),
    (155, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "1c687e76582b9b713f08f2b26a35105d", "invalid"),
    (156, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "505152535455565758595a5b", "", "202122232425262728292a2b2c2d2e2f", "b2061457c0759fc1749f174ee1ccadfa", "9de9fff7d9aa1af0be897333ebb491dc", "invalid"),
    (1, "5b9604fe14eadba931b0ccf34843dab9", "028318abc1824029138141a2", "", "001d0c231287c1182784554ca3a21908", "26073cc1d851beff176384dc9896d5ff", "0a3ea7a5487cb5f7d70fb6c58d038554", "valid"),
    (176, "00112233445566778899aabbccddeeff1021324354657687", "000000000000000000000000", "", "0b4dbbba8982e0f649f8ba85f3aa061b", "3f875c9bd7d8511448459468e398c3b2", "ffffffffffffffffffffffffffffffff", "valid"),
    (240, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f", "5c2ea9b695fcf6e264b96074d6bfa572", "", "00000000000000000000000000000000000000000000000000000000000000000000000000000000", "28e1c5232f4ee8161dbe4c036309e0b3254e9212bef0a93431ce5e5604c8f6a73c18a3183018b770", "d5808a1bd11a01129bf3c6919aff2339", "valid"),
    (299, "8f9a38c1014966e4d9ae736139c5e79b99345874f42d4c7d2c81aa6797c417c0", "a9", "", "", "", "2a268bf3a75fd7b00ba230b904bbb014", "valid"),
    (315, "3f8ca47b9a940582644e8ecf9c2d44e8138377a8379c5c11aafe7fec19856cf1", "", "", "", "", "1726aa695fbaa21a1db88455c670a4b0", "invalid"),
]

VALID_IDS = [91, 92, 93, 94, 96, 97, 98, 104, 105, 106, 110, 111, 112,
             100, 102, 116, 117, 118, 123, 128, 129]
MODIFIED_TAG_IDS = [130, 137, 138, 148, 149, 152, 153, 154, 155, 156]
LENGTH_REJECT_IDS = [1, 176, 240, 299, 315]


# ---------- the self-checks, all of them before any pin ----------


def bail(message: str) -> None:
    print(f"diff_gcm: SELF-CHECK FAILED: {message}")
    sys.exit(1)


def self_check_aes() -> None:
    """The S-box and the two published AES-256 ciphertexts."""
    for arg, want in ((0x00, 0x63), (0x01, 0x7C), (0x53, 0xED), (0xFF, 0x16)):
        if SBOX[arg] != want:
            bail(f"the S-box of {arg:#04x} is {SBOX[arg]:#04x}")
    c3 = aes_encrypt_block(key_expansion(FIPS197_KEY), FIPS197_MSG)
    if hx(c3) != "8ea2b7ca516745bfeafc49904b496089":
        bail(f"FIPS 197 C.3 recomputes to {hx(c3)}")
    f15 = aes_encrypt_block(key_expansion(F15_KEY), F15_MSG)
    if hx(f15) != "f3eed1bdb5d2a03c064b5a7e3db181f8":
        bail(f"SP 800-38A F.1.5 recomputes to {hx(f15)}")
    h0 = aes_encrypt_block(key_expansion(ZERO_KEY), b"\x00" * 16)
    if hx(h0) != "dc95c078a2408989ad48a21492842087":
        bail(f"H of the zero key recomputes to {hx(h0)}")
    print("diff_gcm: aes self-check ok")


SPEC_CASES = (
    (ZERO_KEY, ZERO_IV, b"", b"", "", "530f8afbc74536b9a963b4f1c4cb738b"),
    (
        ZERO_KEY,
        ZERO_IV,
        b"",
        b"\x00" * 16,
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    ),
    (
        CASE15_KEY,
        CASE15_IV,
        b"",
        CASE15_MSG,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c",
    ),
    (
        CASE15_KEY,
        CASE15_IV,
        CASE16_AAD,
        CASE16_MSG,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
)


def self_check_gcm_spec() -> None:
    """The four SP 800-38D cases, their roundtrips and the generated pair."""
    for n, (key, iv, aad, msg, want_ct, want_tag) in enumerate(SPEC_CASES, 13):
        ct, tag = gcm_seal(key, iv, aad, msg)
        if hx(ct) != want_ct or hx(tag) != want_tag:
            bail(f"case {n} recomputes to {hx(ct)} and {hx(tag)}")
        if gcm_unseal(key, iv, aad, ct, tag) != msg:
            bail(f"case {n} does not unseal to its plaintext")
    gen_ct, gen_tag = gcm_seal(GEN_KEY, GEN_IV, GEN_AAD, GEN_MSG)
    if gcm_unseal(GEN_KEY, GEN_IV, GEN_AAD, gen_ct, gen_tag) != GEN_MSG:
        bail("the generated vector does not unseal to its plaintext")
    twin_ct, twin_tag = gcm_seal(GEN_KEY, GEN_IV, GEN_AAD, b"")
    if twin_ct != b"" or gcm_unseal(GEN_KEY, GEN_IV, GEN_AAD, b"", twin_tag) != b"":
        bail("the empty twin does not unseal to the empty string")
    bad = bytes([gen_tag[0] ^ 0xC0]) + gen_tag[1:]
    if gcm_unseal(GEN_KEY, GEN_IV, GEN_AAD, gen_ct, bad) is not None:
        bail("the corrupted twin unseals")
    print("diff_gcm: gcm-spec self-check ok (4 cases)")


def self_check_lnsym() -> None:
    """The four case tags, corroborated by the LNSym AES-GCM spec test."""
    if not lnsym_path.is_file():
        print("diff_gcm: lnsym file absent")
        return
    text = re.sub(r"0x|#128|_|\s", "", lnsym_path.read_text())
    missing = [want_tag for (_, _, _, _, _, want_tag) in SPEC_CASES
               if want_tag not in text]
    if missing:
        bail(f"the lnsym file does not carry {missing}")
    print("diff_gcm: lnsym corroboration ok (4 tags)")


BY_ID = {row[0]: row for row in WYCHEPROOF}


def row_of(tc: int) -> tuple:
    row = BY_ID.get(tc)
    if row is None:
        bail(f"tcId {tc} is not in the embedded subset")
    return row


def self_check_wycheproof() -> None:
    """Every embedded vector, under this arithmetic alone."""
    for tc in VALID_IDS:
        (_, key, iv, aad, msg, ct, tag, result) = row_of(tc)
        if result != "valid":
            bail(f"tcId {tc} is embedded as {result} and not as valid")
        got_ct, got_tag = gcm_seal(uh(key), uh(iv), uh(aad), uh(msg))
        if hx(got_ct) != ct or hx(got_tag) != tag:
            bail(f"tcId {tc} recomputes to {hx(got_ct)} and {hx(got_tag)}")
        if gcm_unseal(uh(key), uh(iv), uh(aad), uh(ct), uh(tag)) != uh(msg):
            bail(f"tcId {tc} does not unseal to its message")
    for tc in MODIFIED_TAG_IDS:
        (_, key, iv, aad, msg, ct, tag, result) = row_of(tc)
        if result != "invalid":
            bail(f"tcId {tc} is embedded as {result} and not as invalid")
        got_ct, got_tag = gcm_seal(uh(key), uh(iv), uh(aad), uh(msg))
        if hx(got_ct) != ct:
            bail(f"tcId {tc} recomputes the ciphertext {hx(got_ct)}")
        if hx(got_tag) == tag:
            bail(f"tcId {tc} carries the honest tag {tag}")
        if gcm_unseal(uh(key), uh(iv), uh(aad), uh(ct), uh(tag)) is not None:
            bail(f"tcId {tc} unseals under a modified tag")
    for tc in LENGTH_REJECT_IDS:
        (_, key, iv, _, _, _, _, _) = row_of(tc)
        if len(uh(key)) == 32 and len(uh(iv)) == 12:
            bail(f"tcId {tc} is a 32-byte key with a 12-byte iv, no reject")
    print("diff_gcm: wycheproof self-check ok (21 valid, 10 invalid)")


def cross_check() -> None:
    """Every embedded record against the corpus, resolved by tcId."""
    if not wycheproof_path.is_file():
        print("diff_gcm: corpus absent, the embedded subset stands alone")
        return
    corpus = json.loads(wycheproof_path.read_text())
    if corpus.get("algorithm") != "AES-GCM":
        bail(f"the corpus algorithm is {corpus.get('algorithm')}")
    if corpus.get("numberOfTests") != 316:
        bail(f"the corpus holds {corpus.get('numberOfTests')} tests")
    found = {}
    for group in corpus["testGroups"]:
        for test in group["tests"]:
            found[test["tcId"]] = test
    for (tc, key, iv, aad, msg, ct, tag, result) in WYCHEPROOF:
        theirs = found.get(tc)
        if theirs is None:
            bail(f"tcId {tc} is not in the corpus")
        mine = (key, iv, aad, msg, ct, tag, result)
        real = (
            theirs["key"],
            theirs["iv"],
            theirs["aad"],
            theirs["msg"],
            theirs["ct"],
            theirs["tag"],
            theirs["result"],
        )
        if mine != real:
            bail(f"tcId {tc} disagrees with the corpus: {mine} against {real}")
    print(
        f"diff_gcm: corpus cross-check ok ({len(WYCHEPROOF)} vectors, "
        f"from {wycheproof_path})"
    )


def self_check_pycryptodome() -> None:
    """An INDEPENDENT implementation, when the host carries one."""
    try:
        from Crypto.Cipher import AES

        def sha_stream(label: bytes, n: int) -> bytes:
            """The first n bytes of a counter-chained SHA-256 stream."""
            blocks = (n + 31) // 32 + 1
            return b"".join(
                hashlib.sha256(label + b"-%d" % j).digest() for j in range(blocks)
            )[:n]

        def round_trip(key: bytes, iv: bytes, aad: bytes, ct: bytes, tag: bytes):
            """The recovered plaintext, or None when the tag does not verify."""
            back = AES.new(key, AES.MODE_GCM, nonce=iv)
            back.update(aad)
            try:
                return back.decrypt_and_verify(ct, tag)
            except ValueError:
                return None

        # D11 gives the derivation: 32 tuples over i in range(32), the key
        # the SHA-256 of "venice-m21-key-%d", the nonce the first 12 bytes
        # of the SHA-256 of "venice-m21-nonce-%d", the aad the first
        # (7 * i) % 70 bytes of one SHA-256 stream and the plaintext the
        # first (37 * i) % 600 bytes of another.
        tuples = [
            (
                hashlib.sha256(b"venice-m21-key-%d" % i).digest(),
                hashlib.sha256(b"venice-m21-nonce-%d" % i).digest()[:12],
                sha_stream(b"venice-m21-aad-%d" % i, (7 * i) % 70),
                sha_stream(b"venice-m21-msg-%d" % i, (37 * i) % 600),
            )
            for i in range(32)
        ]
        # Both directions per tuple: the seal must agree with
        # encrypt_and_digest, and the produced ct and tag must come back
        # through a FRESH decrypt_and_verify as the original plaintext.
        for (key, iv, aad, msg) in tuples:
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            cipher.update(aad)
            their_ct, their_tag = cipher.encrypt_and_digest(msg)
            my_ct, my_tag = gcm_seal(key, iv, aad, msg)
            recovered = round_trip(key, iv, aad, my_ct, my_tag)
            if (their_ct, their_tag) != (my_ct, my_tag) or recovered != msg:
                print("diff_gcm: DISAGREEMENT with pycryptodome")
                print(f"  key {hx(key)} iv {hx(iv)} aad {hx(aad)} msg {hx(msg)}")
                print(f"  pycryptodome {hx(their_ct)} {hx(their_tag)}")
                print(f"  this file    {hx(my_ct)} {hx(my_tag)}")
                sys.exit(1)
        print(f"diff_gcm: pycryptodome cross-check ok ({len(tuples)} tuples)")
    except Exception:
        # The WHOLE leg sits inside the try, not the import alone, so a
        # pycryptodome whose API differs cannot raise out of the oracle.
        # A real DISAGREEMENT is different: it exits 1 above through
        # SystemExit, which is a BaseException and not caught here.
        print("diff_gcm: pycryptodome absent, embedded vectors stand alone")


self_check_aes()
self_check_gcm_spec()
self_check_lnsym()
self_check_wycheproof()
cross_check()
self_check_pycryptodome()


# ---------- the suite matcher ----------


def strip_ocaml_comments(text: str) -> str:
    """Replace every (* ... *) comment with one space, nesting aware."""
    out = []
    depth = 0
    i = 0
    end = len(text)
    while i < end:
        if text.startswith("(*", i):
            depth += 1
            i += 2
            continue
        if text.startswith("*)", i) and depth > 0:
            depth -= 1
            i += 2
            out.append(" ")
            continue
        if depth == 0:
            out.append(text[i])
        i += 1
    return "".join(out)


ROW_START = re.compile(r'^\s*(?:\[\s*)?\(\s*"')
TOP_LEVEL = re.compile(r"^\S")


def check_rows(text: str) -> list:
    """Split the stripped suite into check rows.

    A row opens on an indented `( "label",` line and closes at the next
    row or at the next column-zero definition, so a constant sitting in
    a top-level let is outside every row.
    """
    rows = []
    current = None
    for line in text.splitlines():
        if ROW_START.match(line):
            if current is not None:
                rows.append("\n".join(current))
            current = [line]
        elif current is not None:
            if TOP_LEVEL.match(line):
                rows.append("\n".join(current))
                current = None
            else:
                current.append(line)
    if current is not None:
        rows.append("\n".join(current))
    return rows


SUITES = {"test_aesx.ml": aes_suite_path, "test_gcmx.ml": gcm_suite_path}

for suite_name, suite_path in SUITES.items():
    if not suite_path.is_file():
        print(f"diff_gcm: the suite is missing: {suite_path}")
        sys.exit(1)

RAW = {name: path.read_text() for name, path in SUITES.items()}
STRIPPED = {name: strip_ocaml_comments(text) for name, text in RAW.items()}
ROWS = {name: check_rows(text) for name, text in STRIPPED.items()}

for suite_name, rows in ROWS.items():
    if not rows:
        print(f"diff_gcm: no check row found in {suite_name}; the oracle is vacuous")
        sys.exit(1)

LABEL = re.compile(r'^\s*(?:\[\s*)?\(\s*"(?:[^"\\]|\\.)*"')
BODIES = {
    name: [LABEL.sub("", row, count=1) for row in rows]
    for name, rows in ROWS.items()
}


def pin(suite: str, name: str, needles: list) -> None:
    """Require every needle of a pin to sit inside one check row."""
    global fail
    bodies = BODIES[suite]
    missing = [x for x in needles if not any(x in body for body in bodies)]
    for x in missing:
        print(f"diff_gcm: {name}: recomputed value is in no check row")
        print(f"  wanted: {x}")
    if missing:
        fail = 1
    else:
        print(f"diff_gcm: {name} ok")


def require(name: str, ok: bool) -> None:
    """A pure cryptographic fact about a pin, independent of the suite."""
    global fail
    if not ok:
        print(f"diff_gcm: {name}: the python recompute disagrees with itself")
        fail = 1


# ---------- pin (a): the aesx suite ----------
#
# The four S-box known answers as OCaml hex literals, the two published
# ciphertexts and H for the zero key, which is E_0(0^16).

AES_WORDS_ZERO = key_expansion(ZERO_KEY)
H_ZERO = aes_encrypt_block(AES_WORDS_ZERO, b"\x00" * 16)

require("(a) the S-box masks its argument", SBOX[0xFF] == sbox(0x1FF) == sbox(-1))
require("(a) the S-box is a permutation", len(set(SBOX)) == 256)
require(
    "(a) H of the zero key is E_0(0^16)",
    H_ZERO == aes_encrypt_block(key_expansion(ZERO_KEY), bytes(16)),
)
pin(
    "test_aesx.ml",
    "(a) aesx known answers",
    [
        f"0x{SBOX[0x00]:02x}",
        f"0x{SBOX[0x01]:02x}",
        f"0x{SBOX[0x53]:02x}",
        f"0x{SBOX[0xFF]:02x}",
        hx(aes_encrypt_block(key_expansion(FIPS197_KEY), FIPS197_MSG)),
        hx(aes_encrypt_block(key_expansion(F15_KEY), F15_MSG)),
        hx(H_ZERO),
    ],
)

# ---------- pin (b): the D12 subset, field by field ----------
#
# Only the NON-EMPTY hex fields a D13 row actually CARRIES. A valid row
# seals, so it carries the key, the iv, the aad, the msg, the ct and the
# tag. A ModifiedTag row only unseals, so it carries the key, the iv,
# the ct and the modified tag, and NOT the msg. A length reject stops at
# Key.of_bytes or at Nonce.of_bytes, so it carries only the one field it
# passes and neither the msg nor the ct nor the tag of its vector. An
# empty field is the empty string, which sits inside every body, so it is
# skipped as a needle instead of passing vacuously.

# The field each length reject passes to the surface that refuses it.
REJECT_FIELD = {1: "key", 176: "key", 240: "iv", 299: "iv", 315: "iv"}

subset_needles = []
for tc in VALID_IDS:
    (_, key, iv, aad, msg, ct, tag, _) = row_of(tc)
    subset_needles += [x for x in (key, iv, aad, msg, ct, tag) if x != ""]
for tc in MODIFIED_TAG_IDS:
    (_, key, iv, _, _, ct, tag, _) = row_of(tc)
    subset_needles += [x for x in (key, iv, ct, tag) if x != ""]
for tc in LENGTH_REJECT_IDS:
    (_, key, iv, _, _, _, _, _) = row_of(tc)
    passed = key if REJECT_FIELD[tc] == "key" else iv
    subset_needles += [x for x in (passed,) if x != ""]
require("(b) the subset holds 36 vectors", len(WYCHEPROOF) == 36)
require(
    "(b) the subset splits 21, 10 and 5",
    len(VALID_IDS) == 21 and len(MODIFIED_TAG_IDS) == 10 and len(LENGTH_REJECT_IDS) == 5,
)
pin("test_gcmx.ml", "(b) wycheproof subset fields", subset_needles)

# ---------- pin (c): the four specification cases ----------

spec_needles = []
for (key, iv, aad, msg, want_ct, want_tag) in SPEC_CASES:
    got_ct, got_tag = gcm_seal(key, iv, aad, msg)
    require("(c) the case recomputes its ciphertext", hx(got_ct) == want_ct)
    require("(c) the case recomputes its tag", hx(got_tag) == want_tag)
    spec_needles += [x for x in (hx(got_ct), hx(got_tag)) if x != ""]
pin("test_gcmx.ml", "(c) sp 800-38d cases 13 to 16", spec_needles)

# ---------- pin (d): the generated vectors, recomputed ----------
#
# The derivations are the source: the key is SHA-256 of one ASCII
# string, the nonce the first 12 bytes of SHA-256 of another, the aad an
# ASCII string and the plaintext the first 100 bytes of a repeated one.
# Nothing here is quoted from the design.

GEN_CT, GEN_TAG = gcm_seal(GEN_KEY, GEN_IV, GEN_AAD, GEN_MSG)
TWIN_CT, TWIN_TAG = gcm_seal(GEN_KEY, GEN_IV, GEN_AAD, b"")

require("(d) the generated key is 32 bytes", len(GEN_KEY) == 32)
require("(d) the generated nonce is 12 bytes", len(GEN_IV) == 12)
require("(d) the generated plaintext is 100 bytes", len(GEN_MSG) == 100)
require("(d) the generated ciphertext is 100 bytes", len(GEN_CT) == 100)
require("(d) the empty twin has no ciphertext", TWIN_CT == b"")
require(
    "(d) the generated vector unseals",
    gcm_unseal(GEN_KEY, GEN_IV, GEN_AAD, GEN_CT, GEN_TAG) == GEN_MSG,
)
require(
    "(d) the empty twin unseals to the empty string",
    gcm_unseal(GEN_KEY, GEN_IV, GEN_AAD, b"", TWIN_TAG) == b"",
)
pin(
    "test_gcmx.ml",
    "(d) the generated vectors",
    [
        hx(GEN_KEY),
        hx(GEN_IV),
        hx(GEN_AAD),
        hx(GEN_MSG),
        hx(GEN_CT),
        hx(GEN_TAG),
        hx(TWIN_TAG),
    ],
)

# ---------- pin (e): the length cap ----------

require("(e) the cap is (2^32 - 2) * 16", MAX_LEN == 68719476704)
pin("test_gcmx.ml", "(e) max_len", [str(MAX_LEN)])


# ---------- the controls ----------
#
# The negative control is the corrupted twin of the generated tag, its
# first hex digit changed. A suite that quoted it would accept a forged
# tag, so it must sit NOWHERE in the stripped suite. The label control
# is a synthetic row whose value lives only in the row NAME: pin must
# report it MISSING, which proves the matcher reads bodies alone.

GEN_TAG_HEX = hx(GEN_TAG)
CORRUPT_TAG_HEX = ("0" if GEN_TAG_HEX[0] != "0" else "1") + GEN_TAG_HEX[1:]

require("control: the corrupted tag differs", CORRUPT_TAG_HEX != GEN_TAG_HEX)
require(
    "control: the corrupted tag does not unseal",
    gcm_unseal(GEN_KEY, GEN_IV, GEN_AAD, GEN_CT, uh(CORRUPT_TAG_HEX)) is None,
)

if CORRUPT_TAG_HEX in STRIPPED["test_gcmx.ml"]:
    print("diff_gcm: negative control: the corrupted tag is in the suite")
    print(f"  found: {CORRUPT_TAG_HEX}")
    fail = 1
else:
    print("diff_gcm: negative control ok")

MARKER = "b3f0c1a2d4e5f60718293a4b5c6d7e8f"
SYNTHETIC = f'  ("gcmx: label control {MARKER}",\n   fun () -> Ok ());'
SYNTHETIC_BODY = LABEL.sub("", SYNTHETIC, count=1)

if MARKER in SYNTHETIC_BODY:
    print("diff_gcm: label control: a row name still reaches the body")
    fail = 1
else:
    print("diff_gcm: label control ok")

sys.exit(fail)
