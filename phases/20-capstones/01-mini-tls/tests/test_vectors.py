"""
Test suite for the Mini TLS 1.3 library.

Run:
  python3 tests/test_vectors.py
"""

import json
import os
import sys
from contextlib import contextmanager

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as tls  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


# ---------------------------------------------------------------------------
# Vector-based tests
# ---------------------------------------------------------------------------

def test_vectors():
    vectors_path = os.path.join(HERE, "vectors.json")
    with open(vectors_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        inp = vec["inputs"]

        if op == "hkdf_extract":
            got = tls.hkdf_extract(_b(inp["salt_hex"]), _b(inp["ikm_hex"]))
            assert got.hex() == vec["expected"], f"vector failed: op={op}"

        elif op == "hkdf_expand":
            prk = _b(inp["prk_hex"])
            info = inp["info_ascii"].encode()
            got = tls.hkdf_expand(prk, info, inp["length"])
            assert got.hex() == vec["expected"], f"vector failed: op={op}"

        elif op == "hkdf_expand_label":
            secret = _b(inp["secret_hex"])
            context = _b(inp["context_hex"]) if inp["context_hex"] else b""
            got = tls.hkdf_expand_label(secret, inp["label"], context, inp["length"])
            assert got.hex() == vec["expected"], f"vector failed: op={op}"

        elif op == "hmac_aead_encrypt":
            key = _b(inp["key_hex"])
            nonce = _b(inp["nonce_hex"])
            plaintext = _b(inp["plaintext_hex"])
            aad = inp["aad_ascii"].encode()
            got = tls.aead_encrypt(key, nonce, plaintext, aad)
            assert got.hex() == vec["expected"], f"vector failed: op={op}"

        elif op == "hmac_aead_decrypt":
            key = _b(inp["key_hex"])
            nonce = _b(inp["nonce_hex"])
            ct_tag = _b(inp["ciphertext_and_tag_hex"])
            aad = inp["aad_ascii"].encode()
            got = tls.aead_decrypt(key, nonce, ct_tag, aad)
            assert got.hex() == vec["expected"], f"vector failed: op={op}"

        elif op == "handshake_key_schedule":
            ecdhe = _b(inp["ecdhe_shared_hex"])
            transcript = _b(inp["transcript_ch_sh_hex"])
            ks = tls.build_key_schedule(ecdhe, transcript)
            exp = vec["expected"]
            assert ks.early_secret.hex() == exp["early_secret"], "early_secret mismatch"
            assert ks.handshake_secret.hex() == exp["handshake_secret"], "handshake_secret mismatch"
            assert ks.master_secret.hex() == exp["master_secret"], "master_secret mismatch"
            assert ks.client_write_key.hex() == exp["client_write_key"], "client_write_key mismatch"
            assert ks.server_write_key.hex() == exp["server_write_key"], "server_write_key mismatch"

        elif op == "dh_shared_secret":
            c_priv = int(inp["client_private_hex"], 16)
            s_priv = int(inp["server_private_hex"], 16)
            _, c_pub = tls.dh_generate_keypair(c_priv)
            _, s_pub = tls.dh_generate_keypair(s_priv)
            shared_c = tls.dh_compute_shared(c_priv, s_pub)
            shared_s = tls.dh_compute_shared(s_priv, c_pub)
            assert shared_c == shared_s, "DH symmetry check failed"
            assert shared_c.hex() == vec["expected"], f"vector failed: op={op}"

        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

    print(f"  test_vectors: {len(data['vectors'])} vectors passed")


# ---------------------------------------------------------------------------
# Property-based / unit tests
# ---------------------------------------------------------------------------

def test_hkdf_extract_empty_salt():
    """Empty salt should be replaced by zeros per RFC 5869."""
    prk_empty = tls.hkdf_extract(b"", b"somekey")
    prk_zeros = tls.hkdf_extract(bytes(tls.HASH_LEN), b"somekey")
    assert prk_empty == prk_zeros


def test_hkdf_expand_length_variants():
    """hkdf_expand should produce any requested length up to 255*hash_len."""
    prk = tls.hkdf_extract(b"salt", b"ikm")
    for length in (1, 16, 32, 64, 100):
        okm = tls.hkdf_expand(prk, b"info", length)
        assert len(okm) == length, f"wrong length for {length}"
    # First 32 bytes must be the same regardless of requested length
    okm32 = tls.hkdf_expand(prk, b"info", 32)
    okm64 = tls.hkdf_expand(prk, b"info", 64)
    assert okm64[:32] == okm32


def test_aead_roundtrip():
    """aead_decrypt(aead_encrypt(p)) == p for arbitrary plaintexts."""
    key = bytes(range(32))
    nonce = bytes(range(12))
    for plaintext in [b"", b"x", b"A" * 100, bytes(range(200))]:
        blob = tls.aead_encrypt(key, nonce, plaintext, b"aad")
        recovered = tls.aead_decrypt(key, nonce, blob, b"aad")
        assert recovered == plaintext, f"roundtrip failed for plaintext={plaintext!r}"


def test_aead_tag_tamper_rejected():
    """Any modification to the ciphertext or tag must raise ValueError."""
    key = bytes(range(32))
    nonce = bytes(range(12))
    blob = tls.aead_encrypt(key, nonce, b"secret", b"aad")

    # Tamper last byte of tag
    bad = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    with _raises(ValueError):
        tls.aead_decrypt(key, nonce, bad, b"aad")

    # Tamper first byte of ciphertext
    bad2 = bytes([blob[0] ^ 0x01]) + blob[1:]
    with _raises(ValueError):
        tls.aead_decrypt(key, nonce, bad2, b"aad")

    # Wrong AAD
    with _raises(ValueError):
        tls.aead_decrypt(key, nonce, blob, b"wrong-aad")


def test_aead_nonce_uniqueness():
    """Different sequence numbers produce different nonces and different ciphertexts."""
    key = bytes(range(32))
    base_iv = bytes(range(12))
    rl = tls.RecordLayer(
        write_key=key,
        write_iv=base_iv,
        read_key=key,
        read_iv=base_iv,
    )
    pt = b"same plaintext"
    blob0 = rl.encrypt(pt)
    blob1 = rl.encrypt(pt)
    # Different sequence numbers → different nonces → different ciphertexts
    assert blob0 != blob1, "nonce reuse: same ciphertext for seq 0 and seq 1"


def test_record_layer_roundtrip():
    """Encrypt on client side, decrypt on server side, and vice versa."""
    key = bytes(range(32))
    c_iv = bytes([0xAA] * 12)
    s_iv = bytes([0xBB] * 12)
    client = tls.RecordLayer(write_key=key, write_iv=c_iv, read_key=key, read_iv=s_iv)
    server = tls.RecordLayer(write_key=key, write_iv=s_iv, read_key=key, read_iv=c_iv)

    for msg in [b"ping", b"pong", b"hello world"]:
        blob = client.encrypt(msg)
        assert server.decrypt(blob) == msg

    for msg in [b"response1", b"response2"]:
        blob = server.encrypt(msg)
        assert client.decrypt(blob) == msg


def test_dh_commutativity():
    """DH shared secret must be symmetric: dh(a, B) == dh(b, A)."""
    for priv_a, priv_b in [
        (12345, 67890),
        (0xABCDEF, 0x123456),
    ]:
        _, pub_a = tls.dh_generate_keypair(priv_a)
        _, pub_b = tls.dh_generate_keypair(priv_b)
        assert tls.dh_compute_shared(priv_a, pub_b) == tls.dh_compute_shared(priv_b, pub_a)


def test_finished_roundtrip():
    """make_finished / verify_finished must succeed and reject wrong transcript."""
    key = bytes(range(32))
    transcript = bytes(range(32, 64))
    fin = tls.make_finished(key, transcript)
    assert tls.verify_finished(key, transcript, fin)

    # Wrong transcript must fail
    wrong = tls.Finished(verify_data=bytes(tls.HASH_LEN))
    assert not tls.verify_finished(key, transcript, wrong)


def test_full_handshake_deterministic():
    """run_handshake with fixed inputs must produce a working record layer pair."""
    client_priv = 0xDEADBEEFCAFEBABE0102030405060708090A0B0C0D0E0F101112131415161718
    server_priv = 0xFEEDFACEDEADC0DE1A2B3C4D5E6F70718293A4B5C6D7E8F9AABBCCDDEEFF00
    c_rand = bytes(range(32))
    s_rand = bytes(range(31, -1, -1))

    ks, c_rl, s_rl = tls.run_handshake(client_priv, server_priv, c_rand, s_rand)

    # Application data c→s
    msg = b"hello server"
    blob = c_rl.encrypt(msg)
    assert s_rl.decrypt(blob) == msg

    # Application data s→c
    reply = b"hello client"
    blob2 = s_rl.encrypt(reply)
    assert c_rl.decrypt(blob2) == reply

    # Key schedule fields are non-empty and distinct
    secrets = [ks.early_secret, ks.handshake_secret, ks.master_secret,
               ks.client_write_key, ks.server_write_key]
    assert len(set(secrets)) == len(secrets), "key schedule produced duplicate secrets"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_vectors,
        test_hkdf_extract_empty_salt,
        test_hkdf_expand_length_variants,
        test_aead_roundtrip,
        test_aead_tag_tamper_rejected,
        test_aead_nonce_uniqueness,
        test_record_layer_roundtrip,
        test_dh_commutativity,
        test_finished_roundtrip,
        test_full_handshake_deterministic,
    ]
    for t in tests:
        t()
        print(f"  {t.__name__}: ok")
    print("all tests pass")
