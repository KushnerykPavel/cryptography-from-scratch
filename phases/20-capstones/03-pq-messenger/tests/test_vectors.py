"""
Test suite for the PQ-Secure Messenger capstone.

Run:
  python3 tests/test_vectors.py
"""

import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as pq  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


# ---------------------------------------------------------------------------
# Vector-based tests
# ---------------------------------------------------------------------------

def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "lwe_keygen":
            seed = int(vec["seed"], 16)
            rng = pq._SeededRNG(seed)
            pk, sk = pq.lwe_keygen(rng)
            assert pk.b == vec["b_vec"], f"lwe_keygen b_vec mismatch"
            assert sk.s == vec["s_vec"], f"lwe_keygen s_vec mismatch"
            assert pk.A[0] == vec["A_row0"], f"lwe_keygen A_row0 mismatch"

        elif op == "lwe_encaps":
            rng_kg = pq._SeededRNG(int(vec["seed_keygen"], 16))
            pk, sk = pq.lwe_keygen(rng_kg)
            plaintext = _b(vec["plaintext_hex"])
            rng_enc = pq._SeededRNG(int(vec["seed_encaps"], 16))
            ct = pq.lwe_encaps(pk, plaintext, rng_enc)
            u0, v0 = ct.pairs[0]
            assert u0 == vec["u0"], f"lwe_encaps u0 mismatch"
            assert v0 == vec["v0"], f"lwe_encaps v0 mismatch"

        elif op == "lwe_decaps":
            rng_kg = pq._SeededRNG(int(vec["seed_keygen"], 16))
            pk, sk = pq.lwe_keygen(rng_kg)
            plaintext = _b(vec["plaintext_hex"])
            rng_enc = pq._SeededRNG(int(vec["seed_encaps"], 16))
            ct = pq.lwe_encaps(pk, plaintext, rng_enc)
            recovered = pq.lwe_decaps(sk, ct)
            assert recovered == _b(vec["recovered_hex"]), f"lwe_decaps mismatch"

        elif op == "hkdf":
            got = pq.hkdf(
                _b(vec["salt_hex"]),
                _b(vec["ikm_hex"]),
                _b(vec["info_hex"]),
                vec["length"],
            )
            assert got == _b(vec["okm_hex"]), f"hkdf output mismatch"

        elif op == "hmac_aead_encrypt":
            ct, tag = pq.hmac_aead_encrypt(
                _b(vec["key_hex"]),
                _b(vec["nonce_hex"]),
                _b(vec["plaintext_hex"]),
                _b(vec["aad_hex"]),
            )
            assert ct == _b(vec["ciphertext_hex"]), f"hmac_aead_encrypt ciphertext mismatch"
            assert tag == _b(vec["tag_hex"]), f"hmac_aead_encrypt tag mismatch"

        elif op == "hmac_aead_decrypt":
            pt = pq.hmac_aead_decrypt(
                _b(vec["key_hex"]),
                _b(vec["nonce_hex"]),
                _b(vec["ciphertext_hex"]),
                _b(vec["tag_hex"]),
                _b(vec["aad_hex"]),
            )
            assert pt == _b(vec["expected_plaintext_hex"]), f"hmac_aead_decrypt plaintext mismatch"

        elif op == "ratchet_key":
            k0 = _b(vec["key0_hex"])
            k1 = pq.ratchet_key(k0)
            k2 = pq.ratchet_key(k1)
            assert k1 == _b(vec["key1_hex"]), f"ratchet_key step1 mismatch"
            assert k2 == _b(vec["key2_hex"]), f"ratchet_key step2 mismatch"

        else:
            raise ValueError(f"unknown op in vectors.json: {op}")


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

def test_lwe_kem_roundtrip_multiple_plaintexts():
    """Different 32-byte values should all survive encaps/decaps correctly."""
    rng_kg = pq._SeededRNG(0x1234)
    pk, sk = pq.lwe_keygen(rng_kg)
    test_plaintexts = [
        bytes([0x00] * 32),
        bytes([0xFF] * 32),
        bytes(range(32)),
        bytes(range(32, 64)),
    ]
    for pt in test_plaintexts:
        rng_enc = pq._SeededRNG(0x5678 + sum(pt))
        ct = pq.lwe_encaps(pk, pt, rng_enc)
        recovered = pq.lwe_decaps(sk, ct)
        assert recovered == pt, f"LWE roundtrip failed for plaintext starting with {pt[:4].hex()}"


def test_hkdf_different_info_produces_different_keys():
    """Different info values must yield different outputs."""
    ikm = b"shared_input_keying_material"
    salt = b"salt"
    k1 = pq.hkdf(salt, ikm, b"info-1", 32)
    k2 = pq.hkdf(salt, ikm, b"info-2", 32)
    assert k1 != k2, "HKDF with different info must produce different keys"


def test_hmac_aead_tampered_tag_rejected():
    """Flipping a tag byte must raise ValueError."""
    key = b"\x42" * 32
    nonce = b"\x00" * 12
    pt = b"message under test"
    aad = b"aad"
    ct, tag = pq.hmac_aead_encrypt(key, nonce, pt, aad)
    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    try:
        pq.hmac_aead_decrypt(key, nonce, ct, bad_tag, aad)
        raise AssertionError("Expected ValueError for tampered tag")
    except ValueError:
        pass


def test_hmac_aead_tampered_ciphertext_rejected():
    """Flipping a ciphertext byte must raise ValueError."""
    key = b"\x11" * 32
    nonce = b"\x00" * 12
    pt = b"another test message"
    aad = b"context"
    ct, tag = pq.hmac_aead_encrypt(key, nonce, pt, aad)
    bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
    try:
        pq.hmac_aead_decrypt(key, nonce, bad_ct, tag, aad)
        raise AssertionError("Expected ValueError for tampered ciphertext")
    except ValueError:
        pass


def test_hmac_aead_wrong_aad_rejected():
    """Changing AAD must fail authentication."""
    key = b"\x99" * 32
    nonce = b"\x00" * 12
    pt = b"secret payload"
    ct, tag = pq.hmac_aead_encrypt(key, nonce, pt, b"correct-aad")
    try:
        pq.hmac_aead_decrypt(key, nonce, ct, tag, b"wrong-aad")
        raise AssertionError("Expected ValueError for wrong AAD")
    except ValueError:
        pass


def test_signature_roundtrip():
    """sig_sign / sig_verify roundtrip with multiple messages."""
    rng = pq._SeededRNG(0xABCD)
    sig_pk, sig_sk = pq.sig_keygen(rng)
    for msg in [b"hello", b"world", b"\x00" * 64, b"pq-secure"]:
        sig = pq.sig_sign(sig_sk, msg, pq._SeededRNG(0xEF01 + sum(msg)))
        assert pq.sig_verify(sig_pk, msg, sig), f"sig_verify failed for msg={msg!r}"
        # Wrong message must not verify
        assert not pq.sig_verify(sig_pk, msg + b"!", sig), \
            f"sig_verify should fail for tampered msg={msg!r}"


def test_ratchet_irreversibility():
    """Ratcheted key must differ from original and consecutive steps differ."""
    k0 = b"\xAA" * 32
    k1 = pq.ratchet_key(k0)
    k2 = pq.ratchet_key(k1)
    assert k0 != k1 != k2
    assert k1 != k2


def test_dh_shared_secret_symmetry():
    """Alice and Bob derive the same DH shared secret."""
    rng_a = pq._SeededRNG(0xAAAA)
    rng_b = pq._SeededRNG(0xBBBB)
    a_priv, a_pub = pq.dh_generate_keypair(rng_a)
    b_priv, b_pub = pq.dh_generate_keypair(rng_b)
    assert pq.dh_shared_secret(a_priv, b_pub) == pq.dh_shared_secret(b_priv, a_pub)


def test_hybrid_combine_salt_sensitivity():
    """Different salts must yield different session keys."""
    lwe_secret = b"\x01" * 32
    dh_secret = b"\x02" * 16
    info = b"session"
    k1 = pq.hybrid_combine(lwe_secret, dh_secret, b"salt1" * 6 + b"sa", info)
    k2 = pq.hybrid_combine(lwe_secret, dh_secret, b"salt2" * 6 + b"sa", info)
    assert k1 != k2


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_vectors,
        test_lwe_kem_roundtrip_multiple_plaintexts,
        test_hkdf_different_info_produces_different_keys,
        test_hmac_aead_tampered_tag_rejected,
        test_hmac_aead_tampered_ciphertext_rejected,
        test_hmac_aead_wrong_aad_rejected,
        test_signature_roundtrip,
        test_ratchet_irreversibility,
        test_dh_shared_secret_symmetry,
        test_hybrid_combine_salt_sensitivity,
    ]
    for t in tests:
        t()
    print("all tests pass")
