import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    ctr_mode_decrypt,
    ctr_mode_encrypt,
    prf_collision_probability,
    prf_to_prg,
    prg_security_bits,
    prg_stretch,
    prp_prf_switching_advantage,
    safe_query_limit,
    toy_prf,
    toy_prf_n,
    toy_prg,
    toy_prp_decrypt,
    toy_prp_encrypt,
)

_KEY0 = bytes(32)
_SEED0 = bytes(16)


def _run_vector(v):
    op = v["op"]
    if op == "toy_prg":
        seed = bytes.fromhex(v["seed_hex"])
        return toy_prg(seed, v["output_bytes"]).hex()
    if op == "toy_prf":
        key = bytes.fromhex(v["key_hex"])
        x = bytes.fromhex(v["x_hex"])
        return toy_prf(key, x).hex()
    if op == "toy_prf_n":
        key = bytes.fromhex(v["key_hex"])
        x = bytes.fromhex(v["x_hex"])
        return toy_prf_n(key, x, v["output_bits"])
    if op == "toy_prp_encrypt":
        key = bytes.fromhex(v["key_hex"])
        pt = bytes.fromhex(v["pt_hex"])
        return toy_prp_encrypt(key, pt).hex()
    if op == "toy_prp_roundtrip":
        key = bytes.fromhex(v["key_hex"])
        pt = bytes.fromhex(v["pt_hex"])
        ct = toy_prp_encrypt(key, pt)
        return toy_prp_decrypt(key, ct) == pt
    if op == "ctr_encrypt":
        key = bytes.fromhex(v["key_hex"])
        pt = bytes.fromhex(v["pt_hex"])
        return ctr_mode_encrypt(key, v["nonce"], pt).hex()
    if op == "prp_prf_switching":
        return prp_prf_switching_advantage(v["q"], v["block_bits"])
    if op == "prg_stretch":
        return prg_stretch(v["seed_bits"], v["output_bits"])
    if op == "prg_security_bits":
        return prg_security_bits(v["seed_bits"])
    raise AssertionError(f"unknown op {op!r}")


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)
    for v in data["vectors"]:
        got = _run_vector(v)
        expected = v["expected"] if "expected" in v else v.get("expected_hex")
        if isinstance(expected, bool):
            assert got == expected, f"vector {v}: got {got!r}, want {expected!r}"
        elif isinstance(expected, (int, float)):
            assert math.isclose(got, expected, rel_tol=1e-9, abs_tol=1e-50), (
                f"vector {v}: got {got!r}, want {expected!r}"
            )
        else:
            assert got == expected, f"vector {v}: got {got!r}, want {expected!r}"


# --- toy_prg ---

def test_prg_deterministic():
    assert toy_prg(_SEED0, 16) == toy_prg(_SEED0, 16)

def test_prg_different_seeds():
    out1 = toy_prg(b"\x00" * 16, 32)
    out2 = toy_prg(b"\x01" * 16, 32)
    assert out1 != out2

def test_prg_prefix_consistent():
    out16 = toy_prg(_SEED0, 16)
    out32 = toy_prg(_SEED0, 32)
    assert out32[:16] == out16

def test_prg_zero_output():
    assert toy_prg(_SEED0, 0) == b""

def test_prg_rejects_empty_seed():
    try:
        toy_prg(b"", 16)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for empty seed")

def test_prg_security_bits_equals_seed():
    for bits in (64, 128, 256):
        assert prg_security_bits(bits) == bits

def test_prg_stretch_positive():
    assert prg_stretch(128, 256) == 128
    assert prg_stretch(128, 128) == 0
    assert prg_stretch(128, 512) == 384


# --- toy_prf ---

def test_prf_deterministic():
    assert toy_prf(_KEY0, b"x") == toy_prf(_KEY0, b"x")

def test_prf_different_inputs():
    h1 = toy_prf(_KEY0, b"\x00" * 4)
    h2 = toy_prf(_KEY0, b"\x01" * 4)
    assert h1 != h2

def test_prf_different_keys():
    h1 = toy_prf(b"\x00" * 32, b"input")
    h2 = toy_prf(b"\x01" * 32, b"input")
    assert h1 != h2

def test_prf_output_length():
    assert len(toy_prf(_KEY0, b"x")) == 32

def test_prf_rejects_empty_key():
    try:
        toy_prf(b"", b"x")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for empty key")

def test_prf_n_in_range():
    for bits in (1, 8, 16, 32, 64, 128, 256):
        v = toy_prf_n(_KEY0, b"x", bits)
        assert 0 <= v < 2 ** bits, f"prf_n({bits}) out of range: {v}"


# --- toy_prp ---

def test_prp_roundtrip_many():
    for i in range(20):
        pt = os.urandom(8)
        ct = toy_prp_encrypt(_KEY0, pt)
        assert toy_prp_decrypt(_KEY0, ct) == pt

def test_prp_different_plaintexts():
    ct1 = toy_prp_encrypt(_KEY0, b"\x00" * 8)
    ct2 = toy_prp_encrypt(_KEY0, b"\x01" * 8)
    assert ct1 != ct2

def test_prp_is_bijection():
    seen = set()
    for i in range(256):
        pt = bytes([i, 0, 0, 0, 0, 0, 0, 0])
        ct = toy_prp_encrypt(_KEY0, pt)
        assert ct not in seen, f"collision at i={i}"
        seen.add(ct)

def test_prp_rejects_odd_length():
    try:
        toy_prp_encrypt(_KEY0, b"\x00" * 7)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for odd-length plaintext")

def test_prp_different_keys():
    pt = b"\xde\xad\xbe\xef" * 2
    ct1 = toy_prp_encrypt(b"\x00" * 32, pt)
    ct2 = toy_prp_encrypt(b"\x01" * 32, pt)
    assert ct1 != ct2


# --- CTR mode ---

def test_ctr_roundtrip():
    msg = b"hello, world!! CTR mode test msg"
    enc = ctr_mode_encrypt(_KEY0, 0, msg)
    dec = ctr_mode_decrypt(_KEY0, 0, enc)
    assert dec == msg

def test_ctr_nonce_reuse_reveals_xor():
    key, nonce = _KEY0, 0x1234
    m1 = b"Attack at dawn!!"
    m2 = b"Attack at dusk!!"
    ct1 = ctr_mode_encrypt(key, nonce, m1)
    ct2 = ctr_mode_encrypt(key, nonce, m2)
    xored = bytes(a ^ b for a, b in zip(ct1, ct2))
    expected = bytes(a ^ b for a, b in zip(m1, m2))
    assert xored == expected, "nonce reuse should reveal plaintext XOR"

def test_ctr_different_nonces():
    ct1 = ctr_mode_encrypt(_KEY0, 0, b"same message    ")
    ct2 = ctr_mode_encrypt(_KEY0, 1, b"same message    ")
    assert ct1 != ct2

def test_ctr_empty_message():
    assert ctr_mode_encrypt(_KEY0, 0, b"") == b""


# --- prf_to_prg ---

def test_prf_to_prg_deterministic():
    assert prf_to_prg(_KEY0, 64) == prf_to_prg(_KEY0, 64)

def test_prf_to_prg_length():
    for n in (0, 1, 32, 64, 100):
        assert len(prf_to_prg(_KEY0, n)) == n


# --- security bounds ---

def test_switching_advantage_zero_queries():
    assert prp_prf_switching_advantage(0, 128) == 0.0
    assert prp_prf_switching_advantage(1, 128) == 0.0

def test_switching_advantage_grows_quadratically():
    adv2 = prp_prf_switching_advantage(2, 64)
    adv4 = prp_prf_switching_advantage(4, 64)
    assert adv4 / adv2 > 3.5

def test_safe_query_limit_reasonable():
    q = safe_query_limit(128, 2 ** -32)
    assert q > 0
    adv = prp_prf_switching_advantage(q, 128)
    assert adv <= 2 ** -32 + 1e-10


if __name__ == "__main__":
    test_vectors()
    test_prg_deterministic()
    test_prg_different_seeds()
    test_prg_prefix_consistent()
    test_prg_zero_output()
    test_prg_rejects_empty_seed()
    test_prg_security_bits_equals_seed()
    test_prg_stretch_positive()
    test_prf_deterministic()
    test_prf_different_inputs()
    test_prf_different_keys()
    test_prf_output_length()
    test_prf_rejects_empty_key()
    test_prf_n_in_range()
    test_prp_roundtrip_many()
    test_prp_different_plaintexts()
    test_prp_is_bijection()
    test_prp_rejects_odd_length()
    test_prp_different_keys()
    test_ctr_roundtrip()
    test_ctr_nonce_reuse_reveals_xor()
    test_ctr_different_nonces()
    test_ctr_empty_message()
    test_prf_to_prg_deterministic()
    test_prf_to_prg_length()
    test_switching_advantage_zero_queries()
    test_switching_advantage_grows_quadratically()
    test_safe_query_limit_reasonable()
    print("all tests pass")
