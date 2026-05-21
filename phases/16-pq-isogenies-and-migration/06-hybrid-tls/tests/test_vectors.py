import json
import os
import random
import sys
from contextlib import contextmanager

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as hybrid  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "hkdf_extract_sha256":
            got = hybrid.hkdf_extract_sha256(_b(vec["salt_hex"]), _b(vec["ikm_hex"])).hex()
            expected = vec["expected_hex"]
        elif op == "hkdf_expand_sha256":
            got = hybrid.hkdf_expand_sha256(
                _b(vec["prk_hex"]), _b(vec["info_hex"]), int(vec["length"])
            ).hex()
            expected = vec["expected_hex"]
        elif op == "dh_shared_secret_bytes":
            got = hybrid.toy_dh_shared_secret_bytes(
                int(vec["p"]), int(vec["g"]), int(vec["sk_a"]), int(vec["sk_b"]), int(vec["length"])
            ).hex()
            expected = vec["expected_hex"]
        elif op == "toy_kem_keypair_from_seed":
            sk, pk = hybrid.toy_kem_keypair_from_seed(_b(vec["seed_hex"]))
            got = {"sk_hex": sk.hex(), "pk_hex": pk.hex()}
            expected = vec["expected"]
        elif op == "toy_kem_encapsulate":
            ct, ss = hybrid.toy_kem_encapsulate(_b(vec["pk_hex"]), _b(vec["seed_hex"]))
            got = {"ct_hex": ct.hex(), "ss_hex": ss.hex()}
            expected = vec["expected"]
        elif op == "toy_kem_decapsulate":
            got = hybrid.toy_kem_decapsulate(_b(vec["sk_hex"]), _b(vec["ct_hex"])).hex()
            expected = vec["expected_hex"]
        elif op == "combine_hybrid_secret_concat_hkdf":
            got = hybrid.combine_hybrid_secret_concat_hkdf(
                _b(vec["ss_classical_hex"]), _b(vec["ss_pq_hex"])
            ).hex()
            expected = vec["expected_hex"]
        elif op == "transcript_hash_sha256":
            got = hybrid.transcript_hash_sha256([_b(m) for m in vec["messages_hex"]]).hex()
            expected = vec["expected_hex"]
        elif op == "derive_tls13_like_secrets":
            got_secrets = hybrid.derive_tls13_like_secrets(
                _b(vec["hybrid_secret_hex"]), _b(vec["transcript_hash_hex"])
            )
            got = {k + "_hex": v.hex() for k, v in got_secrets.items()}
            expected = vec["expected"]
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

        assert got == expected, f"vector failed: op={op}"


def test_hkdf_expand_zero_length():
    assert hybrid.hkdf_expand_sha256(b"\x00" * 32, b"info", 0) == b""


def test_hkdf_extract_empty_salt_is_zeros():
    ikm = b"ikm"
    prk_empty = hybrid.hkdf_extract_sha256(b"", ikm)
    prk_zero = hybrid.hkdf_extract_sha256(b"\x00" * 32, ikm)
    assert prk_empty == prk_zero


def test_hkdf_expand_rejects_too_large():
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        hybrid.hkdf_expand_sha256(b"\x00" * 32, b"info", 255 * 32 + 1)


def test_dh_symmetric_shared_secret_int():
    p = 2**127 - 1
    g = 3
    rng = random.Random(0)
    for _ in range(20):
        sk_a = rng.randrange(1, 1_000_000)
        sk_b = rng.randrange(1, 1_000_000)
        pk_a = hybrid.dh_public_key(p, g, sk_a)
        pk_b = hybrid.dh_public_key(p, g, sk_b)
        ss_a = hybrid.dh_shared_secret_int(p, pk_b, sk_a)
        ss_b = hybrid.dh_shared_secret_int(p, pk_a, sk_b)
        assert ss_a == ss_b


def test_toy_kem_rejects_tampered_ciphertext():
    sk, pk = hybrid.toy_kem_keypair_from_seed(b"alice")
    ct, _ss = hybrid.toy_kem_encapsulate(pk, b"seed")
    tampered = bytearray(ct)
    tampered[0] ^= 1
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        hybrid.toy_kem_decapsulate(sk, bytes(tampered))


def test_transcript_binding_changes_secrets():
    ss_classical = b"\x11" * 16
    ss_pq = b"\x22" * 32
    hybrid_secret = hybrid.combine_hybrid_secret_concat_hkdf(ss_classical, ss_pq)

    t1 = hybrid.transcript_hash_sha256([b"client_hello", b"server_hello"])
    t2 = hybrid.transcript_hash_sha256([b"client_hello", b"server_hello", b"extension:x"])
    s1 = hybrid.derive_tls13_like_secrets(hybrid_secret, t1)
    s2 = hybrid.derive_tls13_like_secrets(hybrid_secret, t2)
    assert s1["client_app_traffic"] != s2["client_app_traffic"]
    assert s1["server_app_traffic"] != s2["server_app_traffic"]


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_hkdf_expand_zero_length,
        test_hkdf_extract_empty_salt_is_zeros,
        test_hkdf_expand_rejects_too_large,
        test_dh_symmetric_shared_secret_int,
        test_toy_kem_rejects_tampered_ciphertext,
        test_transcript_binding_changes_secrets,
    ]
    for t in tests:
        t()
    print("all tests pass")
