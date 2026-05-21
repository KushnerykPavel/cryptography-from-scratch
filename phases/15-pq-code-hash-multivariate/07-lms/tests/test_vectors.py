import json
import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
CODE_DIR = (THIS_DIR / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as lms  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _flip_one_bit(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty")
    b = bytearray(data)
    b[len(b) // 2] ^= 0x01
    return bytes(b)


def test_vectors() -> None:
    vectors_path = THIS_DIR / "vectors.json"
    raw = json.loads(vectors_path.read_text())
    vectors = raw["vectors"]

    for v in vectors:
        op = v["op"]

        if op == "coef":
            got = lms.coef(_b(v["s_hex"]), v["i"], v["w"])
            assert got == v["expected"]
            continue

        if op == "lmots_public_key_hash":
            got = lms.lmots_public_key_hash(
                _b(v["I_hex"]),
                v["q"],
                _b(v["seed_hex"]),
                v["lmots_type"],
            )
            assert got == _b(v["expected_hex"])
            continue

        if op == "lmots_sign":
            got = lms.lmots_sign(
                _b(v["I_hex"]),
                v["q"],
                _b(v["seed_hex"]),
                _b(v["message_hex"]),
                v["lmots_type"],
                C=_b(v["C_hex"]),
            )
            assert got == _b(v["expected_hex"])
            continue

        if op == "lmots_public_key_candidate":
            got = lms.lmots_public_key_candidate(
                _b(v["I_hex"]),
                v["q"],
                _b(v["message_hex"]),
                _b(v["lmots_sig_hex"]),
                v["lmots_type"],
            )
            assert got == _b(v["expected_hex"])
            continue

        if op == "lms_keygen":
            prv, pub = lms.lms_keygen(
                _b(v["I_hex"]),
                _b(v["seed_hex"]),
                v["lms_type"],
                v["lmots_type"],
            )
            assert pub == _b(v["expected_pub_hex"])
            assert prv.q == 0
            continue

        if op == "lms_sign":
            prv, pub = lms.lms_keygen(
                _b(v["I_hex"]),
                _b(v["seed_hex"]),
                v["lms_type"],
                v["lmots_type"],
            )
            sig = lms.lms_sign(prv, _b(v["message_hex"]), C=_b(v["C_hex"]))
            assert sig == _b(v["expected_sig_hex"])
            assert lms.lms_verify(pub, _b(v["message_hex"]), sig)
            continue

        if op == "lms_verify":
            got = lms.lms_verify(_b(v["pub_hex"]), _b(v["message_hex"]), _b(v["sig_hex"]))
            assert got == v["expected"]
            continue

        raise ValueError(f"unknown op: {op}")


def test_roundtrip_and_statefulness() -> None:
    I = lms.sha256(b"property-I")[:16]
    seed = lms.sha256(b"property-seed")[:32]
    n, _, _, _ = lms.lmots_params(lms.LMOTS_SHA256_N32_W8)

    prv, pub = lms.lms_keygen(I, seed, lms.LMS_SHA256_M32_H5, lms.LMOTS_SHA256_N32_W8)
    assert prv.q == 0

    m1 = b"m1"
    s1 = lms.lms_sign(prv, m1, C=lms.derive_C_deterministic(I, 0, seed, m1, n))
    assert prv.q == 1
    assert lms.lms_verify(pub, m1, s1)

    m2 = b"m2"
    s2 = lms.lms_sign(prv, m2, C=lms.derive_C_deterministic(I, 1, seed, m2, n))
    assert prv.q == 2
    assert lms.lms_verify(pub, m2, s2)

    assert not lms.lms_verify(pub, m1, s2)
    assert not lms.lms_verify(pub, m2, s1)


def test_exhaustion_and_rejection() -> None:
    I = lms.sha256(b"exhaust-I")[:16]
    seed = lms.sha256(b"exhaust-seed")[:32]
    n, _, _, _ = lms.lmots_params(lms.LMOTS_SHA256_N32_W8)

    prv, pub = lms.lms_keygen(I, seed, lms.LMS_SHA256_M32_H5, lms.LMOTS_SHA256_N32_W8)
    _, h = lms.lms_params(lms.LMS_SHA256_M32_H5)
    leaf_count = 1 << h

    for q in range(leaf_count):
        m = b"x" + bytes([q])
        sig = lms.lms_sign(prv, m, C=lms.derive_C_deterministic(I, q, seed, m, n))
        assert lms.lms_verify(pub, m, sig)

    assert prv.q == leaf_count
    try:
        lms.lms_sign(prv, b"too many", C=lms.derive_C_deterministic(I, leaf_count, seed, b"too many", n))
        raise AssertionError("expected exhaustion")
    except ValueError:
        pass

    assert not lms.lms_verify(pub, b"m", b"")
    assert not lms.lms_verify(_flip_one_bit(pub), b"m", b"")


def test_tamper_detection() -> None:
    I = lms.sha256(b"tamper-I")[:16]
    seed = lms.sha256(b"tamper-seed")[:32]
    n, _, _, _ = lms.lmots_params(lms.LMOTS_SHA256_N32_W8)

    prv, pub = lms.lms_keygen(I, seed, lms.LMS_SHA256_M32_H5, lms.LMOTS_SHA256_N32_W8)
    m = b"hello"
    sig = lms.lms_sign(prv, m, C=lms.derive_C_deterministic(I, 0, seed, m, n))
    assert lms.lms_verify(pub, m, sig)

    assert not lms.lms_verify(_flip_one_bit(pub), m, sig)
    assert not lms.lms_verify(pub, m, _flip_one_bit(sig))


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_and_statefulness()
    test_exhaustion_and_rejection()
    test_tamper_detection()
    print("all tests pass")

