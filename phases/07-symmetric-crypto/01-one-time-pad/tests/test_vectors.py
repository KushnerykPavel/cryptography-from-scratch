import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import from_hex, otp_decrypt, otp_encrypt, to_hex, xor_bytes


def _rand_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(0, 256) for _ in range(n))


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "xor_bytes":
            got = to_hex(xor_bytes(from_hex(v["a_hex"]), from_hex(v["b_hex"])))
            assert got == v["expected_hex"], f"{op} failed: got {got}, expected {v['expected_hex']}"
        elif op == "otp_encrypt":
            got = to_hex(otp_encrypt(from_hex(v["plaintext_hex"]), from_hex(v["key_hex"])))
            assert got == v["expected_hex"], f"{op} failed: got {got}, expected {v['expected_hex']}"
        elif op == "otp_decrypt":
            got = to_hex(otp_decrypt(from_hex(v["ciphertext_hex"]), from_hex(v["key_hex"])))
            assert got == v["expected_hex"], f"{op} failed: got {got}, expected {v['expected_hex']}"
        else:
            raise AssertionError(f"unknown op {op}")


def test_xor_properties_roundtrip_and_commutativity():
    rng = random.Random(0)
    for n in [0, 1, 2, 15, 16, 31, 32, 100]:
        for _ in range(25):
            a = _rand_bytes(rng, n)
            b = _rand_bytes(rng, n)
            assert xor_bytes(a, b) == xor_bytes(b, a)
            assert xor_bytes(xor_bytes(a, b), b) == a
            assert xor_bytes(a, a) == b"\x00" * n


def test_otp_roundtrip():
    rng = random.Random(1)
    for n in [0, 1, 2, 15, 16, 31, 32, 100]:
        for _ in range(25):
            msg = _rand_bytes(rng, n)
            key = _rand_bytes(rng, n)
            ct = otp_encrypt(msg, key)
            assert otp_decrypt(ct, key) == msg


def test_reject_length_mismatch():
    try:
        xor_bytes(b"\x00", b"")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    try:
        otp_encrypt(b"\x00", b"")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    try:
        otp_decrypt(b"\x00", b"")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_reject_wrong_types():
    for bad in [None, 123, "hi", ["x"]]:
        try:
            xor_bytes(b"\x00", bad)  # type: ignore[arg-type]
            raise AssertionError("expected TypeError")
        except TypeError:
            pass

        try:
            otp_encrypt(b"\x00", bad)  # type: ignore[arg-type]
            raise AssertionError("expected TypeError")
        except TypeError:
            pass

        try:
            otp_decrypt(b"\x00", bad)  # type: ignore[arg-type]
            raise AssertionError("expected TypeError")
        except TypeError:
            pass


if __name__ == "__main__":
    test_vectors()
    test_xor_properties_roundtrip_and_commutativity()
    test_otp_roundtrip()
    test_reject_length_mismatch()
    test_reject_wrong_types()
    print("all tests pass")

