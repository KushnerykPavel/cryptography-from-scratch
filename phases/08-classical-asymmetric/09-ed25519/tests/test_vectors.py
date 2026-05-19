import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    ED25519_B_ENC,
    ED25519_L,
    ed25519_decode,
    ed25519_encode,
    ed25519_secret_to_public,
    ed25519_sign,
    ed25519_verify,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "secret_to_public":
            got = ed25519_secret_to_public(bytes.fromhex(v["secret_hex"])).hex()
            assert got == v["expected_public_hex"], f"secret_to_public failed: got {got}, expected {v['expected_public_hex']}"
            continue

        if op == "sign":
            got = ed25519_sign(bytes.fromhex(v["secret_hex"]), bytes.fromhex(v["msg_hex"])).hex()
            assert (
                got == v["expected_signature_hex"]
            ), f"sign failed: got {got}, expected {v['expected_signature_hex']}"
            continue

        if op == "verify":
            got = ed25519_verify(bytes.fromhex(v["public_hex"]), bytes.fromhex(v["msg_hex"]), bytes.fromhex(v["signature_hex"]))
            assert got == v["expected"], f"verify failed: got {got}, expected {v['expected']}"
            continue

        raise AssertionError(f"unknown op {op}")


def test_roundtrips_and_rejection():
    b = ed25519_decode(ED25519_B_ENC)
    assert ed25519_decode(ed25519_encode(b)) == b

    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    msg = b""
    pk = ed25519_secret_to_public(seed)
    sig = ed25519_sign(seed, msg)
    assert ed25519_verify(pk, msg, sig)

    sig_bad = bytearray(sig)
    sig_bad[0] ^= 1
    assert not ed25519_verify(pk, msg, bytes(sig_bad))

    s_too_large = (ED25519_L).to_bytes(32, "little")
    assert not ed25519_verify(pk, msg, sig[:32] + s_too_large)

    assert not ed25519_verify(pk, msg + b"\x00", sig)
    assert not ed25519_verify(pk[:-1], msg, sig)
    assert not ed25519_verify(pk, msg, sig[:-1])


if __name__ == "__main__":
    test_vectors()
    test_roundtrips_and_rejection()
    print("all tests pass")

