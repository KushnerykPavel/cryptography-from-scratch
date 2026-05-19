import importlib.util
import json
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON / "code" / "main.py"
VECTORS_PATH = LESSON / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("schnorr_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


def call(vector):
    op = vector["op"]

    if op == "mod_inv":
        return main.mod_inv(vector["a"], vector["modulus"])

    if op == "schnorr_public_key":
        return main.schnorr_public_key(vector["p"], vector["g"], vector["x"])

    if op == "schnorr_sign":
        return list(
            main.schnorr_sign(
                bytes.fromhex(vector["message_hex"]),
                vector["p"],
                vector["q"],
                vector["g"],
                vector["x"],
                k=vector.get("k"),
            )
        )

    if op == "schnorr_verify":
        return main.schnorr_verify(
            bytes.fromhex(vector["message_hex"]),
            vector["p"],
            vector["q"],
            vector["g"],
            vector["y"],
            (vector["signature"][0], vector["signature"][1]),
        )

    if op == "recover_x_from_nonce_reuse":
        return main.recover_x_from_nonce_reuse(
            vector["q"],
            vector["e1"],
            vector["s1"],
            vector["e2"],
            vector["s2"],
        )

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        assert call(vector) == vector["expected"]


def test_schnorr_rejects_out_of_range_signature():
    p = 1019
    q = 509
    g = 4
    x = 37
    y = main.schnorr_public_key(p, g, x)
    msg = b"hello"

    assert main.schnorr_verify(msg, p, q, g, y, (-1, 1)) is False
    assert main.schnorr_verify(msg, p, q, g, y, (q, 1)) is False
    assert main.schnorr_verify(msg, p, q, g, y, (1, -1)) is False
    assert main.schnorr_verify(msg, p, q, g, y, (1, q)) is False


def test_schnorr_roundtrip_is_deterministic_and_message_bound():
    p = 1019
    q = 509
    g = 4
    x = 123
    y = main.schnorr_public_key(p, g, x)

    msg = b"hello schnorr"
    sig1 = main.schnorr_sign(msg, p, q, g, x)
    sig2 = main.schnorr_sign(msg, p, q, g, x)
    assert sig1 == sig2
    assert main.schnorr_verify(msg, p, q, g, y, sig1) is True
    assert main.schnorr_verify(b"hello schnorr!", p, q, g, y, sig1) is False


def test_nonce_reuse_recovers_private_key():
    p = 1019
    q = 509
    g = 4
    x = 123
    y = main.schnorr_public_key(p, g, x)
    k = 77

    m1 = b"pay bob 10"
    m2 = b"pay mallory 10"
    e1, s1 = main.schnorr_sign(m1, p, q, g, x, k=k)
    e2, s2 = main.schnorr_sign(m2, p, q, g, x, k=k)

    x_recovered = main.recover_x_from_nonce_reuse(q, e1, s1, e2, s2)
    assert x_recovered == x % q
    assert main.schnorr_verify(m1, p, q, g, y, (e1, s1)) is True
    assert main.schnorr_verify(m2, p, q, g, y, (e2, s2)) is True


if __name__ == "__main__":
    test_vectors()
    test_schnorr_rejects_out_of_range_signature()
    test_schnorr_roundtrip_is_deterministic_and_message_bound()
    test_nonce_reuse_recovers_private_key()
    print("all tests pass")

