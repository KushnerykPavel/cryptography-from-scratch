import importlib.util
import json
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
MODULE_PATH = LESSON / "code" / "main.py"
VECTORS_PATH = LESSON / "tests" / "vectors.json"


spec = importlib.util.spec_from_file_location("dsa_ecdsa_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


def parse_point(value):
    if value is None:
        return None
    return main.Point(value[0], value[1])


def point_to_json(value):
    if value is None:
        return None
    return [value.x, value.y]


def call(vector):
    op = vector["op"]

    if op == "mod_inv":
        return main.mod_inv(vector["a"], vector["modulus"])

    if op == "hash_to_int":
        return main.hash_to_int(bytes.fromhex(vector["message_hex"]), vector["q"])

    if op == "rfc6979_generate_k":
        return main.rfc6979_generate_k(
            vector["x"], bytes.fromhex(vector["h1_hex"]), vector["q"]
        )

    if op == "dsa_sign":
        return list(
            main.dsa_sign(
                bytes.fromhex(vector["message_hex"]),
                vector["p"],
                vector["q"],
                vector["g"],
                vector["x"],
            )
        )

    if op == "dsa_verify":
        return main.dsa_verify(
            bytes.fromhex(vector["message_hex"]),
            vector["p"],
            vector["q"],
            vector["g"],
            vector["y"],
            (vector["signature"][0], vector["signature"][1]),
        )

    if op == "recover_private_key_from_nonce_reuse":
        return list(
            main.recover_private_key_from_nonce_reuse(
                vector["q"],
                vector["e1"],
                vector["e2"],
                vector["r"],
                vector["s1"],
                vector["s2"],
            )
        )

    if op == "scalar_mul_secp256k1":
        point = main.SECP256K1_G if vector["point"] == "G" else parse_point(vector["point"])
        return point_to_json(main.scalar_mul_secp256k1(vector["k"], point))

    if op == "ecdsa_public_key":
        return point_to_json(main.ecdsa_public_key(vector["d"]))

    if op == "ecdsa_sign":
        return list(
            main.ecdsa_sign(
                bytes.fromhex(vector["message_hex"]),
                vector["d"],
                low_s=vector.get("low_s", True),
            )
        )

    if op == "ecdsa_verify":
        q = parse_point(vector["Q"])
        return main.ecdsa_verify(
            bytes.fromhex(vector["message_hex"]),
            q,
            (vector["signature"][0], vector["signature"][1]),
        )

    if op == "normalize_s_low_s":
        return list(
            main.normalize_s_low_s(vector["n"], (vector["signature"][0], vector["signature"][1]))
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


def test_dsa_rejects_out_of_range_signature():
    x = 37
    y = main.dsa_public_key(main.DSA_P, main.DSA_G, x)
    msg = b"hello"
    assert main.dsa_verify(msg, main.DSA_P, main.DSA_Q, main.DSA_G, y, (0, 1)) is False
    assert main.dsa_verify(msg, main.DSA_P, main.DSA_Q, main.DSA_G, y, (1, 0)) is False
    assert (
        main.dsa_verify(msg, main.DSA_P, main.DSA_Q, main.DSA_G, y, (main.DSA_Q, 1))
        is False
    )
    assert (
        main.dsa_verify(msg, main.DSA_P, main.DSA_Q, main.DSA_G, y, (1, main.DSA_Q))
        is False
    )


def test_secp256k1_group_sanity():
    assert main.is_on_secp256k1(main.SECP256K1_G)
    assert main.scalar_mul_secp256k1(main.SECP256K1_N, main.SECP256K1_G) is None

    p = main.scalar_mul_secp256k1(37, main.SECP256K1_G)
    assert main.is_on_secp256k1(p)
    assert main.point_add_secp256k1(p, main.point_neg_secp256k1(p)) is None


def test_ecdsa_roundtrip_and_malleability():
    msg = b"hello"
    d = 1
    q = main.ecdsa_public_key(d)

    sig = main.ecdsa_sign(msg, d, low_s=False)
    assert main.ecdsa_verify(msg, q, sig) is True
    assert main.ecdsa_verify(b"hellO", q, sig) is False

    r, s = sig
    malleable = (r, (main.SECP256K1_N - s) % main.SECP256K1_N)
    assert main.ecdsa_verify(msg, q, malleable) is True

    normalized = main.normalize_s_low_s(main.SECP256K1_N, sig)
    assert main.ecdsa_verify(msg, q, normalized) is True
    assert normalized[1] <= main.SECP256K1_N // 2


if __name__ == "__main__":
    test_vectors()
    test_dsa_rejects_out_of_range_signature()
    test_secp256k1_group_sanity()
    test_ecdsa_roundtrip_and_malleability()
    print("all tests pass")

