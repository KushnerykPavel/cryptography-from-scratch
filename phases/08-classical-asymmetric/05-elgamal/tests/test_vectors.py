import json
import sys
import secrets
from pathlib import Path


HERE = Path(__file__).resolve().parent
LESSON_DIR = HERE.parent
CODE_DIR = LESSON_DIR / "code"
sys.path.insert(0, str(CODE_DIR))

import main as elgamal


def _pub_priv_from_x(p: int, g: int, x: int):
    params = elgamal.ElGamalParams(p=p, g=g)
    pub, priv = elgamal.elgamal_keygen(params, x=x)
    return params, pub, priv


def _run_vector(v):
    op = v["op"]
    inputs = v["inputs"]
    expected = v["expected"]

    if op == "modinv":
        got = elgamal.modinv(inputs["a"], inputs["modulus"])
        assert got == expected
        return

    if op == "keygen_y":
        _, pub, _ = _pub_priv_from_x(inputs["p"], inputs["g"], inputs["x"])
        assert pub.y == expected
        return

    if op == "encrypt_int":
        _, pub, _ = _pub_priv_from_x(inputs["p"], inputs["g"], inputs["x"])
        c1, c2 = elgamal.elgamal_encrypt_int(pub, inputs["m"], k=inputs["k"])
        assert {"c1": c1, "c2": c2} == expected
        return

    if op == "decrypt_int":
        _, _, priv = _pub_priv_from_x(inputs["p"], inputs["g"], inputs["x"])
        got = elgamal.elgamal_decrypt_int(priv, (inputs["c1"], inputs["c2"]))
        assert got == expected
        return

    if op == "rerandomize":
        params, pub, priv = _pub_priv_from_x(inputs["p"], inputs["g"], inputs["x"])
        ct = (inputs["c1"], inputs["c2"])
        out = elgamal.elgamal_rerandomize(pub, ct, r=inputs["r"])
        assert {"c1": out[0], "c2": out[1]} == expected
        assert elgamal.elgamal_decrypt_int(priv, out) == elgamal.elgamal_decrypt_int(priv, ct)
        assert params.p == inputs["p"]
        return

    if op == "mul_ciphertexts":
        params = elgamal.ElGamalParams(p=inputs["p"], g=2)
        out = elgamal.elgamal_mul_ciphertexts(
            params,
            (inputs["a"]["c1"], inputs["a"]["c2"]),
            (inputs["b"]["c1"], inputs["b"]["c2"]),
        )
        assert {"c1": out[0], "c2": out[1]} == expected
        return

    if op == "encrypt_bytes":
        _, pub, _ = _pub_priv_from_x(inputs["p"], inputs["g"], inputs["x"])
        label = bytes.fromhex(inputs["label_hex"])
        pt = bytes.fromhex(inputs["plaintext_hex"])
        c1, cbytes = elgamal.elgamal_encrypt_bytes(pub, pt, k=inputs["k"], label=label)
        assert c1 == expected["c1"]
        assert cbytes.hex() == expected["ciphertext_hex"]
        return

    if op == "decrypt_bytes":
        _, _, priv = _pub_priv_from_x(inputs["p"], inputs["g"], inputs["x"])
        label = bytes.fromhex(inputs["label_hex"])
        cbytes = bytes.fromhex(inputs["ciphertext_hex"])
        pt = elgamal.elgamal_decrypt_bytes(priv, inputs["c1"], cbytes, label=label)
        assert pt.hex() == expected
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    vectors_path = HERE / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    for v in data["vectors"]:
        _run_vector(v)


def test_roundtrip_many():
    params = elgamal.demo_params()
    pub, priv = elgamal.elgamal_keygen(params, x=101)

    for m in [1, 2, 3, 7, 42, 123, params.p - 1]:
        ct = elgamal.elgamal_encrypt_int(pub, m, k=17)
        assert elgamal.elgamal_decrypt_int(priv, ct) == m

    for _ in range(50):
        m = secrets.randbelow(params.p - 1) + 1
        ct = elgamal.elgamal_encrypt_int(pub, m)
        assert elgamal.elgamal_decrypt_int(priv, ct) == m


def test_probabilistic_ciphertexts_differ():
    params = elgamal.demo_params()
    pub, priv = elgamal.elgamal_keygen(params, x=17)

    m = 123
    ct1 = elgamal.elgamal_encrypt_int(pub, m, k=3)
    ct2 = elgamal.elgamal_encrypt_int(pub, m, k=5)
    assert ct1 != ct2
    assert elgamal.elgamal_decrypt_int(priv, ct1) == m
    assert elgamal.elgamal_decrypt_int(priv, ct2) == m


def test_rerandomization_preserves_message():
    params = elgamal.demo_params()
    pub, priv = elgamal.elgamal_keygen(params, x=37)

    m = 99
    ct = elgamal.elgamal_encrypt_int(pub, m, k=11)
    ct_r = elgamal.elgamal_rerandomize(pub, ct, r=23)
    assert ct != ct_r
    assert elgamal.elgamal_decrypt_int(priv, ct_r) == m


def test_homomorphic_multiplication():
    params = elgamal.demo_params()
    pub, priv = elgamal.elgamal_keygen(params, x=37)

    a, b = 7, 11
    cta = elgamal.elgamal_encrypt_int(pub, a, k=3)
    ctb = elgamal.elgamal_encrypt_int(pub, b, k=5)
    combined = elgamal.elgamal_mul_ciphertexts(params, cta, ctb)
    assert elgamal.elgamal_decrypt_int(priv, combined) == (a * b) % params.p


def test_reject_bad_inputs():
    params = elgamal.demo_params()
    pub, priv = elgamal.elgamal_keygen(params, x=37)

    try:
        elgamal.elgamal_encrypt_int(pub, 0, k=1)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    try:
        elgamal.elgamal_encrypt_int(pub, 1, k=0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass

    try:
        elgamal.elgamal_decrypt_int(priv, (0, 1))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_bytes_roundtrip_and_label():
    params = elgamal.demo_params()
    pub, priv = elgamal.elgamal_keygen(params, x=37)

    msg = b"hello"
    c1, cbytes = elgamal.elgamal_encrypt_bytes(pub, msg, k=9, label=b"demo")
    assert elgamal.elgamal_decrypt_bytes(priv, c1, cbytes, label=b"demo") == msg
    assert elgamal.elgamal_decrypt_bytes(priv, c1, cbytes, label=b"wrong") != msg


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_many()
    test_probabilistic_ciphertexts_differ()
    test_rerandomization_preserves_message()
    test_homomorphic_multiplication()
    test_reject_bad_inputs()
    test_bytes_roundtrip_and_label()
    print("all tests pass")
