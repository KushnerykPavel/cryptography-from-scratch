import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.join(HERE, "..", "code")
sys.path.insert(0, os.path.abspath(CODE_DIR))

import main as falcon_toy  # noqa: E402


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


def _dispatch(vec):
    op = vec["op"]
    n = vec.get("n")
    q = vec.get("q")

    if op == "poly_mul_mod_phi_q":
        return falcon_toy.poly_mul_mod_phi_q(vec["a"], vec["b"], q, n)

    if op == "poly_inv_mod_phi_q":
        return falcon_toy.poly_inv_mod_phi_q(vec["f"], q, n)

    if op == "ntru_public_key_h":
        return falcon_toy.ntru_public_key_h(vec["f"], vec["g"], q, n)

    if op == "solve_ntru_equation_small":
        F, G = falcon_toy.solve_ntru_equation_small(vec["f"], vec["g"], q, n, max_abs=vec.get("max_abs", 2))
        return {"F": F, "G": G}

    if op == "hash_to_point":
        return falcon_toy.hash_to_point(_b(vec["msg_hex"]), _b(vec["salt_hex"]), n, q)

    if op == "toy_sign":
        sk, _ = falcon_toy.toy_keypair(n, q)
        _, s2 = falcon_toy.toy_sign(_b(vec["msg_hex"]), sk, _b(vec["salt_hex"]))
        return {"s2": s2}

    if op == "toy_verify":
        _, pk = falcon_toy.toy_keypair(n, q)
        sig = (_b(vec["salt_hex"]), vec["s2"])
        return falcon_toy.toy_verify(_b(vec["msg_hex"]), sig, pk, beta2=vec.get("beta2", falcon_toy.TOY_BETA2))

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    for vec in _load_vectors():
        got = _dispatch(vec)
        expected = vec["expected"]
        assert got == expected


def test_poly_inv_roundtrip():
    sk, _ = falcon_toy.toy_keypair(falcon_toy.TOY_N, falcon_toy.TOY_Q)
    inv_f = falcon_toy.poly_inv_mod_phi_q(sk.f, sk.q, sk.n)
    one = falcon_toy.poly_mul_mod_phi_q(sk.f, inv_f, sk.q, sk.n)
    assert one == [1] + [0] * (sk.n - 1)


def test_sign_verify_roundtrip_and_tamper():
    sk, pk = falcon_toy.toy_keypair(falcon_toy.TOY_N, falcon_toy.TOY_Q)
    msg = b"hello, falcon"
    salt = falcon_toy.hashlib.sha256(b"toy-falcon-salt" + msg).digest()[:16]
    sig = falcon_toy.toy_sign(msg, sk, salt=salt)
    assert falcon_toy.toy_verify(msg, sig, pk, beta2=falcon_toy.TOY_BETA2)
    assert not falcon_toy.toy_verify(msg + b"!", sig, pk, beta2=falcon_toy.TOY_BETA2)


if __name__ == "__main__":
    test_vectors()
    test_poly_inv_roundtrip()
    test_sign_verify_roundtrip_and_tamper()
    print("all tests pass")
