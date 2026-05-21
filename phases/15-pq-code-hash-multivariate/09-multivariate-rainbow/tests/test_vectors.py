import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.append(CODE_DIR)

import main as rainbow  # noqa: E402


def _load_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def _b(s):
    return s.encode("utf-8")


def test_vectors():
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]

        if op == "mod_inv":
            got = rainbow.mod_inv(v["a"], v["p"])
            assert got == v["expected"]

        elif op == "solve_linear_system":
            got = rainbow.solve_linear_system(v["A"], v["b"], v["p"])
            assert got == v["expected"]

        elif op == "hash_to_field_elems":
            got = rainbow.hash_to_field_elems(_b(v["message"]), v["p"], v["m"])
            assert got == v["expected"]

        elif op == "rainbow_toy_sign":
            pk, sk = rainbow.rainbow_toy_keygen(_b(v["seed"]), params=rainbow.RainbowToyParams())
            got = rainbow.rainbow_toy_sign(sk, _b(v["message"]))
            assert got == v["expected"]
            assert rainbow.rainbow_toy_verify(pk, _b(v["message"]), got) is True

        elif op == "rainbow_toy_verify":
            pk, _ = rainbow.rainbow_toy_keygen(_b(v["seed"]), params=rainbow.RainbowToyParams())
            got = rainbow.rainbow_toy_verify(pk, _b(v["message"]), v["signature"])
            assert got == v["expected"]

        else:
            raise ValueError(f"unknown op: {op}")


def test_mod_inv_roundtrip():
    p = 31
    for a in range(1, p):
        inv = rainbow.mod_inv(a, p)
        assert (a * inv) % p == 1


def test_affine_inverse_roundtrip():
    params = rainbow.RainbowToyParams()
    rng = random.Random(123)
    A = rainbow.random_invertible_matrix(rng, params.n(), params.p)
    b = [rng.randrange(params.p) for _ in range(params.n())]
    T = rainbow.AffineMap(A, b, params.p)
    Tinv = T.inverse()

    x = [rng.randrange(params.p) for _ in range(params.n())]
    assert Tinv.apply(T.apply(x)) == [xi % params.p for xi in x]


def test_sign_verify_and_tamper():
    params = rainbow.RainbowToyParams()
    pk, sk = rainbow.rainbow_toy_keygen(b"rainbow-toy-seed", params=params)
    msg = b"tamper-test"

    sig = rainbow.rainbow_toy_sign(sk, msg)
    assert rainbow.rainbow_toy_verify(pk, msg, sig) is True

    bad = sig[:]
    bad[0] = (bad[0] + 1) % params.p
    assert rainbow.rainbow_toy_verify(pk, msg, bad) is False


if __name__ == "__main__":
    test_vectors()
    test_mod_inv_roundtrip()
    test_affine_inverse_roundtrip()
    test_sign_verify_and_tamper()
    print("all tests pass")
