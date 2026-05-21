import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as ntru  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    data = _load_vectors()
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "poly_mul_cyclic":
            got = ntru.poly_mul_cyclic(inputs["a"], inputs["b"], inputs["N"], mod=inputs.get("mod"))
            assert got == expected
        elif op == "poly_center_lift":
            got = ntru.poly_center_lift(inputs["a"], inputs["mod"])
            assert got == expected
        elif op == "poly_inverse_mod_prime":
            got = ntru.poly_inverse_mod_prime(inputs["f"], inputs["N"], inputs["prime"])
            assert got == expected
        elif op == "ntru_keygen_deterministic":
            params = ntru.NTRUParams(N=inputs["N"], p=inputs["p"], q=inputs["q"])
            pub, priv = ntru.ntru_keygen_deterministic(params, inputs["seed"])
            assert pub.h == expected["h"]
            assert priv.f == expected["f"]
            assert priv.f_inv_p == expected["f_inv_p"]
        elif op == "ntru_encrypt":
            params = ntru.NTRUParams(N=inputs["N"], p=inputs["p"], q=inputs["q"])
            pub = ntru.NTRUPublicKey(params=params, h=inputs["h"])
            got = ntru.ntru_encrypt(pub, inputs["m"], inputs["r"])
            assert got == expected
        elif op == "ntru_decrypt":
            params = ntru.NTRUParams(N=inputs["N"], p=inputs["p"], q=inputs["q"])
            priv = ntru.NTRUPrivateKey(params=params, f=inputs["f"], f_inv_p=inputs["f_inv_p"])
            got = ntru.ntru_decrypt(priv, inputs["e"])
            assert got == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_inverse_is_identity_mod_p_and_q_for_demo_private_key():
    params = ntru._demo_params()
    pub, priv = ntru._demo_keypair()

    inv_p = ntru.poly_inverse_mod_prime(priv.f, params.N, params.p)
    check_p = ntru.poly_mul_cyclic(ntru.poly_mod(priv.f, params.p), inv_p, params.N, mod=params.p)
    assert check_p == [1] + [0] * (params.N - 1)

    inv_q = ntru.poly_inverse_mod_prime(priv.f, params.N, params.q)
    check_q = ntru.poly_mul_cyclic(ntru.poly_mod(priv.f, params.q), inv_q, params.N, mod=params.q)
    assert check_q == [1] + [0] * (params.N - 1)

    assert pub.params == params
    assert priv.params == params


def test_encrypt_decrypt_roundtrip_demo():
    params = ntru._demo_params()
    pub, priv = ntru._demo_keypair()
    m = ntru._demo_message(params)
    r = ntru._demo_blinding(params)
    e = ntru.ntru_encrypt(pub, m, r)
    m2 = ntru.ntru_decrypt(priv, e)

    assert m2 == ntru.poly_center_lift(ntru.poly_mod(m, params.p), params.p)


def test_poly_inverse_rejects_noninvertible():
    params = ntru._demo_params()
    f = [0] * params.N
    try:
        ntru.poly_inverse_mod_prime(f, params.N, params.p)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_rejects_wrong_lengths():
    params = ntru._demo_params()
    pub, priv = ntru._demo_keypair()
    try:
        ntru.poly_mul_cyclic([1, 2], [3, 4], params.N, mod=params.q)
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        ntru.ntru_encrypt(pub, [0] * (params.N - 1), [0] * params.N)
        assert False, "expected ValueError"
    except ValueError:
        pass

    try:
        ntru.ntru_decrypt(priv, [0] * (params.N - 1))
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_inverse_is_identity_mod_p_and_q_for_demo_private_key()
    test_encrypt_decrypt_roundtrip_demo()
    test_poly_inverse_rejects_noninvertible()
    test_rejects_wrong_lengths()
    print("all tests pass")

