import json
import random
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = (HERE / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as bfv  # noqa: E402


def _params_from_dict(d):
    return bfv.Params(
        n=int(d["n"]),
        q=int(d["q"]),
        t=int(d["t"]),
        delta=int(d["delta"]),
        relin_base=int(d["relin_base"]),
    )


def test_vectors():
    vectors_path = HERE / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]

        if op == "round_div":
            got = bfv.round_div(int(v["num"]), int(v["den"]))
            assert got == v["expected"]

        elif op == "poly_mul_negacyclic_int":
            got = bfv.poly_mul_negacyclic_int(v["a"], v["b"])
            assert got == v["expected"]

        elif op == "poly_mul_negacyclic_mod":
            got = bfv.poly_mul_negacyclic(v["a"], v["b"], int(v["q"]))
            assert got == v["expected"]

        elif op == "digits_for_base":
            got = bfv.digits_for_base(int(v["q"]), int(v["base"]))
            assert got == v["expected"]

        elif op == "poly_decompose_base":
            got = bfv.poly_decompose_base(v["a"], int(v["base"]), int(v["digits"]))
            assert got == v["expected"]

        elif op == "bfv_encrypt":
            params = _params_from_dict(v["params"])
            rng = random.Random(int(v["seed"]))
            ct = bfv.bfv_encrypt(params, v["s"], v["m"], rng)
            assert {"c0": ct.c0, "c1": ct.c1} == v["expected"]

        elif op == "bfv_decrypt":
            params = _params_from_dict(v["params"])
            ct = bfv.Ciphertext(c0=v["ct"]["c0"], c1=v["ct"]["c1"])
            got = bfv.bfv_decrypt(params, v["s"], ct)
            assert got == v["expected"]

        elif op == "bfv_add":
            params = _params_from_dict(v["params"])
            a = bfv.Ciphertext(**v["ct_a"])
            b = bfv.Ciphertext(**v["ct_b"])
            got = bfv.bfv_add(params, a, b)
            assert got.__dict__ == v["expected"]

        elif op == "bfv_mul_raw":
            params = _params_from_dict(v["params"])
            a = bfv.Ciphertext(**v["ct_a"])
            b = bfv.Ciphertext(**v["ct_b"])
            got = bfv.bfv_mul_raw(params, a, b)
            assert got.__dict__ == v["expected"]

        elif op == "bfv_decrypt3":
            params = _params_from_dict(v["params"])
            ct = bfv.Ciphertext3(**v["ct"])
            got = bfv.bfv_decrypt3(params, v["s"], ct)
            assert got == v["expected"]

        elif op == "bfv_relinearize":
            params = _params_from_dict(v["params"])
            rng = random.Random(int(v["rlk_seed"]))
            s = [1, 0, -1, 1, 0, 0, 1, -1]
            rlk = bfv.bfv_relin_keygen(params, s, rng)
            ct3 = bfv.Ciphertext3(**v["ct3"])
            got = bfv.bfv_relinearize(params, ct3, rlk)
            assert got.__dict__ == v["expected"]

        elif op == "bfv_mul":
            params = _params_from_dict(v["params"])
            rng = random.Random(int(v["rlk_seed"]))
            rlk = bfv.bfv_relin_keygen(params, v["s"], rng)
            a = bfv.Ciphertext(**v["ct_a"])
            b = bfv.Ciphertext(**v["ct_b"])
            ct = bfv.bfv_mul(params, a, b, rlk)
            got = bfv.bfv_decrypt(params, v["s"], ct)
            assert got == v["expected_dec"]

        elif op == "bfv_modulus_switch":
            params = _params_from_dict(v["params"])
            ct = bfv.Ciphertext(**v["ct"])
            got = bfv.bfv_modulus_switch(params, ct, int(v["q_new"]))
            assert got.__dict__ == v["expected"]

        else:
            raise AssertionError(f"unknown op: {op}")


def test_roundtrip_add_mul_properties():
    params = bfv.Params(n=8, q=40961, t=17, delta=40961 // 17, relin_base=64)
    rng = random.Random(2026)
    s = bfv.bfv_keygen(params, rng)
    rlk = bfv.bfv_relin_keygen(params, s, rng)

    for _ in range(25):
        m1 = [rng.randrange(0, 5) for _ in range(params.n)]
        m2 = [rng.randrange(0, 5) for _ in range(params.n)]
        ct1 = bfv.bfv_encrypt(params, s, m1, rng)
        ct2 = bfv.bfv_encrypt(params, s, m2, rng)

        dec_add = bfv.bfv_decrypt(params, s, bfv.bfv_add(params, ct1, ct2))
        assert dec_add == [(x + y) % params.t for x, y in zip(m1, m2)]

        dec_mul = bfv.bfv_decrypt(params, s, bfv.bfv_mul(params, ct1, ct2, rlk))
        expect_mul = bfv.poly_mod(bfv.poly_mul_negacyclic_int(m1, m2), params.t)
        assert dec_mul == expect_mul


def test_rejects_bad_params():
    try:
        bfv.bfv_keygen(
            bfv.Params(n=7, q=97, t=17, delta=97 // 17, relin_base=2),
            random.Random(0),
        )
    except ValueError as error:
        assert str(error) == "n must be a power of two"
    else:
        raise AssertionError("expected params validation error")


if __name__ == "__main__":
    test_vectors()
    test_roundtrip_add_mul_properties()
    test_rejects_bad_params()
    print("all tests pass")
