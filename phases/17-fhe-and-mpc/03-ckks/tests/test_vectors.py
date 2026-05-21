import json
import random
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
CODE_DIR = (HERE / ".." / "code").resolve()
sys.path.insert(0, str(CODE_DIR))

import main as ckks  # noqa: E402


def _approx_equal_list(a, b, *, tol):
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if abs(float(x) - float(y)) > tol:
            return False
    return True


def test_vectors():
    vectors_path = HERE / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]

        if op == "round_nearest_int":
            got = ckks.round_nearest_int(float(v["x"]))
            assert got == v["expected"]

        elif op == "round_div_int":
            got = ckks.round_div_int(int(v["num"]), int(v["den"]))
            assert got == v["expected"]

        elif op == "ckks_encode":
            pt = ckks.ckks_encode(v["values"], scale=int(v["scale"]))
            assert pt.__dict__ == v["expected"]

        elif op == "ckks_decode":
            pt = ckks.Plaintext(slots=v["pt"]["slots"], scale=int(v["pt"]["scale"]))
            got = ckks.ckks_decode(pt)
            assert _approx_equal_list(got, v["expected"], tol=1e-12)

        elif op == "ckks_encrypt":
            pt = ckks.Plaintext(slots=v["pt"]["slots"], scale=int(v["pt"]["scale"]))
            ct = ckks.ckks_encrypt(
                pt,
                noise_bound=int(v["noise_bound"]),
                seed=int(v["seed"]),
                level=int(v["level"]),
            )
            assert ct.__dict__ == v["expected"]

        elif op == "ckks_add":
            a = ckks.Ciphertext(**v["ct_a"])
            b = ckks.Ciphertext(**v["ct_b"])
            got = ckks.ckks_add(a, b)
            assert got.__dict__ == v["expected"]

        elif op == "ckks_mul":
            a = ckks.Ciphertext(**v["ct_a"])
            b = ckks.Ciphertext(**v["ct_b"])
            got = ckks.ckks_mul(a, b)
            assert got.__dict__ == v["expected"]

        elif op == "ckks_rescale":
            ct = ckks.Ciphertext(**v["ct"])
            got = ckks.ckks_rescale(ct, factor=int(v["factor"]))
            assert got.__dict__ == v["expected"]

        else:
            raise AssertionError(f"unknown op: {op}")


def test_encode_decode_roundtrip_bound():
    rng = random.Random(2026)
    scale = 2**14

    for _ in range(50):
        values = [rng.uniform(-10.0, 10.0) for _ in range(8)]
        pt = ckks.ckks_encode(values, scale=scale)
        decoded = ckks.ckks_decode(pt)

        max_err = ckks.approx_linf_error(decoded, values)
        assert max_err <= (0.5 / scale) + 1e-12


def test_encrypt_add_mul_rescale_properties():
    rng = random.Random(7)
    scale = 2**12

    for i in range(25):
        values = [rng.uniform(-2.0, 2.0) for _ in range(6)]
        pt = ckks.ckks_encode(values, scale=scale)
        decoded_pt = ckks.ckks_decode(pt)

        ct = ckks.ckks_encrypt(pt, noise_bound=5, seed=1000 + i, level=0)
        dec_ct = ckks.ckks_decode(ckks.ckks_decrypt(ct))
        assert ckks.approx_linf_error(dec_ct, decoded_pt) <= (5 / scale) + 1e-12

        ct_sum = ckks.ckks_add(ct, ct)
        dec_sum = ckks.ckks_decode(ckks.ckks_decrypt(ct_sum))
        expect_sum = [2 * x for x in decoded_pt]
        assert ckks.approx_linf_error(dec_sum, expect_sum) <= (10 / scale) + 1e-12

        ct_prod = ckks.ckks_mul(ct, ct)
        assert ct_prod.scale == scale * scale
        ct_rs = ckks.ckks_rescale(ct_prod, factor=scale)
        assert ct_rs.scale == scale
        assert ct_rs.level == 1

        dec_prod = ckks.ckks_decode(ckks.ckks_decrypt(ct_rs))
        expect_prod = [x * x for x in decoded_pt]
        assert ckks.approx_linf_error(dec_prod, expect_prod) <= 0.2


def test_rejects_scale_mismatch():
    a = ckks.Ciphertext(slots=[1], noise=[0], scale=8, level=0)
    b = ckks.Ciphertext(slots=[1], noise=[0], scale=16, level=0)
    try:
        ckks.ckks_add(a, b)
    except ValueError as error:
        assert str(error) == "ckks_add: scale mismatch"
    else:
        raise AssertionError("expected scale mismatch error")


def test_rejects_rescale_factor_not_dividing_scale():
    ct = ckks.Ciphertext(slots=[10], noise=[0], scale=12, level=0)
    try:
        ckks.ckks_rescale(ct, factor=5)
    except ValueError as error:
        assert str(error) == "ckks_rescale: factor must divide ct.scale exactly in this toy model"
    else:
        raise AssertionError("expected factor divisibility error")


if __name__ == "__main__":
    test_vectors()
    test_encode_decode_roundtrip_bound()
    test_encrypt_add_mul_rescale_properties()
    test_rejects_scale_mismatch()
    test_rejects_rescale_factor_not_dividing_scale()
    print("all tests pass")

