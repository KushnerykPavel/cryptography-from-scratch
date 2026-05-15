import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (
    GF2N,
    aes_mix_single_column,
    aes_mul,
    aes_xtime,
    gf2n_add,
    gf2n_div,
    gf2n_field_report,
    gf2n_inverse,
    gf2n_is_generator,
    gf2n_mul,
    gf2n_multiplicative_order,
    gf2n_pow,
    is_irreducible,
    poly_add,
    poly_degree,
    poly_divmod,
    poly_gcd,
    poly_mod,
    poly_mul,
    poly_to_terms,
)


def normalize(value):
    if isinstance(value, GF2N):
        return value.value
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [normalize(v) for v in value]
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        try:
            if op == "poly_degree":
                got = poly_degree(v["poly"])
            elif op == "poly_to_terms":
                got = poly_to_terms(v["poly"])
            elif op == "poly_add":
                got = poly_add(v["a"], v["b"])
            elif op == "poly_mul":
                got = poly_mul(v["a"], v["b"])
            elif op == "poly_divmod":
                got = poly_divmod(v["dividend"], v["divisor"])
            elif op == "poly_mod":
                got = poly_mod(v["poly"], v["modulus"])
            elif op == "poly_gcd":
                got = poly_gcd(v["a"], v["b"])
            elif op == "is_irreducible":
                got = is_irreducible(v["modulus"])
            elif op == "gf2n_add":
                got = gf2n_add(v["a"], v["b"], v["modulus"])
            elif op == "gf2n_mul":
                got = gf2n_mul(v["a"], v["b"], v["modulus"])
            elif op == "gf2n_pow":
                got = gf2n_pow(v["a"], v["exponent"], v["modulus"])
            elif op == "gf2n_inverse":
                got = gf2n_inverse(v["a"], v["modulus"])
            elif op == "gf2n_div":
                got = gf2n_div(v["a"], v["b"], v["modulus"])
            elif op == "gf2n_multiplicative_order":
                got = gf2n_multiplicative_order(v["a"], v["modulus"])
            elif op == "gf2n_is_generator":
                got = gf2n_is_generator(v["a"], v["modulus"])
            elif op == "gf2n_expression":
                a = GF2N(v["a"], v["modulus"])
                b = GF2N(v["b"], v["modulus"])
                c = GF2N(v["c"], v["modulus"])
                got = (a + b) * c
            elif op == "gf2n_field_report":
                got = gf2n_field_report(v["modulus"])
            elif op == "aes_xtime":
                got = aes_xtime(v["byte"])
            elif op == "aes_mul":
                got = aes_mul(v["a"], v["b"])
            elif op == "aes_mix_single_column":
                got = aes_mix_single_column(v["column"])
            else:
                raise AssertionError(f"unknown op {op}")
        except ValueError as exc:
            assert v.get("expected_error") == str(exc), (
                f"{op} wrong error: got {exc!s}, expected {v.get('expected_error')}"
            )
            continue

        assert normalize(got) == normalize(v["expected"]), (
            f"{op} failed: got {normalize(got)}, expected {normalize(v['expected'])}"
        )


if __name__ == "__main__":
    test_vectors()
    print("all vectors pass")
