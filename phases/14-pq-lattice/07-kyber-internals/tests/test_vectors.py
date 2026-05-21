import json
import os
import random
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.append(CODE_DIR)

import main as kyber  # noqa: E402


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _sparse_poly(n, terms, q):
    poly = [0] * n
    for idx, val in terms:
        if not (0 <= idx < n):
            raise ValueError("term index out of range")
        poly[idx] = val % q
    return poly


def _expand_expected(n, terms, q):
    return _sparse_poly(n, terms, q)


def test_vectors():
    data = _load_vectors()
    assert "vectors" in data and isinstance(data["vectors"], list)

    for v in data["vectors"]:
        op = v["op"]

        if op == "compress_coeff":
            got = kyber.compress_coeff(v["c"], d=v["d"], q=v["q"])
            assert got == v["expected"]
        elif op == "decompress_coeff":
            got = kyber.decompress_coeff(v["t"], d=v["d"], q=v["q"])
            assert got == v["expected"]
        elif op == "pack_bits":
            got_hex = kyber.pack_bits(v["values"], bits=v["bits"]).hex()
            assert got_hex == v["expected_hex"]
        elif op == "unpack_bits":
            got = kyber.unpack_bits(bytes.fromhex(v["data_hex"]), bits=v["bits"], count=v["count"])
            assert got == v["expected"]
        elif op == "compress_poly":
            got_hex = kyber.compress_poly(v["coeffs"], d=v["d"], q=v["q"]).hex()
            assert got_hex == v["expected_hex"]
        elif op == "decompress_poly":
            got = kyber.decompress_poly(
                bytes.fromhex(v["data_hex"]), d=v["d"], count=v["count"], q=v["q"]
            )
            assert got == v["expected"]
        elif op == "mul_by_y_in_mod_y128_plus_1":
            n = v["n"]
            q = v["q"]
            poly = _sparse_poly(n, v["poly_terms"], q=q)
            got = kyber.mul_by_y_in_mod_y128_plus_1(poly, q=q)
            expected = _expand_expected(n, v["expected_terms"], q=q)
            assert got == expected
        elif op == "poly_mul_schoolbook_negacyclic":
            n = v["n"]
            q = v["q"]
            a = _sparse_poly(n, v["a_terms"], q=q)
            b = _sparse_poly(n, v["b_terms"], q=q)
            got = kyber.poly_mul_schoolbook_negacyclic(a, b, q=q)
            expected = _expand_expected(n, v["expected_terms"], q=q)
            assert got == expected
        elif op == "negacyclic_mul_128_via_twist":
            n = v["n"]
            q = v["q"]
            assert n == kyber.N_HALF
            a = _sparse_poly(n, v["a_terms"], q=q)
            b = _sparse_poly(n, v["b_terms"], q=q)
            got = kyber.negacyclic_mul_128_via_twist(a, b, q=q)
            expected = _expand_expected(n, v["expected_terms"], q=q)
            assert got == expected
        elif op == "poly_mul_kyber_style_ntt_256":
            n = v["n"]
            q = v["q"]
            assert n == kyber.N
            a = _sparse_poly(n, v["a_terms"], q=q)
            b = _sparse_poly(n, v["b_terms"], q=q)
            got = kyber.poly_mul_kyber_style_ntt_256(a, b, q=q)
            expected = _expand_expected(n, v["expected_terms"], q=q)
            assert got == expected
        else:
            raise AssertionError(f"unknown op: {op}")


def test_negacyclic_128_ntt_matches_schoolbook_random():
    q = kyber.Q
    rng = random.Random(2026)
    for _ in range(30):
        a = [rng.randrange(0, q) for _ in range(kyber.N_HALF)]
        b = [rng.randrange(0, q) for _ in range(kyber.N_HALF)]
        got = kyber.negacyclic_mul_128_via_twist(a, b, q=q)
        expected = kyber.poly_mul_schoolbook_negacyclic(a, b, q=q)
        assert got == expected


def test_negacyclic_256_ntt_matches_schoolbook_random():
    q = kyber.Q
    rng = random.Random(2027)
    for _ in range(10):
        a = [rng.randrange(0, q) for _ in range(kyber.N)]
        b = [rng.randrange(0, q) for _ in range(kyber.N)]
        got = kyber.poly_mul_kyber_style_ntt_256(a, b, q=q)
        expected = kyber.poly_mul_schoolbook_negacyclic(a, b, q=q)
        assert got == expected


def test_compress_decompress_error_bound():
    q = kyber.Q
    rng = random.Random(2028)
    coeffs = [rng.randrange(0, q) for _ in range(256)]
    for d in [4, 5, 10, 11]:
        blob = kyber.compress_poly(coeffs, d=d, q=q)
        recovered = kyber.decompress_poly(blob, d=d, count=len(coeffs), q=q)
        err = kyber.poly_max_abs_error(coeffs, recovered, q=q)
        assert err <= (q // (1 << (d + 1))) + 2


def test_pack_unpack_roundtrip_random():
    rng = random.Random(2029)
    for bits in [1, 2, 3, 4, 5, 10, 11]:
        mask = (1 << bits) - 1
        values = [rng.randrange(0, mask + 1) for _ in range(50)]
        blob = kyber.pack_bits(values, bits=bits)
        got = kyber.unpack_bits(blob, bits=bits, count=len(values))
        assert got == values


if __name__ == "__main__":
    test_vectors()
    test_negacyclic_128_ntt_matches_schoolbook_random()
    test_negacyclic_256_ntt_matches_schoolbook_random()
    test_compress_decompress_error_bound()
    test_pack_unpack_roundtrip_random()
    print("all tests pass")

