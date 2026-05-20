import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    build_toy_circuit_witness,
    check_gate_constraints,
    check_permutation_constraints,
    compute_grand_product_z,
    derive_permutation_mapping,
    eval_poly,
    lagrange_interpolate,
    modinv,
    primitive_root_of_unity,
    prove_and_verify_toy_plonk,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "modinv":
            got = modinv(v["a"], v["p"])
        elif op == "eval_poly":
            got = eval_poly(v["coeffs"], v["x"], v["p"])
        elif op == "lagrange_interpolate":
            got = lagrange_interpolate(v["xs"], v["ys"], v["p"])
        elif op == "derive_permutation_mapping":
            got = derive_permutation_mapping(v["n"])
        elif op == "compute_grand_product_z":
            p = v["p"]
            n = v["n"]
            w = primitive_root_of_unity(p, n)
            roots = [pow(w, i, p) for i in range(n)]
            witness = build_toy_circuit_witness(p, n)
            perm = derive_permutation_mapping(n)
            got = compute_grand_product_z(
                witness["a"],
                witness["b"],
                witness["c"],
                perm,
                v["beta"],
                v["gamma"],
                roots,
                p,
            )
        elif op == "prove_and_verify_toy_plonk":
            got = prove_and_verify_toy_plonk(v["p"], v["n"])
        else:
            raise AssertionError(f"unknown op {op}")

        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_modinv_roundtrip():
    p = 97
    for a in range(1, p):
        inv = modinv(a, p)
        assert (a * inv) % p == 1


def test_root_of_unity_order():
    p = 97
    n = 8
    w = primitive_root_of_unity(p, n)
    assert pow(w, n, p) == 1
    assert pow(w, n // 2, p) != 1


def test_lagrange_interpolation_roundtrip():
    p = 97
    xs = [0, 1, 2, 3]
    coeffs = [10, 3, 4, 9]
    ys = [eval_poly(coeffs, x, p) for x in xs]
    got = lagrange_interpolate(xs, ys, p)
    for x, y in zip(xs, ys):
        assert eval_poly(got, x, p) == y % p


def test_gate_constraints_reject_invalid_witness():
    p = 97
    n = 8
    w = primitive_root_of_unity(p, n)
    roots = [pow(w, i, p) for i in range(n)]
    witness = build_toy_circuit_witness(p, n)
    assert check_gate_constraints(witness, roots, p)

    witness_bad = {k: list(v) if isinstance(v, list) else v for k, v in witness.items()}
    witness_bad["c"][0] = (witness_bad["c"][0] + 1) % p
    assert not check_gate_constraints(witness_bad, roots, p)


def test_permutation_constraints_reject_broken_copy():
    p = 97
    n = 8
    w = primitive_root_of_unity(p, n)
    roots = [pow(w, i, p) for i in range(n)]
    witness = build_toy_circuit_witness(p, n)
    perm = derive_permutation_mapping(n)
    beta, gamma = 7, 13

    assert check_permutation_constraints(witness, perm, roots, beta, gamma, p)

    witness_bad = {k: list(v) if isinstance(v, list) else v for k, v in witness.items()}
    witness_bad["b"][1] = (witness_bad["b"][1] + 2) % p
    assert not check_permutation_constraints(witness_bad, perm, roots, beta, gamma, p)


if __name__ == "__main__":
    test_vectors()
    test_modinv_roundtrip()
    test_root_of_unity_order()
    test_lagrange_interpolation_roundtrip()
    test_gate_constraints_reject_invalid_witness()
    test_permutation_constraints_reject_broken_copy()
    print("all tests pass")

