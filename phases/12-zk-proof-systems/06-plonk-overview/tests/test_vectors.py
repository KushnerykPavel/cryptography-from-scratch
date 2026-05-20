import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    PlonkColumns,
    PlonkWitness,
    compute_grand_product_z,
    evaluation_domain,
    find_primitive_root_of_unity,
    gate_constraint_values,
    inv_mod,
    lagrange_interpolate,
    permutation_sigma_columns,
    poly_eval,
    toy_plonk_instance,
)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]

        if op == "inv_mod":
            try:
                got = inv_mod(v["a"], v["p"])
            except ValueError as exc:
                assert v.get("expected_error") == str(exc), (
                    f"inv_mod wrong error: got {exc!s}, expected {v.get('expected_error')}"
                )
                continue
        elif op == "find_primitive_root_of_unity":
            got = find_primitive_root_of_unity(v["p"], v["n"])
        elif op == "evaluation_domain":
            got = evaluation_domain(v["p"], v["n"], v["omega"])
        elif op == "lagrange_interpolate":
            got = lagrange_interpolate(v["xs"], v["ys"], v["p"])
        elif op == "gate_constraint_values_toy":
            inst = toy_plonk_instance(p=v["p"], n=4)
            got = gate_constraint_values(inst["cols"], inst["witness"], v["p"])
        elif op == "permutation_sigma_columns_toy":
            inst = toy_plonk_instance(p=v["p"], n=4)
            got = {
                "sigma_a": inst["sigma_a"],
                "sigma_b": inst["sigma_b"],
                "sigma_c": inst["sigma_c"],
            }
        elif op == "compute_grand_product_z_toy":
            inst = toy_plonk_instance(p=v["p"], n=4)
            got = compute_grand_product_z(
                inst["cols"],
                inst["witness"],
                inst["sigma_a"],
                inst["sigma_b"],
                inst["sigma_c"],
                inst["xs"],
                v["p"],
                beta=v["beta"],
                gamma=v["gamma"],
            )
        else:
            raise AssertionError(f"unknown op {op}")

        assert "expected" in v, f"{op} missing expected result"
        assert got == v["expected"], f"{op} failed: got {got}, expected {v['expected']}"


def test_interpolation_roundtrip_and_rejects_duplicates():
    p = 97
    omega = 22
    xs = evaluation_domain(p, 4, omega)
    ys = [3, 9, 0, 0]

    poly = lagrange_interpolate(xs, ys, p)
    for x, y in zip(xs, ys, strict=True):
        assert poly_eval(poly, x, p) == y

    try:
        lagrange_interpolate([1, 1], [2, 3], p)
        raise AssertionError("expected ValueError for duplicate xs")
    except ValueError as exc:
        assert str(exc) == "xs must be distinct"


def test_gate_constraints_fail_if_witness_is_wrong():
    inst = toy_plonk_instance()
    p = inst["p"]
    cols = inst["cols"]
    w = inst["witness"]

    ok = gate_constraint_values(cols, w, p)
    assert ok == [0, 0, 0, 0]

    w_bad = PlonkWitness(a=list(w.a), b=list(w.b), c=list(w.c))
    w_bad.c[1] = (w_bad.c[1] + 1) % p
    bad = gate_constraint_values(cols, w_bad, p)
    assert bad[1] != 0


def test_permutation_grand_product_detects_copy_constraint_violation():
    inst = toy_plonk_instance()
    p = inst["p"]
    cols = inst["cols"]
    xs = inst["xs"]
    sigma_a = inst["sigma_a"]
    sigma_b = inst["sigma_b"]
    sigma_c = inst["sigma_c"]

    w = inst["witness"]
    z = compute_grand_product_z(cols, w, sigma_a, sigma_b, sigma_c, xs, p, beta=7, gamma=9)
    assert z[0] == 1
    assert z[-1] == 1

    w_bad = PlonkWitness(a=list(w.a), b=list(w.b), c=list(w.c))
    w_bad.b[1] = (w_bad.b[1] + 1) % p
    z_bad = compute_grand_product_z(cols, w_bad, sigma_a, sigma_b, sigma_c, xs, p, beta=7, gamma=9)
    assert z_bad[-1] != 1


def test_permutation_sigma_columns_rejects_invalid_cycles():
    p = 97
    n = 4
    omega = 22
    xs = evaluation_domain(p, n, omega)

    try:
        permutation_sigma_columns(n, xs, p, copy_cycles=[[0]])
        raise AssertionError("expected ValueError for cycle of length < 2")
    except ValueError as exc:
        assert str(exc) == "each copy cycle must have at least 2 slots"

    try:
        permutation_sigma_columns(n, xs, p, copy_cycles=[[-1, 0]])
        raise AssertionError("expected ValueError for out-of-range slot index")
    except ValueError as exc:
        assert str(exc) == "slot index out of range"


if __name__ == "__main__":
    test_vectors()
    test_interpolation_roundtrip_and_rejects_duplicates()
    test_gate_constraints_fail_if_witness_is_wrong()
    test_permutation_grand_product_detects_copy_constraint_violation()
    test_permutation_sigma_columns_rejects_invalid_cycles()
    print("all tests pass")

