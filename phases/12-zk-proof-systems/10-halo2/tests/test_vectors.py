import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CODE_DIR = ROOT / "code"
sys.path.insert(0, str(CODE_DIR))

import main as halo2  # noqa: E402


def _load_vectors():
    path = ROOT / "tests" / "vectors.json"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data.get("source"), str) and data["source"]
    vectors = data.get("vectors")
    assert isinstance(vectors, list)
    return vectors


def _run_vector(v):
    op = v["op"]
    if op == "f_add":
        got = int(halo2.F(v["a"]) + halo2.F(v["b"]))
        assert got == v["expected"]
        return
    if op == "f_mul":
        got = int(halo2.F(v["a"]) * halo2.F(v["b"]))
        assert got == v["expected"]
        return
    if op == "f_inv":
        got = int(halo2.F(v["a"]).inv())
        assert got == v["expected"]
        return
    if op == "f_div":
        got = int(halo2.F(v["a"]) / halo2.F(v["b"]))
        assert got == v["expected"]
        return
    if op == "decompose_3bit":
        got = list(halo2.decompose_3bit(v["value"]))
        assert got == v["expected"]
        return
    if op == "recompose_3bit":
        bits = v["bits"]
        got = halo2.recompose_3bit(bits[0], bits[1], bits[2])
        assert got == v["expected"]
        return
    if op == "prove_range_add_failures":
        failures = halo2.prove_range_add(v["a"], v["b"])
        assert len(failures) == v["expected"]
        return
    raise ValueError(f"unknown op: {op}")


def test_vectors():
    for v in _load_vectors():
        _run_vector(v)


def test_decompose_roundtrip_all_values():
    for x in range(8):
        bits = halo2.decompose_3bit(x)
        assert halo2.recompose_3bit(*bits) == x


def test_range_add_all_pairs_in_range():
    for a in range(8):
        for b in range(8):
            failures = halo2.prove_range_add(a, b)
            assert failures == []


def test_range_add_rejects_out_of_range():
    for a, b in [(-1, 0), (8, 0), (0, 9)]:
        try:
            halo2.prove_range_add(a, b)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for out-of-range input")


def test_mockprover_detects_bit_flip():
    cs, assignment, cols = halo2.build_witness_for_range_add(5, 6)
    assert halo2.MockProver(cs, assignment).check() == []

    broken = assignment.clone()
    broken.set_advice(cols["d0"], 0, 0 if int(assignment.get(cols["d0"], 0)) == 1 else 1)
    failures = halo2.MockProver(cs, broken).check()
    assert len(failures) >= 1


def run_all_tests():
    test_vectors()
    test_decompose_roundtrip_all_values()
    test_range_add_all_pairs_in_range()
    test_range_add_rejects_out_of_range()
    test_mockprover_detects_bit_flip()


if __name__ == "__main__":
    run_all_tests()
    print("all tests pass")

