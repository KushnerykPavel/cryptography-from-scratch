import json
import os
import random
import sys
from contextlib import contextmanager

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as r1cs  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _terms(terms_json):
    return [(int(i), int(c)) for i, c in terms_json]


def _constraint(con_json):
    return {"A": _terms(con_json["A"]), "B": _terms(con_json["B"]), "C": _terms(con_json["C"])}


def _constraints(cons_json):
    return [_constraint(c) for c in cons_json]


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        p = int(vec["p"])

        if op == "inv_mod":
            got = r1cs.inv_mod(int(vec["a"]), p)
        elif op == "eval_lc":
            got = r1cs.eval_lc(_terms(vec["terms"]), [int(x) for x in vec["witness"]], p)
        elif op == "check_constraint":
            got = r1cs.check_constraint(
                _constraint(vec["constraint"]), [int(x) for x in vec["witness"]], p
            )
        elif op == "check_r1cs":
            got = r1cs.check_r1cs(
                _constraints(vec["constraints"]), [int(x) for x in vec["witness"]], p
            )
        elif op == "first_unsatisfied":
            got = r1cs.first_unsatisfied(
                _constraints(vec["constraints"]), [int(x) for x in vec["witness"]], p
            )
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

        assert got == vec["expected"], f"vector failed: op={op}"


def test_inv_mod_roundtrip():
    p = 101
    rng = random.Random(0)
    for _ in range(50):
        a = rng.randrange(1, p)
        inv = r1cs.inv_mod(a, p)
        assert (a * inv) % p == 1


def test_inv_mod_rejects_zero():
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        r1cs.inv_mod(0, 101)


def test_normalize_witness_contract():
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        r1cs.normalize_witness([], 101)
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        r1cs.normalize_witness([0, 123], 101)

    w = r1cs.normalize_witness([1, -1, 102], 101)
    assert w == [1, 100, 1]


def test_eval_lc_rejects_bad_index():
    cm = pytest.raises(IndexError) if pytest else _raises(IndexError)
    with cm:
        r1cs.eval_lc([(2, 1)], [1], 101)


def test_check_r1cs_matches_example_builder():
    p, constraints, w = r1cs.r1cs_for_out_equals_xplusy_times_xminusy()
    assert r1cs.check_r1cs(constraints, w, p) is True

    w_bad = r1cs.normalize_witness(w, p)
    w_bad[3] = (w_bad[3] + 1) % p
    assert r1cs.check_r1cs(constraints, w_bad, p) is False
    assert r1cs.first_unsatisfied(constraints, w_bad, p) == 0


if __name__ == "__main__":
    if pytest:
        raise SystemExit(pytest.main([__file__, "-q"]))

    tests = [
        test_vectors,
        test_inv_mod_roundtrip,
        test_inv_mod_rejects_zero,
        test_normalize_witness_contract,
        test_eval_lc_rejects_bad_index,
        test_check_r1cs_matches_example_builder,
    ]
    for t in tests:
        t()
    print("all tests pass")
