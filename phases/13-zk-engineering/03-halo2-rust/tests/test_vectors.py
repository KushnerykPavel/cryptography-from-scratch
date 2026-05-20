import json
import os
import sys


HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as lesson  # noqa: E402


def _load_vectors() -> dict:
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector(vector: dict) -> None:
    op = vector["op"]

    if op == "mul_residual":
        got = lesson.mul_residual(vector["a"], vector["b"], vector["c"])
        assert got == vector["expected"]
        return

    if op == "vanishing_product":
        got = lesson.vanishing_product(vector["x"], vector["allowed"])
        assert got == vector["expected"]
        return

    if op == "mul_circuit_ok":
        cs, cols, q = lesson.build_mul_circuit()
        assn = lesson.Assignment()
        lesson.assign_mul_witness(assn, cols, q, a=vector["a"], b=vector["b"], row=0)
        lesson.expose_public_output(cs, assn, cols, row=0)
        ok, failures = cs.is_satisfied(assn)
        assert failures == []
        assert ok == vector["expected"]
        return

    if op == "range_circuit_ok":
        cs = lesson.ConstraintSystem()
        x_col = cs.new_column(lesson.ColumnType.ADVICE)
        q = cs.new_selector()
        lesson.add_range_gate(cs, x_col, q, allowed=list(range(16)))

        assn = lesson.Assignment()
        assn.enable(q, 0)
        assn.assign(x_col, 0, vector["x"])
        ok, _failures = cs.is_satisfied(assn)
        assert ok == vector["expected"]
        return

    raise ValueError(f"unknown vector op: {op}")


def test_vectors() -> None:
    data = _load_vectors()
    assert isinstance(data.get("source"), str) and data["source"]
    for i, vector in enumerate(data.get("vectors", [])):
        try:
            _run_vector(vector)
        except Exception as e:
            raise AssertionError(f"vector #{i} failed: {vector}") from e


def test_field_inverses_roundtrip() -> None:
    for x in range(1, lesson.MODULUS):
        fx = lesson.fe(x)
        assert int(fx * fx.inv()) == 1


def test_vanishing_product_hits_zero_on_allowed_set() -> None:
    allowed = list(range(16))
    for x in allowed:
        assert lesson.vanishing_product(x, allowed) == 0


def test_inv_rejects_zero() -> None:
    try:
        lesson.fe(0).inv()
    except ZeroDivisionError:
        return
    raise AssertionError("expected ZeroDivisionError for inv(0)")


def test_assignment_rejects_negative_row() -> None:
    cs = lesson.ConstraintSystem()
    col = cs.new_column(lesson.ColumnType.ADVICE)
    assn = lesson.Assignment()
    try:
        assn.assign(col, -1, 1)
    except ValueError:
        return
    raise AssertionError("expected ValueError for negative row")


def test_query_rejects_unassigned_cell() -> None:
    cs = lesson.ConstraintSystem()
    col = cs.new_column(lesson.ColumnType.ADVICE)
    assn = lesson.Assignment()
    try:
        assn.query(col, 0)
    except KeyError:
        return
    raise AssertionError("expected KeyError for unassigned query")


def _run_all_tests() -> None:
    test_vectors()
    test_field_inverses_roundtrip()
    test_vanishing_product_hits_zero_on_allowed_set()
    test_inv_rejects_zero()
    test_assignment_rejects_negative_row()
    test_query_rejects_unassigned_cell()


if __name__ == "__main__":
    _run_all_tests()
    print("all tests pass")

