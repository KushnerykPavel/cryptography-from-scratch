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

import main as ark  # noqa: E402


@contextmanager
def _raises(exc_type):
    try:
        yield
    except exc_type:
        return
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _constraint(json_con):
    return {k: [(int(i), int(c)) for i, c in json_con[k]] for k in ("A", "B", "C")}


def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]
        p = int(vec["p"])

        if op == "inv_mod":
            got = ark.inv_mod(int(vec["a"]), p)
        elif op == "cubic_output":
            got = ark.cubic_output(int(vec["x"]), p, constant=int(vec["k"]))
        elif op == "compile_cubic_relation_stats":
            compiled, _, _ = ark.compile_cubic_relation(p, x=int(vec["x"]), constant=int(vec["k"]))
            got = {
                "num_public": len(compiled.public_vars),
                "num_witness": len(compiled.witness_vars),
                "num_constraints": len(compiled.constraints),
            }
        elif op == "compile_cubic_relation_witness":
            compiled, pub, wit = ark.compile_cubic_relation(p, x=int(vec["x"]), constant=int(vec["k"]))
            got = compiled.witness_for_assignment(pub, wit)
        elif op == "compile_cubic_relation_first_constraint":
            compiled, _, _ = ark.compile_cubic_relation(p, x=int(vec["x"]), constant=int(vec["k"]))
            got = compiled.constraints[0]
        elif op == "first_unsatisfied_wrong_public_out":
            x = int(vec["x"])
            k = int(vec["k"])
            out = ark.cubic_output(x, p, constant=k)
            out_wrong = (out + 1) % p
            r1cs = ark.R1CSBackend(p)
            ark.cubic_relation_circuit(r1cs, x_value=x, out_value=out_wrong, constant=k)
            compiled = r1cs.compile()
            witness = compiled.witness_for_assignment(
                {"out": out_wrong},
                {v.label: r1cs._values_by_label[v.label] for v in compiled.witness_vars},
            )
            got = ark.first_unsatisfied(compiled.constraints, witness, p)
        else:
            raise ValueError(f"unknown op in vectors.json: {op}")

        expected = vec["expected"]
        if op == "compile_cubic_relation_first_constraint":
            expected = _constraint(expected)
        assert got == expected, f"vector failed: op={op}"


def test_inv_mod_roundtrip():
    p = 101
    rng = random.Random(0)
    for _ in range(50):
        a = rng.randrange(1, p)
        inv = ark.inv_mod(a, p)
        assert (a * inv) % p == 1


def test_inv_mod_rejects_zero():
    cm = pytest.raises(ValueError) if pytest else _raises(ValueError)
    with cm:
        ark.inv_mod(0, 101)


def test_cubic_relation_satisfied_for_many_x():
    p = 101
    rng = random.Random(1)
    for _ in range(25):
        x = rng.randrange(0, p)
        compiled, pub, wit = ark.compile_cubic_relation(p, x=x, constant=5)
        w = compiled.witness_for_assignment(pub, wit)
        assert ark.check_r1cs(compiled.constraints, w, p) is True


def test_wrong_public_out_fails_at_last_constraint():
    p = 101
    x = 7
    compiled, pub, wit = ark.compile_cubic_relation(p, x=x, constant=5)
    w = compiled.witness_for_assignment(pub, wit)
    w_bad = list(w)
    w_bad[1] = (w_bad[1] + 1) % p
    assert ark.check_r1cs(compiled.constraints, w_bad, p) is False
    assert ark.first_unsatisfied(compiled.constraints, w_bad, p) == len(compiled.constraints) - 1


def test_constant_is_constrained():
    p = 101
    compiled, pub, wit = ark.compile_cubic_relation(p, x=3, constant=5)
    w = compiled.witness_for_assignment(pub, wit)
    k_idx = next(v.idx for v in compiled.witness_vars if v.label == "k")
    w_bad = list(w)
    w_bad[k_idx] = (w_bad[k_idx] + 2) % p
    assert ark.check_r1cs(compiled.constraints, w_bad, p) is False
    assert ark.first_unsatisfied(compiled.constraints, w_bad, p) == 3


if __name__ == "__main__":
    if pytest:
        raise SystemExit(pytest.main([__file__, "-q"]))

    tests = [
        test_vectors,
        test_inv_mod_roundtrip,
        test_inv_mod_rejects_zero,
        test_cubic_relation_satisfied_for_many_x,
        test_wrong_public_out_fails_at_last_constraint,
        test_constant_is_constrained,
    ]
    for t in tests:
        t()
    print("all tests pass")

