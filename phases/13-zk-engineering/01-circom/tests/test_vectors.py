import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    Field,
    LinearComb,
    R1CSConstraint,
    build_arith_and_range_circuit,
    check_r1cs,
    compile_range_check_4bit,
    eval_lc,
    witness_arith_and_range_circuit,
)


def _int_keyed(d):
    out = {}
    for k, v in d.items():
        out[int(k)] = v
    return out


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors():
    vectors = _load_vectors()["vectors"]
    for v in vectors:
        op = v["op"]
        if op == "field_add":
            p = v["p"]
            F = Field(p)
            got = int(F(v["a"]) + F(v["b"]))
            assert got == v["expected"]
        elif op == "field_mul":
            p = v["p"]
            F = Field(p)
            got = int(F(v["a"]) * F(v["b"]))
            assert got == v["expected"]
        elif op == "lc_eval":
            F = Field(v["p"])
            lc = LinearComb(F, const=v["const"], terms=v["terms"])
            got = int(eval_lc(lc, _int_keyed(v["assignment"])))
            assert got == v["expected"]
        elif op == "r1cs_check":
            F = Field(v["p"])
            constraints = []
            for c in v["constraints"]:
                A = LinearComb(F, const=c["A"]["const"], terms=c["A"]["terms"])
                B = LinearComb(F, const=c["B"]["const"], terms=c["B"]["terms"])
                C = LinearComb(F, const=c["C"]["const"], terms=c["C"]["terms"])
                constraints.append(R1CSConstraint(A=A, B=B, C=C, label=c.get("label", "")))
            ok, _ = check_r1cs(constraints, _int_keyed(v["assignment"]))
            assert ok == v["expected_ok"]
        elif op == "compile_range_check_4bit":
            F = Field(v["p"])
            constraints, bit_ids = compile_range_check_4bit(F=F, x_var=v["x_var"], prefix=v["prefix"])
            ok, failures = check_r1cs(constraints, _int_keyed(v["assignment"]))
            assert ok == v["expected_ok"]
            assert bit_ids == v["expected_bit_ids"]
            if v["expected_ok"] is False:
                assert failures
        elif op == "arith_range_circuit_ok":
            F = Field(v["p"])
            c = build_arith_and_range_circuit(F=F)
            assignment = witness_arith_and_range_circuit(
                c,
                a=v["a"],
                b=v["b"],
                c_in=v["c_in"],
                d=v["d"],
            )
            ok, failures = check_r1cs(c["constraints"], assignment)
            assert ok is True, failures
        elif op == "arith_range_circuit_reject":
            F = Field(v["p"])
            c = build_arith_and_range_circuit(F=F)
            assignment = witness_arith_and_range_circuit(
                c,
                a=v["a"],
                b=v["b"],
                c_in=v["c_in"],
                d=v["d"],
                force_bad=v.get("force_bad", {}),
            )
            ok, _ = check_r1cs(c["constraints"], assignment)
            assert ok is False
        else:
            raise ValueError(f"unknown op: {op}")


def test_range_check_accepts_0_to_15():
    F = Field(97)
    x_var = 1
    constraints, bit_ids = compile_range_check_4bit(F=F, x_var=x_var, prefix="t")
    for x in range(16):
        assignment = {0: 1, x_var: x}
        for i, bid in enumerate(bit_ids):
            assignment[bid] = (x >> i) & 1
        ok, failures = check_r1cs(constraints, assignment)
        assert ok is True, (x, failures)


def test_range_check_rejects_non_bits():
    F = Field(97)
    x_var = 1
    constraints, bit_ids = compile_range_check_4bit(F=F, x_var=x_var, prefix="t")
    assignment = {0: 1, x_var: 7}
    for bid in bit_ids:
        assignment[bid] = 0
    assignment[bit_ids[0]] = 2
    ok, _ = check_r1cs(constraints, assignment)
    assert ok is False


def test_r1cs_edge_missing_variable_is_error():
    F = Field(97)
    A = LinearComb(F, const=0, terms=[[1, 1]])
    B = LinearComb(F, const=0, terms=[])
    C = LinearComb(F, const=0, terms=[])
    ok, failures = check_r1cs([R1CSConstraint(A=A, B=B, C=C, label="missing")], {0: 1})
    assert ok is False
    assert failures


if __name__ == "__main__":
    try:
        test_vectors()
        test_range_check_accepts_0_to_15()
        test_range_check_rejects_non_bits()
        test_r1cs_edge_missing_variable_is_error()
    except Exception as e:
        print("tests failed")
        raise
    print("all tests pass")
