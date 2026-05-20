"""Writing Circom circuits by building a tiny R1CS model in Python.

This is not Circom. It's a small, runnable mental model:
  - a circuit is a set of constraints over a finite field
  - a witness is an assignment that satisfies those constraints

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


class Field:
    def __init__(self, p: int):
        if not isinstance(p, int) or p <= 2:
            raise ValueError("p must be an int > 2")
        self.p = p

    def __call__(self, x: int) -> "FieldElem":
        return FieldElem(self, x % self.p)


@dataclass(frozen=True)
class FieldElem:
    F: Field
    v: int

    def __post_init__(self) -> None:
        if not (0 <= self.v < self.F.p):
            raise ValueError("field element out of range")

    def __int__(self) -> int:
        return self.v

    def __add__(self, other: "FieldElem") -> "FieldElem":
        _assert_same_field(self, other)
        return self.F(self.v + other.v)

    def __sub__(self, other: "FieldElem") -> "FieldElem":
        _assert_same_field(self, other)
        return self.F(self.v - other.v)

    def __mul__(self, other: "FieldElem") -> "FieldElem":
        _assert_same_field(self, other)
        return self.F(self.v * other.v)

    def inv(self) -> "FieldElem":
        if self.v == 0:
            raise ZeroDivisionError("0 has no inverse")
        return self.F(pow(self.v, -1, self.F.p))

    def __truediv__(self, other: "FieldElem") -> "FieldElem":
        return self * other.inv()


def _assert_same_field(a: FieldElem, b: FieldElem) -> None:
    if a.F.p != b.F.p:
        raise ValueError("field mismatch")


@dataclass(frozen=True)
class LinearComb:
    """A linear combination over variables: const + sum_i (coeff_i * var_i).

    `terms` is a list of [coeff, var_id] pairs. var_id 0 is reserved for the
    constant-one wire (so assignment[0] must be 1).
    """

    F: Field
    const: int
    terms: List[List[int]]


def eval_lc(lc: LinearComb, assignment: Dict[int, int]) -> FieldElem:
    F = lc.F
    acc = F(lc.const)
    for coeff, var_id in lc.terms:
        if var_id not in assignment:
            raise KeyError(f"missing var {var_id} in assignment")
        acc = acc + F(coeff) * F(assignment[var_id])
    return acc


@dataclass(frozen=True)
class R1CSConstraint:
    A: LinearComb
    B: LinearComb
    C: LinearComb
    label: str = ""


def check_r1cs(constraints: Iterable[R1CSConstraint], assignment: Dict[int, int]) -> Tuple[bool, List[str]]:
    failures: List[str] = []
    for i, con in enumerate(constraints):
        try:
            a = eval_lc(con.A, assignment)
            b = eval_lc(con.B, assignment)
            c = eval_lc(con.C, assignment)
        except Exception as e:
            failures.append(f"constraint {i} {con.label}: eval error: {e}")
            continue
        if int(a * b - c) != 0:
            failures.append(
                f"constraint {i} {con.label}: (A*B-C) != 0 (A={int(a)}, B={int(b)}, C={int(c)})"
            )
    return (len(failures) == 0), failures


def _lc_const(F: Field, c: int) -> LinearComb:
    return LinearComb(F, const=c, terms=[])


def _lc_var(F: Field, var_id: int, coeff: int = 1) -> LinearComb:
    return LinearComb(F, const=0, terms=[[coeff, var_id]])


def compile_mul(F: Field, x_var: int, y_var: int, out_var: int, label: str) -> R1CSConstraint:
    return R1CSConstraint(A=_lc_var(F, x_var), B=_lc_var(F, y_var), C=_lc_var(F, out_var), label=label)


def compile_assert_equal(F: Field, x_var: int, y_var: int, label: str) -> R1CSConstraint:
    A = LinearComb(F, const=0, terms=[[1, x_var], [-1, y_var]])
    return R1CSConstraint(A=A, B=_lc_const(F, 1), C=_lc_const(F, 0), label=label)


def compile_assert_boolean(F: Field, b_var: int, label: str) -> R1CSConstraint:
    A = _lc_var(F, b_var)
    B = LinearComb(F, const=-1, terms=[[1, b_var]])
    return R1CSConstraint(A=A, B=B, C=_lc_const(F, 0), label=label)


def compile_range_check_4bit(F: Field, x_var: int, prefix: str) -> Tuple[List[R1CSConstraint], List[int]]:
    """Constrains x in [0, 15] by introducing 4 boolean bits b0..b3.

    Constraints:
      - each bi is boolean
      - x == b0 + 2*b1 + 4*b2 + 8*b3

    Returns (constraints, bit_var_ids). Bit ids are deterministic: [x_var+1..x_var+4].
    """

    bit_ids = [x_var + 1, x_var + 2, x_var + 3, x_var + 4]
    constraints: List[R1CSConstraint] = []

    for i, bid in enumerate(bit_ids):
        constraints.append(compile_assert_boolean(F, bid, label=f"{prefix}.bit{i}.boolean"))

    terms = [[1, x_var]]
    for i, bid in enumerate(bit_ids):
        terms.append([-(1 << i), bid])
    A = LinearComb(F, const=0, terms=terms)
    constraints.append(R1CSConstraint(A=A, B=_lc_const(F, 1), C=_lc_const(F, 0), label=f"{prefix}.recompose"))
    return constraints, bit_ids


def witness_range_check_4bit(x: int) -> Dict[str, int]:
    if not (0 <= x <= 15):
        raise ValueError("x must be in [0, 15] for this witness helper")
    return {f"bit{i}": (x >> i) & 1 for i in range(4)}


def build_arith_and_range_circuit(F: Field) -> Dict[str, object]:
    """Circuit:
      - inputs: a, b, c (all 4-bit), d (unconstrained field element)
      - compute: t = a*b, out = t + c
      - enforce: out == d
      - range-check: a,b,c are 4-bit

    Variable layout is fixed for determinism:
      0: one
      1: a
      2..5: a bits
      6: b
      7..10: b bits
      11: c
      12..15: c bits
      16: d
      21: t
      22: out
    """

    one = 0
    a = 1
    b = 6
    c_in = 11
    d = 16
    t = 21
    out = 22

    constraints: List[R1CSConstraint] = []
    constraints.extend(compile_range_check_4bit(F, a, "a")[0])
    constraints.extend(compile_range_check_4bit(F, b, "b")[0])
    constraints.extend(compile_range_check_4bit(F, c_in, "c")[0])

    constraints.append(compile_mul(F, a, b, t, label="t=a*b"))

    A = LinearComb(F, const=0, terms=[[1, out], [-1, t], [-1, c_in]])
    constraints.append(R1CSConstraint(A=A, B=_lc_const(F, 1), C=_lc_const(F, 0), label="out=t+c"))

    constraints.append(compile_assert_equal(F, out, d, label="out==d"))

    return {
        "var_ids": {"one": one, "a": a, "b": b, "c": c_in, "d": d, "t": t, "out": out},
        "constraints": constraints,
    }


def witness_arith_and_range_circuit(
    circuit: Dict[str, object],
    a: int,
    b: int,
    c_in: int,
    d: int,
    force_bad: Dict[str, int] | None = None,
) -> Dict[int, int]:
    if force_bad is None:
        force_bad = {}

    ids = circuit["var_ids"]
    assignment: Dict[int, int] = {0: 1}

    assignment[ids["a"]] = a
    assignment[ids["b"]] = b
    assignment[ids["c"]] = c_in
    assignment[ids["d"]] = d

    a_bits = witness_range_check_4bit(a)
    b_bits = witness_range_check_4bit(b)
    c_bits = witness_range_check_4bit(c_in)

    for i in range(4):
        assignment[ids["a"] + 1 + i] = a_bits[f"bit{i}"]
        assignment[ids["b"] + 1 + i] = b_bits[f"bit{i}"]
        assignment[ids["c"] + 1 + i] = c_bits[f"bit{i}"]

    assignment[ids["t"]] = a * b
    assignment[ids["out"]] = assignment[ids["t"]] + c_in

    for k, v in force_bad.items():
        if k.startswith("a_bit"):
            idx = int(k[len("a_bit") :])
            assignment[ids["a"] + 1 + idx] = v
        else:
            raise ValueError(f"unknown force_bad key: {k}")

    return assignment


def check_one_wire(assignment: Dict[int, int]) -> None:
    if assignment.get(0) != 1:
        raise ValueError("assignment[0] must be 1 (the constant-one wire)")


def main() -> None:
    F = Field(97)

    print("=== Step 1: Field arithmetic (mod p) ===")
    a = F(100)
    b = F(5)
    print(f"p={F.p}, 100+5 mod p = {int(a + b)}")

    print("\n=== Step 2: R1CS constraints (A*B=C) ===")
    x_var, y_var, z_var = 1, 2, 3
    constraint = compile_mul(F, x_var, y_var, z_var, label="x*y=z")
    ok, failures = check_r1cs([constraint], {0: 1, 1: 3, 2: 4, 3: 12})
    print(f"constraint ok? {ok}")
    if not ok:
        print("failures:", failures)

    print("\n=== Step 3: Range checks are explicit constraints ===")
    constraints, bit_ids = compile_range_check_4bit(F, x_var=1, prefix="x")
    assignment = {0: 1, 1: 9}
    bits = witness_range_check_4bit(9)
    for i, bid in enumerate(bit_ids):
        assignment[bid] = bits[f"bit{i}"]
    ok, failures = check_r1cs(constraints, assignment)
    print(f"x=9 passes 4-bit range check? {ok}")
    if not ok:
        print("failures:", failures)

    print("\n=== Step 4: Build a tiny 'Circom-like' circuit and verify a witness ===")
    circuit = build_arith_and_range_circuit(F)
    assignment = witness_arith_and_range_circuit(circuit, a=3, b=5, c_in=7, d=22)
    check_one_wire(assignment)
    ok, failures = check_r1cs(circuit["constraints"], assignment)
    print(f"a=3,b=5,c=7,d=22 -> witness satisfies constraints? {ok}")
    if not ok:
        print("failures:", failures)

    bad_assignment = witness_arith_and_range_circuit(circuit, a=3, b=5, c_in=7, d=22, force_bad={"a_bit0": 2})
    ok, failures = check_r1cs(circuit["constraints"], bad_assignment)
    print(f"tampered witness (non-bit) satisfies constraints? {ok}")
    if ok:
        print("unexpected: circuit accepted an invalid witness")
    else:
        print("rejected as expected:")
        print(failures[0])


if __name__ == "__main__":
    main()
