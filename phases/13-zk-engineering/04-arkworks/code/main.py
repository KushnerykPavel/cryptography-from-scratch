"""Phase 13 Lesson 04 - arkworks: multi-backend proving (toy model).

This lesson builds a tiny "circuit frontend" that can run in two modes:
  1) evaluate (native arithmetic, for witness generation)
  2) compile to an R1CS constraint system and check satisfiability

It is not a real SNARK. It is an educational mirror of the separation that
arkworks enforces: relation/circuit vs proving system/backend.

Run: python3 code/main.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


def modp(x: int, p: int) -> int:
    if p <= 2:
        raise ValueError("p must be an odd prime (toy code assumes field-like mod p)")
    return x % p


def inv_mod(a: int, p: int) -> int:
    a = modp(a, p)
    if a == 0:
        raise ValueError("0 has no inverse")
    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("p must be prime for inv_mod to succeed for all non-zero a")
    return modp(t, p)


Terms = List[Tuple[int, int]]  # (var_index, coeff)
Constraint = Dict[str, Terms]  # keys: A, B, C


def normalize_terms(terms: Iterable[Tuple[int, int]], p: int) -> Terms:
    acc: Dict[int, int] = {}
    for idx, coeff in terms:
        if idx < 0:
            raise ValueError("variable index must be >= 0")
        acc[idx] = modp(acc.get(idx, 0) + coeff, p)
    out = [(i, c) for i, c in sorted(acc.items()) if modp(c, p) != 0]
    return out


def eval_lc(terms: Sequence[Tuple[int, int]], witness: Sequence[int], p: int) -> int:
    total = 0
    for idx, coeff in terms:
        if idx >= len(witness):
            raise IndexError(f"linear combination references witness[{idx}] but len={len(witness)}")
        total = modp(total + coeff * witness[idx], p)
    return total


def check_constraint(constraint: Constraint, witness: Sequence[int], p: int) -> bool:
    a = eval_lc(constraint["A"], witness, p)
    b = eval_lc(constraint["B"], witness, p)
    c = eval_lc(constraint["C"], witness, p)
    return modp(a * b - c, p) == 0


def check_r1cs(constraints: Sequence[Constraint], witness: Sequence[int], p: int) -> bool:
    return first_unsatisfied(constraints, witness, p) is None


def first_unsatisfied(constraints: Sequence[Constraint], witness: Sequence[int], p: int) -> Optional[int]:
    for i, con in enumerate(constraints):
        if not check_constraint(con, witness, p):
            return i
    return None


@dataclass(frozen=True)
class Var:
    idx: int
    label: str


@dataclass
class CompiledCircuit:
    p: int
    public_vars: List[Var]
    witness_vars: List[Var]
    constraints: List[Constraint]

    def witness_for_assignment(self, public_values: Dict[str, int], witness_values: Dict[str, int]) -> List[int]:
        w: List[int] = [1]

        for i, v in enumerate(self.public_vars):
            expected_idx = 1 + i
            if v.idx != expected_idx:
                raise ValueError(
                    f"public var '{v.label}' has idx={v.idx}, expected {expected_idx} "
                    "(this toy compiler requires public vars to be allocated first)"
                )
            if v.label not in public_values:
                raise KeyError(f"missing public input: {v.label}")
            w.append(modp(public_values[v.label], self.p))

        for j, v in enumerate(self.witness_vars):
            expected_idx = 1 + len(self.public_vars) + j
            if v.idx != expected_idx:
                raise ValueError(
                    f"witness var '{v.label}' has idx={v.idx}, expected {expected_idx} "
                    "(this toy compiler uses a fixed witness-vector layout)"
                )
            if v.label not in witness_values:
                raise KeyError(f"missing witness value: {v.label}")
            w.append(modp(witness_values[v.label], self.p))

        return w


class CircuitAPI:
    def const(self, value: int, *, label: str) -> Var:
        raise NotImplementedError

    def public(self, value: int, *, label: str) -> Var:
        raise NotImplementedError

    def witness(self, value: int, *, label: str) -> Var:
        raise NotImplementedError

    def add(self, a: Var, b: Var, *, label: str) -> Var:
        raise NotImplementedError

    def mul(self, a: Var, b: Var, *, label: str) -> Var:
        raise NotImplementedError

    def assert_eq(self, a: Var, b: Var, *, label: str) -> None:
        raise NotImplementedError


class EvalBackend(CircuitAPI):
    def __init__(self, p: int):
        self.p = p
        self._values: Dict[int, int] = {}
        self._next_idx = 0

    def _alloc(self, value: int, label: str) -> Var:
        idx = self._next_idx
        self._next_idx += 1
        self._values[idx] = modp(value, self.p)
        return Var(idx=idx, label=label)

    def value(self, v: Var) -> int:
        return self._values[v.idx]

    def const(self, value: int, *, label: str) -> Var:
        return self._alloc(value, label)

    def public(self, value: int, *, label: str) -> Var:
        return self._alloc(value, label)

    def witness(self, value: int, *, label: str) -> Var:
        return self._alloc(value, label)

    def add(self, a: Var, b: Var, *, label: str) -> Var:
        return self._alloc(self.value(a) + self.value(b), label)

    def mul(self, a: Var, b: Var, *, label: str) -> Var:
        return self._alloc(self.value(a) * self.value(b), label)

    def assert_eq(self, a: Var, b: Var, *, label: str) -> None:
        if self.value(a) != self.value(b):
            raise ValueError(f"assertion failed ({label}): {self.value(a)} != {self.value(b)}")


class R1CSBackend(CircuitAPI):
    def __init__(self, p: int):
        self.p = p
        self.public_vars: List[Var] = []
        self.witness_vars: List[Var] = []
        self.constraints: List[Constraint] = []
        self._next_global_idx = 1  # witness vector index 0 is the constant 1
        self._values_by_label: Dict[str, int] = {}

    def _alloc_public(self, value: int, label: str) -> Var:
        idx = self._next_global_idx
        self._next_global_idx += 1
        v = Var(idx=idx, label=label)
        self.public_vars.append(v)
        self._values_by_label[label] = modp(value, self.p)
        return v

    def _alloc_witness(self, value: int, label: str) -> Var:
        idx = self._next_global_idx
        self._next_global_idx += 1
        v = Var(idx=idx, label=label)
        self.witness_vars.append(v)
        self._values_by_label[label] = modp(value, self.p)
        return v

    def const(self, value: int, *, label: str) -> Var:
        v = self._alloc_witness(value, label)
        self._con([(v.idx, 1), (0, -value)], [(0, 1)], [])
        return v

    def public(self, value: int, *, label: str) -> Var:
        return self._alloc_public(value, label)

    def witness(self, value: int, *, label: str) -> Var:
        return self._alloc_witness(value, label)

    def _con(self, a_terms: Iterable[Tuple[int, int]], b_terms: Iterable[Tuple[int, int]], c_terms: Iterable[Tuple[int, int]]) -> None:
        con = {
            "A": normalize_terms(a_terms, self.p),
            "B": normalize_terms(b_terms, self.p),
            "C": normalize_terms(c_terms, self.p),
        }
        self.constraints.append(con)

    def add(self, a: Var, b: Var, *, label: str) -> Var:
        out = self._alloc_witness(self._values_by_label[a.label] + self._values_by_label[b.label], label)
        self._con([(a.idx, 1), (b.idx, 1), (out.idx, -1)], [(0, 1)], [])
        return out

    def mul(self, a: Var, b: Var, *, label: str) -> Var:
        out = self._alloc_witness(self._values_by_label[a.label] * self._values_by_label[b.label], label)
        self._con([(a.idx, 1)], [(b.idx, 1)], [(out.idx, 1)])
        return out

    def assert_eq(self, a: Var, b: Var, *, label: str) -> None:
        self._con([(a.idx, 1), (b.idx, -1)], [(0, 1)], [])

    def compile(self) -> CompiledCircuit:
        expected_next = 1 + len(self.public_vars) + len(self.witness_vars)
        if self._next_global_idx != expected_next:
            raise AssertionError("internal variable accounting bug")
        return CompiledCircuit(
            p=self.p,
            public_vars=list(self.public_vars),
            witness_vars=list(self.witness_vars),
            constraints=list(self.constraints),
        )


def cubic_output(x: int, p: int, *, constant: int) -> int:
    x = modp(x, p)
    return modp(x * x * x + x + constant, p)


def cubic_relation_circuit(api: CircuitAPI, *, x_value: int, out_value: int, constant: int) -> Tuple[Var, Var]:
    out = api.public(out_value, label="out")
    x = api.witness(x_value, label="x")
    x2 = api.mul(x, x, label="x2")
    x3 = api.mul(x2, x, label="x3")
    x3_plus_x = api.add(x3, x, label="x3_plus_x")
    rhs = api.add(x3_plus_x, api.const(constant, label="k"), label="rhs")
    api.assert_eq(rhs, out, label="out_matches_rhs")
    return x, out


def compile_cubic_relation(p: int, *, x: int, constant: int) -> Tuple[CompiledCircuit, Dict[str, int], Dict[str, int]]:
    out = cubic_output(x, p, constant=constant)
    r1cs = R1CSBackend(p)
    cubic_relation_circuit(r1cs, x_value=x, out_value=out, constant=constant)
    compiled = r1cs.compile()

    public_values = {"out": out}
    witness_values: Dict[str, int] = {v.label: r1cs._values_by_label[v.label] for v in compiled.witness_vars}
    return compiled, public_values, witness_values


def _pretty_constraint(con: Constraint) -> str:
    return json.dumps(con, separators=(",", ":"), sort_keys=True)


def main() -> None:
    p = 101
    constant = 5
    x = 3

    print("=== Step 1: Prime-field arithmetic ===")
    y = cubic_output(x, p, constant=constant)
    inv = inv_mod(42, p)
    print(f"F_p with p={p}")
    print(f"cubic_output(x={x}, k={constant}) = {y}")
    print(f"inv_mod(42) = {inv}  (check: 42*inv % p = {(42 * inv) % p})")
    print()

    print("=== Step 2: A backend-generic circuit ===")
    ev = EvalBackend(p)
    cubic_relation_circuit(ev, x_value=x, out_value=y, constant=constant)
    print(f"native run satisfied with out={y}")
    try:
        cubic_relation_circuit(EvalBackend(p), x_value=x, out_value=modp(y + 1, p), constant=constant)
        raise AssertionError("expected circuit assertion to fail")
    except ValueError as e:
        print(f"native run rejects wrong public out: {e}")
    print()

    print("=== Step 3: Compile to R1CS and check satisfiability ===")
    compiled, public_values, witness_values = compile_cubic_relation(p, x=x, constant=constant)
    witness_vec = compiled.witness_for_assignment(public_values, witness_values)
    print(f"vars: 1 const + {len(compiled.public_vars)} public + {len(compiled.witness_vars)} witness")
    print(f"constraints: {len(compiled.constraints)}")
    print(f"witness vector length: {len(witness_vec)}")
    print(f"first constraint: {_pretty_constraint(compiled.constraints[0])}")
    print(f"satisfied: {check_r1cs(compiled.constraints, witness_vec, p)}")
    print()

    print("=== Step 4: Same circuit, different backend ===")
    out_wrong = modp(y + 1, p)
    r1cs_wrong = R1CSBackend(p)
    cubic_relation_circuit(r1cs_wrong, x_value=x, out_value=out_wrong, constant=constant)
    compiled_wrong = r1cs_wrong.compile()
    witness_wrong = compiled_wrong.witness_for_assignment(
        {"out": out_wrong},
        {v.label: r1cs_wrong._values_by_label[v.label] for v in compiled_wrong.witness_vars},
    )
    bad_idx = first_unsatisfied(compiled_wrong.constraints, witness_wrong, p)
    print(f"wrong out={out_wrong} => satisfied: {check_r1cs(compiled_wrong.constraints, witness_wrong, p)}")
    print(f"first unsatisfied constraint index: {bad_idx}")


if __name__ == "__main__":
    main()
