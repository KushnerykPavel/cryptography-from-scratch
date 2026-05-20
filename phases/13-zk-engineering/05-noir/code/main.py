"""
Noir-inspired ZK engineering in pure Python.

This lesson builds a tiny "Noir-like" front-end that:
- represents a program as an AST
- compiles it to an R1CS-ish constraint system over a finite field
- checks satisfiability for a given witness
- demonstrates range constraints (u32) and underconstrained computation

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import pathlib
import random
from typing import Dict, Iterable, List, Optional, Tuple


DEFAULT_FIELD_MODULUS = 2**61 - 1


def field_normalize(value: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return value % modulus


def field_add(a: int, b: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return (a + b) % modulus


def field_sub(a: int, b: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return (a - b) % modulus


def field_mul(a: int, b: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return (a * b) % modulus


def range_check_bits(value: int, bits: int) -> bool:
    if bits <= 0:
        return False
    if value < 0:
        return False
    return value < (1 << bits)


@dataclass(frozen=True)
class Expr:
    pass


@dataclass(frozen=True)
class Const(Expr):
    value: int


@dataclass(frozen=True)
class Var(Expr):
    name: str


@dataclass(frozen=True)
class Add(Expr):
    left: Expr
    right: Expr


@dataclass(frozen=True)
class Mul(Expr):
    left: Expr
    right: Expr


def eval_expr(expr: Expr, env: Dict[str, int], modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    if isinstance(expr, Const):
        return field_normalize(expr.value, modulus)
    if isinstance(expr, Var):
        return field_normalize(env[expr.name], modulus)
    if isinstance(expr, Add):
        return field_add(eval_expr(expr.left, env, modulus), eval_expr(expr.right, env, modulus), modulus)
    if isinstance(expr, Mul):
        return field_mul(eval_expr(expr.left, env, modulus), eval_expr(expr.right, env, modulus), modulus)
    raise TypeError(f"unknown Expr: {type(expr).__name__}")


@dataclass(frozen=True)
class Stmt:
    pass


@dataclass(frozen=True)
class Let(Stmt):
    name: str
    expr: Expr
    constrained: bool = True


@dataclass(frozen=True)
class AssertEq(Stmt):
    left: Expr
    right: Expr


@dataclass(frozen=True)
class RangeCheck(Stmt):
    expr: Expr
    bits: int


def execute_program(
    statements: List[Stmt], inputs: Dict[str, int], modulus: int = DEFAULT_FIELD_MODULUS
) -> Dict[str, int]:
    env: Dict[str, int] = {k: field_normalize(v, modulus) for k, v in inputs.items()}
    for stmt in statements:
        if isinstance(stmt, Let):
            env[stmt.name] = eval_expr(stmt.expr, env, modulus)
        elif isinstance(stmt, AssertEq):
            pass
        elif isinstance(stmt, RangeCheck):
            pass
        else:
            raise TypeError(f"unknown Stmt: {type(stmt).__name__}")
    return env


@dataclass(frozen=True)
class LinearCombination:
    terms: Dict[int, int]
    const: int = 0


def lc_const(value: int) -> LinearCombination:
    return LinearCombination({}, value)


def lc_var(wire: int) -> LinearCombination:
    return LinearCombination({wire: 1}, 0)


def lc_add(a: LinearCombination, b: LinearCombination, modulus: int) -> LinearCombination:
    terms: Dict[int, int] = dict(a.terms)
    for w, c in b.terms.items():
        terms[w] = (terms.get(w, 0) + c) % modulus
        if terms[w] == 0:
            del terms[w]
    return LinearCombination(terms, (a.const + b.const) % modulus)


def lc_sub(a: LinearCombination, b: LinearCombination, modulus: int) -> LinearCombination:
    terms: Dict[int, int] = dict(a.terms)
    for w, c in b.terms.items():
        terms[w] = (terms.get(w, 0) - c) % modulus
        if terms[w] == 0:
            del terms[w]
    return LinearCombination(terms, (a.const - b.const) % modulus)


def lc_scale(a: LinearCombination, k: int, modulus: int) -> LinearCombination:
    k = k % modulus
    if k == 0:
        return lc_const(0)
    terms = {w: (c * k) % modulus for w, c in a.terms.items() if (c * k) % modulus != 0}
    return LinearCombination(terms, (a.const * k) % modulus)


def eval_lc(lc: LinearCombination, witness: List[int], modulus: int) -> int:
    acc = lc.const % modulus
    for w, c in lc.terms.items():
        acc = (acc + (c % modulus) * witness[w]) % modulus
    return acc


@dataclass(frozen=True)
class R1CSConstraint:
    a: LinearCombination
    b: LinearCombination
    c: LinearCombination


@dataclass(frozen=True)
class Circuit:
    modulus: int
    num_wires: int
    constraints: List[R1CSConstraint]
    range_constraints: List[Tuple[int, int]]
    name_to_wire: Dict[str, int]
    wire_to_name: Dict[int, str]
    generators: List["WireGenerator"]


@dataclass(frozen=True)
class WireGenerator:
    wire: int
    kind: str
    left: LinearCombination
    right: Optional[LinearCombination] = None


def circuit_is_satisfied(circuit: Circuit, witness: List[int]) -> bool:
    if len(witness) != circuit.num_wires:
        return False
    if witness[0] % circuit.modulus != 1:
        return False

    w = [field_normalize(x, circuit.modulus) for x in witness]
    for wire, bits in circuit.range_constraints:
        if not range_check_bits(w[wire], bits):
            return False

    for con in circuit.constraints:
        left = eval_lc(con.a, w, circuit.modulus)
        right = eval_lc(con.b, w, circuit.modulus)
        out = eval_lc(con.c, w, circuit.modulus)
        if (left * right - out) % circuit.modulus != 0:
            return False
    return True


@dataclass
class _Compiler:
    modulus: int
    next_wire: int
    constraints: List[R1CSConstraint]
    range_constraints: List[Tuple[int, int]]
    name_to_wire: Dict[str, int]
    wire_to_name: Dict[int, str]
    generators: List[WireGenerator]

    @staticmethod
    def new(modulus: int) -> "_Compiler":
        return _Compiler(
            modulus=modulus,
            next_wire=1,
            constraints=[],
            range_constraints=[],
            name_to_wire={"ONE": 0},
            wire_to_name={0: "ONE"},
            generators=[],
        )

    def _alloc_wire(self, name: str) -> int:
        wire = self.next_wire
        self.next_wire += 1
        self.wire_to_name[wire] = name
        return wire

    def wire_for(self, name: str) -> int:
        existing = self.name_to_wire.get(name)
        if existing is not None:
            return existing
        wire = self._alloc_wire(name)
        self.name_to_wire[name] = wire
        return wire

    def fresh_tmp(self, prefix: str) -> int:
        return self._alloc_wire(f"${prefix}{self.next_wire}")

    def assert_zero(self, expr: LinearCombination) -> None:
        self.constraints.append(R1CSConstraint(a=expr, b=lc_const(1), c=lc_const(0)))

    def assert_eq_lc(self, left: LinearCombination, right: LinearCombination) -> None:
        self.assert_zero(lc_sub(left, right, self.modulus))


def compile_to_circuit(statements: List[Stmt], modulus: int = DEFAULT_FIELD_MODULUS) -> Circuit:
    c = _Compiler.new(modulus)

    def expr_to_lc(expr: Expr) -> LinearCombination:
        if isinstance(expr, Const):
            return lc_const(field_normalize(expr.value, modulus))
        if isinstance(expr, Var):
            return lc_var(c.wire_for(expr.name))
        if isinstance(expr, Add):
            return lc_add(expr_to_lc(expr.left), expr_to_lc(expr.right), modulus)
        if isinstance(expr, Mul):
            left = expr_to_lc(expr.left)
            right = expr_to_lc(expr.right)
            out_wire = c.fresh_tmp("mul")
            c.constraints.append(R1CSConstraint(a=left, b=right, c=lc_var(out_wire)))
            c.generators.append(WireGenerator(wire=out_wire, kind="mul", left=left, right=right))
            return lc_var(out_wire)
        raise TypeError(f"unknown Expr: {type(expr).__name__}")

    for stmt in statements:
        if isinstance(stmt, Let):
            out_wire = c.wire_for(stmt.name)
            if stmt.constrained:
                c.assert_eq_lc(lc_var(out_wire), expr_to_lc(stmt.expr))
        elif isinstance(stmt, AssertEq):
            c.assert_eq_lc(expr_to_lc(stmt.left), expr_to_lc(stmt.right))
        elif isinstance(stmt, RangeCheck):
            lc = expr_to_lc(stmt.expr)
            if len(lc.terms) == 1 and lc.const == 0:
                (wire,) = tuple(lc.terms.keys())
                (coef,) = tuple(lc.terms.values())
                if coef % modulus != 1:
                    tmp = c.fresh_tmp("rc")
                    c.assert_eq_lc(lc_var(tmp), lc)
                    c.generators.append(WireGenerator(wire=tmp, kind="lc", left=lc))
                    c.range_constraints.append((tmp, stmt.bits))
                else:
                    c.range_constraints.append((wire, stmt.bits))
            else:
                tmp = c.fresh_tmp("rc")
                c.assert_eq_lc(lc_var(tmp), lc)
                c.generators.append(WireGenerator(wire=tmp, kind="lc", left=lc))
                c.range_constraints.append((tmp, stmt.bits))
        else:
            raise TypeError(f"unknown Stmt: {type(stmt).__name__}")

    return Circuit(
        modulus=modulus,
        num_wires=c.next_wire,
        constraints=c.constraints,
        range_constraints=c.range_constraints,
        name_to_wire=dict(c.name_to_wire),
        wire_to_name=dict(c.wire_to_name),
        generators=list(c.generators),
    )


def witness_from_env(circuit: Circuit, env: Dict[str, int]) -> List[int]:
    witness = [0 for _ in range(circuit.num_wires)]
    witness[0] = 1
    known = {0}
    for name, wire in circuit.name_to_wire.items():
        if name == "ONE":
            continue
        if name in env:
            witness[wire] = field_normalize(env[name], circuit.modulus)
            known.add(wire)

    pending = list(circuit.generators)
    progress = True
    while pending and progress:
        progress = False
        still_pending: List[WireGenerator] = []
        for gen in pending:
            deps = set(gen.left.terms.keys())
            if gen.right is not None:
                deps |= set(gen.right.terms.keys())
            if not deps.issubset(known):
                still_pending.append(gen)
                continue

            if gen.kind == "lc":
                witness[gen.wire] = eval_lc(gen.left, witness, circuit.modulus)
            elif gen.kind == "mul" and gen.right is not None:
                left = eval_lc(gen.left, witness, circuit.modulus)
                right = eval_lc(gen.right, witness, circuit.modulus)
                witness[gen.wire] = (left * right) % circuit.modulus
            else:
                still_pending.append(gen)
                continue

            known.add(gen.wire)
            progress = True
        pending = still_pending
    return witness


def set_witness_value(circuit: Circuit, witness: List[int], name: str, value: int) -> None:
    wire = circuit.name_to_wire[name]
    witness[wire] = field_normalize(value, circuit.modulus)


def demo_program_linear_and_mul() -> List[Stmt]:
    x = Var("x")
    y = Var("y")
    z = Var("z")
    return [
        Let("z", Add(Add(Mul(x, y), x), Const(3))),
        AssertEq(z, Add(Add(Mul(x, y), x), Const(3))),
    ]


def demo_program_u32_add() -> List[Stmt]:
    a = Var("a")
    b = Var("b")
    s = Var("s")
    return [
        RangeCheck(a, 32),
        RangeCheck(b, 32),
        Let("s", Add(a, b)),
        RangeCheck(s, 32),
    ]


def demo_program_unconstrained_product(also_constrain: bool) -> List[Stmt]:
    x = Var("x")
    y = Var("y")
    out = Var("out")
    stmts: List[Stmt] = [Let("out", Mul(x, y), constrained=False)]
    if also_constrain:
        stmts.append(AssertEq(out, Mul(x, y)))
    return stmts


def _print_kv(items: Iterable[Tuple[str, object]]) -> None:
    for k, v in items:
        print(f"{k}: {v}")


def _load_vectors_json() -> Dict[str, object]:
    here = pathlib.Path(__file__).resolve()
    vectors_path = here.parent.parent / "tests" / "vectors.json"
    return json.loads(vectors_path.read_text(encoding="utf-8"))


def main():
    print("=== Step 1: A Tiny Noir-Like AST ===")
    program = demo_program_linear_and_mul()
    env = execute_program(program, {"x": 7, "y": 11})
    _print_kv([("x", env["x"]), ("y", env["y"]), ("z", env["z"])])

    print("\n=== Step 2: Compile to Constraints (R1CS-ish) ===")
    circuit = compile_to_circuit(program)
    witness = witness_from_env(circuit, env)
    ok = circuit_is_satisfied(circuit, witness)
    _print_kv([("num_wires", circuit.num_wires), ("num_constraints", len(circuit.constraints)), ("satisfied", ok)])

    print("\n=== Step 3: Add u32 Range Checks ===")
    u32_prog = demo_program_u32_add()
    u32_circuit = compile_to_circuit(u32_prog)

    safe_env = execute_program(u32_prog, {"a": (1 << 32) - 1, "b": 0})
    safe_witness = witness_from_env(u32_circuit, safe_env)
    _print_kv([("a", safe_env["a"]), ("b", safe_env["b"]), ("s", safe_env["s"]), ("satisfied", circuit_is_satisfied(u32_circuit, safe_witness))])

    overflow_env = execute_program(u32_prog, {"a": (1 << 32) - 1, "b": 1})
    overflow_witness = witness_from_env(u32_circuit, overflow_env)
    _print_kv([("a", overflow_env["a"]), ("b", overflow_env["b"]), ("s", overflow_env["s"]), ("satisfied", circuit_is_satisfied(u32_circuit, overflow_witness))])

    print("\n=== Step 4: Spot Underconstrained Computation ===")
    unconstrained_prog = demo_program_unconstrained_product(also_constrain=False)
    unconstrained_circuit = compile_to_circuit(unconstrained_prog)
    honest_env = execute_program(unconstrained_prog, {"x": 9, "y": 13})
    honest_witness = witness_from_env(unconstrained_circuit, honest_env)
    _print_kv([("honest_out", honest_env["out"]), ("satisfied", circuit_is_satisfied(unconstrained_circuit, honest_witness))])

    malicious_witness = list(honest_witness)
    set_witness_value(unconstrained_circuit, malicious_witness, "out", 123456)
    _print_kv([("malicious_out", 123456), ("satisfied", circuit_is_satisfied(unconstrained_circuit, malicious_witness))])

    fixed_prog = demo_program_unconstrained_product(also_constrain=True)
    fixed_circuit = compile_to_circuit(fixed_prog)
    fixed_env = execute_program(fixed_prog, {"x": 9, "y": 13})
    fixed_witness = witness_from_env(fixed_circuit, fixed_env)
    fixed_malicious = list(fixed_witness)
    set_witness_value(fixed_circuit, fixed_malicious, "out", 123456)
    _print_kv(
        [
            ("fixed_satisfied_honest", circuit_is_satisfied(fixed_circuit, fixed_witness)),
            ("fixed_satisfied_malicious", circuit_is_satisfied(fixed_circuit, fixed_malicious)),
        ]
    )

    vectors = _load_vectors_json()
    print("\nVectors loaded:", len(vectors.get("vectors", [])))


if __name__ == "__main__":
    main()
