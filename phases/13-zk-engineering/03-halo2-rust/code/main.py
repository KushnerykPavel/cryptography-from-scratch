"""
Toy Halo2 (PLONKish) circuit model in pure Python.

This script builds a tiny constraint system with:
- advice / instance / fixed columns (as a table of rows),
- selectors that enable gates on specific rows,
- copy (equality) constraints between arbitrary cells,
- a "lookup-like" range check via a vanishing polynomial.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Sequence


MODULUS = 97


@dataclass(frozen=True)
class F:
    n: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "n", self.n % MODULUS)

    @staticmethod
    def from_int(x: int) -> "F":
        return F(x)

    def __int__(self) -> int:
        return self.n

    def __add__(self, other: "F") -> "F":
        return F(self.n + other.n)

    def __sub__(self, other: "F") -> "F":
        return F(self.n - other.n)

    def __mul__(self, other: "F") -> "F":
        return F(self.n * other.n)

    def __neg__(self) -> "F":
        return F(-self.n)

    def __pow__(self, exp: int) -> "F":
        return F(pow(self.n, exp, MODULUS))

    def inv(self) -> "F":
        if self.n == 0:
            raise ZeroDivisionError("0 has no inverse in a field")
        return self ** (MODULUS - 2)

    def __truediv__(self, other: "F") -> "F":
        return self * other.inv()


def fe(x: int) -> F:
    return F.from_int(x)


class ColumnType(str, Enum):
    ADVICE = "advice"
    FIXED = "fixed"
    INSTANCE = "instance"


@dataclass(frozen=True)
class Column:
    col_type: ColumnType
    index: int


@dataclass(frozen=True)
class Selector:
    index: int


@dataclass(frozen=True)
class Cell:
    column: Column
    row: int


@dataclass(frozen=True)
class Gate:
    name: str
    selector: Selector | None
    constraints: Callable[["Assignment", int], Sequence[F]]


class Assignment:
    def __init__(self) -> None:
        self._values: dict[tuple[ColumnType, int], dict[int, F]] = {}
        self._selectors: dict[int, set[int]] = {}

    def assign(self, column: Column, row: int, value: int | F) -> Cell:
        if row < 0:
            raise ValueError("row must be non-negative")
        key = (column.col_type, column.index)
        col = self._values.setdefault(key, {})
        col[row] = value if isinstance(value, F) else fe(value)
        return Cell(column=column, row=row)

    def enable(self, selector: Selector, row: int) -> None:
        if row < 0:
            raise ValueError("row must be non-negative")
        self._selectors.setdefault(selector.index, set()).add(row)

    def selector_value(self, selector: Selector, row: int) -> F:
        enabled = row in self._selectors.get(selector.index, set())
        return fe(1 if enabled else 0)

    def query(self, column: Column, row: int) -> F:
        key = (column.col_type, column.index)
        if key not in self._values or row not in self._values[key]:
            raise KeyError(f"unassigned cell: {column.col_type}:{column.index} row={row}")
        return self._values[key][row]

    def max_row(self) -> int:
        rows: list[int] = []
        for col in self._values.values():
            rows.extend(col.keys())
        for enabled_rows in self._selectors.values():
            rows.extend(list(enabled_rows))
        return (max(rows) + 1) if rows else 0


class ConstraintSystem:
    def __init__(self) -> None:
        self._next_index: dict[ColumnType, int] = {t: 0 for t in ColumnType}
        self._next_selector: int = 0
        self.gates: list[Gate] = []
        self.equalities: list[tuple[Cell, Cell]] = []

    def new_column(self, col_type: ColumnType) -> Column:
        idx = self._next_index[col_type]
        self._next_index[col_type] = idx + 1
        return Column(col_type=col_type, index=idx)

    def new_selector(self) -> Selector:
        idx = self._next_selector
        self._next_selector = idx + 1
        return Selector(index=idx)

    def create_gate(
        self,
        name: str,
        selector: Selector | None,
        constraints: Callable[[Assignment, int], Sequence[F]],
    ) -> None:
        self.gates.append(Gate(name=name, selector=selector, constraints=constraints))

    def constrain_equal(self, left: Cell, right: Cell) -> None:
        self.equalities.append((left, right))

    def is_satisfied(self, assignment: Assignment) -> tuple[bool, list[str]]:
        failures: list[str] = []

        for (left, right) in self.equalities:
            lv = assignment.query(left.column, left.row)
            rv = assignment.query(right.column, right.row)
            if lv != rv:
                failures.append(
                    f"equality failed: ({left.column.col_type}:{left.column.index}, row {left.row}) "
                    f"!= ({right.column.col_type}:{right.column.index}, row {right.row})"
                )

        for gate in self.gates:
            for row in range(assignment.max_row()):
                if gate.selector is not None and int(assignment.selector_value(gate.selector, row)) == 0:
                    continue
                for i, c in enumerate(gate.constraints(assignment, row)):
                    if int(c) != 0:
                        failures.append(f"gate failed: {gate.name} row={row} constraint#{i} value={int(c)}")

        return (len(failures) == 0), failures


def mul_residual(a: int, b: int, c: int) -> int:
    return int(fe(a) * fe(b) - fe(c))


def vanishing_product(x: int, allowed: Iterable[int]) -> int:
    acc = fe(1)
    fx = fe(x)
    for v in allowed:
        acc = acc * (fx - fe(v))
    return int(acc)


def build_mul_circuit() -> tuple[ConstraintSystem, dict[str, Column], Selector]:
    cs = ConstraintSystem()
    a = cs.new_column(ColumnType.ADVICE)
    b = cs.new_column(ColumnType.ADVICE)
    c = cs.new_column(ColumnType.ADVICE)
    out = cs.new_column(ColumnType.INSTANCE)
    q_mul = cs.new_selector()

    def mul_gate(assn: Assignment, row: int) -> Sequence[F]:
        q = assn.selector_value(q_mul, row)
        av = assn.query(a, row)
        bv = assn.query(b, row)
        cv = assn.query(c, row)
        return [q * (av * bv - cv)]

    cs.create_gate("mul: a*b=c", q_mul, mul_gate)
    return cs, {"a": a, "b": b, "c": c, "out": out}, q_mul


def assign_mul_witness(
    assignment: Assignment, cols: dict[str, Column], selector: Selector, a: int, b: int, row: int = 0
) -> None:
    assignment.enable(selector, row)
    assignment.assign(cols["a"], row, a)
    assignment.assign(cols["b"], row, b)
    assignment.assign(cols["c"], row, fe(a) * fe(b))


def expose_public_output(cs: ConstraintSystem, assignment: Assignment, cols: dict[str, Column], row: int = 0) -> None:
    c_cell = Cell(column=cols["c"], row=row)
    out_cell = assignment.assign(cols["out"], row, assignment.query(cols["c"], row))
    cs.constrain_equal(c_cell, out_cell)


def add_range_gate(cs: ConstraintSystem, x_col: Column, selector: Selector, allowed: Sequence[int]) -> None:
    def range_gate(assn: Assignment, row: int) -> Sequence[F]:
        q = assn.selector_value(selector, row)
        x = assn.query(x_col, row)
        acc = fe(1)
        for v in allowed:
            acc = acc * (x - fe(v))
        return [q * acc]

    cs.create_gate(f"in-set: {allowed[0]}..{allowed[-1]}", selector, range_gate)


def main() -> None:
    print("=== Step 1: Field arithmetic (mod p) ===")
    x = fe(42)
    y = fe(70)
    print("p =", MODULUS)
    print("x =", int(x), "y =", int(y))
    print("x + y =", int(x + y))
    print("x * y =", int(x * y))
    print("y / x =", int(y / x))
    print()

    print("=== Step 2: Constraint systems (columns, selectors, gates) ===")
    cs, cols, q_mul = build_mul_circuit()
    assn = Assignment()
    assign_mul_witness(assn, cols, q_mul, a=7, b=11, row=0)
    expose_public_output(cs, assn, cols, row=0)
    ok, failures = cs.is_satisfied(assn)
    print("satisfied =", ok)
    if not ok:
        for f in failures:
            print(" -", f)
    print()

    print("=== Step 3: Copy constraints (equality across cells) ===")
    assn2 = Assignment()
    cs2, cols2, q_mul2 = build_mul_circuit()
    assign_mul_witness(assn2, cols2, q_mul2, a=9, b=9, row=0)
    assn2.enable(q_mul2, 1)
    a1 = assn2.assign(cols2["a"], 1, assn2.query(cols2["a"], 0))
    b1 = assn2.assign(cols2["b"], 1, 5)
    c1 = assn2.assign(cols2["c"], 1, assn2.query(cols2["a"], 0) * fe(5))
    cs2.constrain_equal(Cell(cols2["a"], 0), a1)
    expose_public_output(cs2, assn2, cols2, row=0)
    ok2, failures2 = cs2.is_satisfied(assn2)
    print("row0 a*b=c with row1 reusing a via copy constraint")
    print("satisfied =", ok2)
    if not ok2:
        for f in failures2:
            print(" -", f)
    print()

    print("=== Step 4: Range checks via a vanishing polynomial (toy lookup) ===")
    cs3 = ConstraintSystem()
    x_col = cs3.new_column(ColumnType.ADVICE)
    q_range = cs3.new_selector()
    add_range_gate(cs3, x_col, q_range, allowed=list(range(16)))
    assn3 = Assignment()
    assn3.enable(q_range, 0)
    assn3.assign(x_col, 0, 13)
    ok3, failures3 = cs3.is_satisfied(assn3)
    print("x=13 in [0..15] satisfied =", ok3, "(residual", vanishing_product(13, range(16)), ")")
    assn3_bad = Assignment()
    assn3_bad.enable(q_range, 0)
    assn3_bad.assign(x_col, 0, 42)
    ok4, failures4 = cs3.is_satisfied(assn3_bad)
    print("x=42 in [0..15] satisfied =", ok4, "(residual", vanishing_product(42, range(16)), ")")
    if not ok4:
        print("first failure =", failures4[0] if failures4 else "unknown")


if __name__ == "__main__":
    main()
