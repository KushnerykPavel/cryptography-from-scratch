"""Arithmetic circuits from scratch (field + gates + witness checking).

Run:
  python3 code/main.py

This lesson builds a tiny arithmetic-circuit representation over a prime field,
evaluates a circuit on concrete inputs, and checks whether a full wire
assignment (a "witness") satisfies every gate constraint.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


def is_prime(n: int) -> bool:
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2
    return True


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def mod_inv(a: int, mod: int) -> int:
    a = a % mod
    if a == 0:
        raise ValueError("0 has no inverse modulo mod")
    g, x, _y = egcd(a, mod)
    if g != 1:
        raise ValueError("a and mod are not coprime")
    return x % mod


@dataclass(frozen=True)
class PrimeField:
    mod: int

    def __post_init__(self) -> None:
        if not is_prime(self.mod):
            raise ValueError("field modulus must be prime")

    def n(self, x: int) -> int:
        return x % self.mod

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.mod

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.mod

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.mod

    def inv(self, a: int) -> int:
        return mod_inv(a, self.mod)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def pow(self, a: int, e: int) -> int:
        return pow(a % self.mod, e, self.mod)


@dataclass(frozen=True)
class Gate:
    op: str  # "const" | "add" | "mul"
    out: int
    left: Optional[int] = None
    right: Optional[int] = None
    value: Optional[int] = None


@dataclass(frozen=True)
class ArithmeticCircuit:
    field: PrimeField
    num_wires: int
    input_wires: list[int]
    output_wire: int
    gates: list[Gate]

    def evaluate(self, inputs: list[int]) -> list[int]:
        if len(inputs) != len(self.input_wires):
            raise ValueError("wrong number of inputs")

        w = [0] * self.num_wires
        for wire, val in zip(self.input_wires, inputs):
            w[wire] = self.field.n(val)

        for gate in self.gates:
            if gate.op == "const":
                if gate.value is None:
                    raise ValueError("const gate missing value")
                w[gate.out] = self.field.n(gate.value)
                continue

            if gate.left is None or gate.right is None:
                raise ValueError("binary gate missing input wires")
            if gate.op == "add":
                w[gate.out] = self.field.add(w[gate.left], w[gate.right])
                continue
            if gate.op == "mul":
                w[gate.out] = self.field.mul(w[gate.left], w[gate.right])
                continue

            raise ValueError("unknown gate op")

        return w

    def check_witness(
        self,
        witness: list[int],
        *,
        inputs: Optional[list[int]] = None,
        expected_output: Optional[int] = None,
    ) -> bool:
        if len(witness) != self.num_wires:
            raise ValueError("bad witness length")

        w = [self.field.n(x) for x in witness]

        if inputs is not None:
            if len(inputs) != len(self.input_wires):
                raise ValueError("wrong number of inputs")
            for wire, val in zip(self.input_wires, inputs):
                if w[wire] != self.field.n(val):
                    return False

        for gate in self.gates:
            if gate.op == "const":
                if gate.value is None:
                    raise ValueError("const gate missing value")
                if w[gate.out] != self.field.n(gate.value):
                    return False
                continue

            if gate.left is None or gate.right is None:
                raise ValueError("binary gate missing input wires")
            if gate.op == "add":
                if w[gate.out] != self.field.add(w[gate.left], w[gate.right]):
                    return False
                continue
            if gate.op == "mul":
                if w[gate.out] != self.field.mul(w[gate.left], w[gate.right]):
                    return False
                continue
            raise ValueError("unknown gate op")

        if expected_output is not None:
            return w[self.output_wire] == self.field.n(expected_output)
        return True


class CircuitBuilder:
    def __init__(self, field: PrimeField):
        self.field = field
        self.gates: list[Gate] = []
        self.input_wires: list[int] = []
        self.next_wire = 0

    def new_input(self) -> int:
        w = self.next_wire
        self.next_wire += 1
        self.input_wires.append(w)
        return w

    def const(self, value: int) -> int:
        w = self.next_wire
        self.next_wire += 1
        self.gates.append(Gate(op="const", out=w, value=self.field.n(value)))
        return w

    def add(self, left: int, right: int) -> int:
        w = self.next_wire
        self.next_wire += 1
        self.gates.append(Gate(op="add", out=w, left=left, right=right))
        return w

    def mul(self, left: int, right: int) -> int:
        w = self.next_wire
        self.next_wire += 1
        self.gates.append(Gate(op="mul", out=w, left=left, right=right))
        return w

    def build(self, output_wire: int) -> ArithmeticCircuit:
        if not (0 <= output_wire < self.next_wire):
            raise ValueError("bad output wire")
        return ArithmeticCircuit(
            field=self.field,
            num_wires=self.next_wire,
            input_wires=list(self.input_wires),
            output_wire=output_wire,
            gates=list(self.gates),
        )


def build_x3_plus_x_plus_5(field: PrimeField) -> ArithmeticCircuit:
    b = CircuitBuilder(field)
    x = b.new_input()
    five = b.const(5)
    x2 = b.mul(x, x)
    x3 = b.mul(x2, x)
    x3_plus_x = b.add(x3, x)
    out = b.add(x3_plus_x, five)
    return b.build(out)


def step_1_field() -> PrimeField:
    print("=== Step 1: Prime-field arithmetic ===")
    field = PrimeField(97)
    a, b = 45, 80
    print(f"field = F_{field.mod}")
    print(f"a={a}, b={b}")
    print(f"(a + b) mod p = {field.add(a, b)}")
    print(f"(a * b) mod p = {field.mul(a, b)}")
    print(f"inv(a) mod p = {field.inv(a)} (check: a*inv(a)={field.mul(a, field.inv(a))})")
    return field


def step_2_circuit_model(field: PrimeField) -> ArithmeticCircuit:
    print("=== Step 2: Build an arithmetic circuit ===")
    c = build_x3_plus_x_plus_5(field)
    print("function: f(x) = x^3 + x + 5  (all arithmetic mod p)")
    print(f"wires: {c.num_wires}, inputs: {c.input_wires}, output: {c.output_wire}, gates: {len(c.gates)}")
    return c


def step_3_evaluate(c: ArithmeticCircuit) -> list[int]:
    print("=== Step 3: Evaluate the circuit (compute a witness) ===")
    x = 3
    w = c.evaluate([x])
    print(f"input x = {x}")
    print(f"output wire value = {w[c.output_wire]}")
    print(f"full witness (wire -> value): {list(enumerate(w))}")
    return w


def step_4_check_witness(c: ArithmeticCircuit, witness: list[int]) -> None:
    print("=== Step 4: Check witness satisfiability ===")
    x = witness[c.input_wires[0]]
    out = witness[c.output_wire]
    ok = c.check_witness(witness, inputs=[x], expected_output=out)
    print(f"witness satisfies all gates: {ok}")

    bad = list(witness)
    bad[c.output_wire] = c.field.add(bad[c.output_wire], 1)
    ok_bad = c.check_witness(bad, inputs=[x], expected_output=out)
    print(f"tampered output still verifies: {ok_bad}")

def main() -> None:
    field = step_1_field()
    circuit = step_2_circuit_model(field)
    witness = step_3_evaluate(circuit)
    step_4_check_witness(circuit, witness)


if __name__ == "__main__":
    main()
