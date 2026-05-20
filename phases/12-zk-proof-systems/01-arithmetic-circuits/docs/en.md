# Arithmetic Circuits — The Universal Computer
> Programs become constraints: “this output came from that computation.”

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/02-abstract-algebra/07-finite-fields-gf-p`, `phases/11-zero-knowledge-foundations/01-what-zk-means`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why ZK proof systems arithmetize programs into add/mul circuits over a field.
- Compute a circuit output by evaluating add/mul gates in `F_p`.
- Implement a tiny arithmetic-circuit DSL (wires + gates) and evaluate it to produce a witness.
- Distinguish evaluating a circuit (forward compute) from checking a witness (constraint satisfaction).
- Apply a witness checker to detect tampering and underconstrained expectations early.

## The Problem

Every modern ZK proof system starts with the same first step: turn “the program I
want to prove I ran” into something algebraic the verifier can check quickly.
That “something” is almost always an **arithmetic circuit** (or a close cousin).

If you don’t understand arithmetic circuits, the rest of the SNARK/STARK
pipeline looks like spellcasting: R1CS constraints, QAP polynomials, PLONK gates,
STARK traces — all of them are just different ways to say “this set of
equations is satisfiable.”

In this lesson you build a tiny circuit model (wires + add/mul/const gates),
evaluate it on concrete inputs to compute a full wire assignment (a **witness**),
and then check that a proposed witness actually satisfies every gate equation.
That “check” is the core of what proof systems make efficient.

## The Concept

An arithmetic circuit is a directed acyclic graph of gates that compute over a
finite field `F_p`:

- **Wires** carry field elements (integers modulo `p`).
- **Gates** are equations like `c = a + b` or `c = a * b` (all modulo `p`).
- A **witness** assigns a value to every wire so that every gate equation holds.

Think of it as “a program with no control flow”: you only get addition and
multiplication, but you get as many intermediate wires as you want.

Example: compute `f(x) = x^3 + x + 5` in `F_p`.

You can represent this as a sequence of intermediate wires:

| Wire | Meaning |
|------|---------|
| `x` | input |
| `x2` | `x * x` |
| `x3` | `x2 * x` |
| `x3_plus_x` | `x3 + x` |
| `out` | `x3_plus_x + 5` |

Evaluation is just computing those wires forward. Checking is verifying that a
provided assignment satisfies each gate equation (even if the prover tries to
cheat).

## Build It

### Step 1: Prime-field arithmetic
```python
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
```
Arithmetic circuits live in a field. The proof system is checking equations in
`F_p`, not “integers”, so we carry a modulus and reduce every operation.

### Step 2: Build an arithmetic circuit
```python
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
```
This is the smallest useful circuit model: we can generate new wires, record
gates, evaluate to compute a witness, and check whether a witness is valid.

### Step 3: Evaluate the circuit (compute a witness)
```python
def build_x3_plus_x_plus_5(field: PrimeField) -> ArithmeticCircuit:
    b = CircuitBuilder(field)
    x = b.new_input()
    five = b.const(5)
    x2 = b.mul(x, x)
    x3 = b.mul(x2, x)
    x3_plus_x = b.add(x3, x)
    out = b.add(x3_plus_x, five)
    return b.build(out)
```
We encode `f(x) = x^3 + x + 5` as a sequence of add/mul gates. Calling
`evaluate([x])` produces the full wire assignment (the witness).

### Step 4: Check witness satisfiability
```python
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
```
In ZK, the prover can propose any witness it wants. The verifier (or prover-side
constraint system) must reject witnesses that don’t satisfy the gate equations.

Run it:
`python3 code/main.py`

## Use It

Production systems don’t expose “raw gates”; they expose a DSL that compiles to
constraints, and then the proof system runs over those constraints.

| Tooling | What you write | What it becomes |
|---------|----------------|-----------------|
| Circom | constraints with components | R1CS |
| Noir | a Rust-like circuit language | an arithmetic circuit / R1CS-ish constraints |
| Halo2 | plonkish “regions” + gates | PLONKish constraints |
| gnark | Go DSL for circuits | R1CS or PLONK-ish backends |
| arkworks | Rust constraint systems | R1CS |

Your `Gate` list is the same idea, just without the ergonomics, optimizations,
or proof backend.

## Pitfalls

- **Underconstrained circuits:** “we compute it in the witness generator” is not a constraint. If it isn’t checked, a prover can lie.
- **Mixing fields:** the same integer means different things in different moduli; cross-field arithmetic silently changes the statement.
- **Missing boolean/range constraints:** field elements are not “ints < 2^k” unless you explicitly constrain them.
- **Relying on division/inverses without guards:** circuits over `F_p` can divide by any nonzero value, but “nonzero” must be enforced.
- **Confusing evaluation with verification:** a correct witness generator does not imply a sound circuit.

## Ship It

Save and reuse this artifact:
`outputs/zk-arithmetic-circuit-review-checklist.md`

Use it when reviewing a circuit PR/spec: it forces the statement/witness split,
checks field consistency, and looks for missing constraints (the most common
real-world circuit bug class).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that changing a single wire breaks witness verification.
2. Medium. Extend `build_x3_plus_x_plus_5` to a two-input function (e.g., `f(x,y)=x*y + x + 7`) and add a few vectors to `tests/vectors.json`.
3. Hard. Add a “boolean wire” helper that constrains a wire to be 0/1 using `b*(b-1)=0`, then demonstrate how the checker catches non-boolean assignments.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Arithmetic circuit | “a circuit” | A DAG of add/mul equations over a field |
| Wire | “a variable” | A slot holding a field element in the witness |
| Gate | “a constraint” | An equation relating input wires to an output wire |
| Witness | “the secret” | Values for all wires that satisfy all gate equations |
| Underconstrained | “missing checks” | The equations don’t enforce an intended property |

## Further Reading

- Vitalik Buterin, *Quadratic Arithmetic Programs: from Zero to Hero* (2016) — a friendly bridge from circuits to QAP/R1CS.
- Jens Groth, *On the Size of Pairing-based Non-interactive Arguments* (2016) — Groth16: where R1CS meets pairings.
- Eli Ben-Sasson et al., *Scalable, transparent, and post-quantum secure computational integrity* (2018) — STARKs: arithmetization + polynomial IOPs.
