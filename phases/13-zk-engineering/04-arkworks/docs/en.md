# arkworks — Multi-Backend Proving (Relation vs Backend)

> Write the relation once; swap the backend later.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 12 · 01 (Arithmetic Circuits), Phase 12 · 02 (R1CS), Phase 12 · 05 (Groth16)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why ZK stacks split “relation/circuit” from “proof system backend”.
- **Distinguish** public inputs vs witness vs constants in an R1CS witness vector.
- **Implement** a tiny circuit frontend that runs in “native eval” and “constraint compile” modes.
- **Compute** whether a witness satisfies an R1CS, and locate the first failing constraint.
- **Apply** the separation to real arkworks code organization (gadgets, relations, SNARK crates).

## The Problem

You ship a ZK feature and six months later the backend changes: Groth16 → Plonk, or one curve → another, or CPU prover → GPU prover. If your application logic is entangled with backend details, this “swap” becomes a rewrite: circuit code changes, test fixtures change, public-input ordering changes, and you lose confidence that you proved the same statement.

The arkworks ecosystem exists to make the swap boring. Your *relation* (what is being proven) should be independent from the *backend* (how the proof is constructed/verified). That separation is the difference between “we can benchmark backends” and “we are stuck with our first choice forever”.

This lesson builds a tiny toy model of that architecture in Python: the same circuit runs in two modes (native evaluation for witness generation, and R1CS compilation for proving backends).

## The Concept

Think in layers:

| Layer | You write | Output | Changes when you switch backends? |
|---|---|---|---|
| **Relation / Circuit** | “Given witness `x`, public `out`, enforce `out = x^3 + x + 5`.” | A set of constraints (or AIR, etc.) | Ideally **no** |
| **Backend / Proof system** | Groth16 / Marlin / Plonk / STARK / ZKVM | Proof + verification logic | **Yes** |

An R1CS instance is “one multiplication per constraint”:

```
⟨A, z⟩ · ⟨B, z⟩ = ⟨C, z⟩
```

where `z = [1, public..., witness...]` is the witness vector. Constants appear as coefficients on the `1` wire (`z[0] = 1`), not as magical literals.

Why the separation matters in practice:

- **Witness generation is native code.** You compute intermediate values efficiently on the CPU.
- **Constraint generation is symbolic.** You emit constraints that a backend can arithmetize into its own representation (R1CS → QAP for Groth16, R1CS → polynomial IOP for Plonk-ish systems, etc.).
- **You want both from the same source of truth.** If your native computation and your constraints drift apart, you get “it runs” but “it won’t prove”.

## Build It

### Step 1: Prime-field arithmetic (the shared base layer)

```python
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


def cubic_output(x: int, p: int, *, constant: int) -> int:
    x = modp(x, p)
    return modp(x * x * x + x + constant, p)
```

Both “native eval” and “constraint compile” must agree on the field. In real arkworks code this is `ark_ff::PrimeField`; the backend choice doesn’t change the field operations you express inside the relation.

### Step 2: A backend-generic circuit API (what you want to stay stable)

```python
from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Var:
    idx: int
    label: str


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
```

This is the “frontend”: it defines the vocabulary circuits use (`witness`, `public`, `add`, `mul`, `assert_eq`). The whole point is that your circuit function will be written once against this API.

### Step 3: Compile to R1CS (a backend consumes constraints, not your Python code)

```python
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


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


def first_unsatisfied(constraints: Sequence[Constraint], witness: Sequence[int], p: int) -> Optional[int]:
    for i, con in enumerate(constraints):
        if not check_constraint(con, witness, p):
            return i
    return None


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

    def _con(
        self,
        a_terms: Iterable[Tuple[int, int]],
        b_terms: Iterable[Tuple[int, int]],
        c_terms: Iterable[Tuple[int, int]],
    ) -> None:
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
```

This backend emits constraints instead of throwing an exception. In real arkworks terms: your circuit’s `generate_constraints` method calls `cs.enforce_constraint(...)` and the SNARK backend consumes the resulting constraint system.

### Step 4: Write the relation once, then run it on both backends

```python
def cubic_relation_circuit(api: CircuitAPI, *, x_value: int, out_value: int, constant: int) -> Tuple[Var, Var]:
    out = api.public(out_value, label="out")
    x = api.witness(x_value, label="x")
    x2 = api.mul(x, x, label="x2")
    x3 = api.mul(x2, x, label="x3")
    x3_plus_x = api.add(x3, x, label="x3_plus_x")
    rhs = api.add(x3_plus_x, api.const(constant, label="k"), label="rhs")
    api.assert_eq(rhs, out, label="out_matches_rhs")
    return x, out
```

The function above is the stable “relation”. The `EvalBackend` will compute values and raise if the relation is false. The `R1CSBackend` will record constraints that other backends (Groth16/Plonk/Marlin) could consume.

Run it:

`python3 code/main.py`

## Use It

In real arkworks projects the mapping is:

- **Field / curves:** `ark-ff`, `ark-ec`, `ark-poly`
- **Relations:** `ark-relations` (R1CS, `ConstraintSynthesizer`)
- **Circuit building:** `ark-r1cs-std` (gadgets like `FpVar`, `Boolean`, hash gadgets)
- **Proof systems:** `ark-groth16`, `ark-marlin`, `ark-plonk` (or other crates)
- **Generic SNARK interface:** `ark-snark` traits (backend-agnostic calling code)

Typical flow:

1. Implement a circuit (a Rust struct) that implements `ConstraintSynthesizer<F>`.
2. Run it once in “setup” mode to generate keys/parameters.
3. Run it again in “prove” mode with a witness to produce a proof.
4. Verify with the public inputs in the exact order the circuit declared.

## Pitfalls

- **Public input ordering drift.** Verifier uses an ordered vector; “same values, different order” is a different statement.
- **Constants accidentally unconstrained.** If a constant becomes a witness without an equality constraint, the prover can “choose” it.
- **Native vs constraint mismatch.** Witness generator computes `rhs` one way; constraint system enforces another.
- **Over-allocating intermediates.** Every multiplication needs a constraint; careless gadget composition explodes constraint count.
- **Debugging without a failing-constraint index.** You want “first unsatisfied constraint” tooling early.

## Ship It

Save the reusable PR review checklist in `outputs/arkworks-circuit-review-checklist.md`. Use it when reviewing circuits that claim to be backend-agnostic: it catches input-order bugs, unconstrained constants, and “it runs but won’t prove” drift.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the “wrong public out” fails at the last constraint.
2. Medium. Extend the circuit to prove `out = x^5 + x + 5` while keeping the same backend-generic API. Update vectors/tests.
3. Hard. Production integration: sketch (in Rust) how the same relation would be expressed as an arkworks `ConstraintSynthesizer` using `FpVar` and `enforce_equal`.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Relation | “The thing you prove” | A predicate over (public inputs, witness) that must hold. |
| Backend | “Groth16/Plonk/etc.” | The proof system + cryptographic machinery that proves the relation. |
| Witness | “Private inputs” | Values only the prover knows, including intermediates. |
| Public input | “Statement” | Values the verifier knows and binds the proof to. |
| Constraint | “A gate” | In R1CS, one equation `⟨A,z⟩·⟨B,z⟩=⟨C,z⟩`. |

## Further Reading

- arkworks contributors, *arkworks zkSNARK ecosystem* (2022) — ecosystem index of crates and their roles.
- Bowe, Gabizon, Green, *Groth16* (2016) — the canonical preprocessing SNARK for R1CS → QAP.
- ark-relations source, *ConstraintSynthesizer* — how circuits generate constraints (`generate_constraints` / `enforce_constraint`).
