# KZG Polynomial Commitments (Toy)

> Commit once; prove any evaluation with one short witness.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 09 · 01 (Hash commitments), Phase 09 · 02 (Pedersen commitments, recommended), Phase 09 · 03 (Vector commitments, recommended)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what a KZG commitment binds you to (a whole polynomial), and why verification is constant-size.
- **Compute** polynomial evaluations in a finite field `F_q` and divide by `(x - z)` to get the quotient polynomial.
- **Implement** a toy pairing check that enforces the identity `f(s) - f(z) = q(s)·(s - z)` “in the exponent”.
- **Distinguish** the public SRS (`[s^i]`) from the secret toxic waste (`s`) and what breaks if `s` leaks.
- **Apply** KZG openings to “data integrity at one point”: proving a single value matches a committed dataset encoding.

## The Problem

You want to publish a **small commitment** to a large dataset that you interpret as a polynomial `f(x)` over a finite field. Later, someone asks: “What is `f(z)` at this specific point `z`?” You want to answer with a **short proof** that is cheap to verify — without sending the whole polynomial.

This pattern shows up everywhere in modern ZK and blockchain systems: data availability sampling, polynomial IOPs, and commitment layers inside SNARKs. If your “proof” is the whole polynomial (all coefficients), verification is huge and bandwidth-bound. If your “proof” is only a hash, you can’t open it at arbitrary points without revealing everything.

KZG (Kate-Zaverucha-Goldberg) polynomial commitments solve this: a single group element commits to the polynomial, and an **opening at a point** is another single group element. Verification is one pairing equation, regardless of the polynomial degree (within the SRS limit).

## The Concept

### Commit to a polynomial “at a secret point” without knowing the point

Let `f(x) = a_0 + a_1 x + ... + a_d x^d` be a polynomial over `F_q`.

A trusted setup samples a secret `s ∈ F_q` (the “toxic waste”) and publishes an SRS:

- in `G1`: `[1]`, `[s]`, `[s^2]`, ..., `[s^d]`
- in `G2`: `[1]`, `[s]` (enough for single-point openings)

Here `[t]` means “the group element corresponding to scalar `t` times the generator”.

The commitment is a dot product:

`C = [f(s)] = Σ a_i · [s^i]`.

No one learns `s`, but everyone can compute `C` because the `[s^i]` are public.

### Open at one point

To prove that `f(z) = y`, define the quotient polynomial:

`q(x) = (f(x) - y) / (x - z)`.

By construction, we have the polynomial identity:

`f(x) - y = (x - z)·q(x)`.

Evaluate it at the secret `s`:

`f(s) - y = (s - z)·q(s)`.

KZG sends the witness `π = [q(s)]`. A verifier checks the above identity **in the exponent** using a bilinear pairing `e`:

`e(C - [y], [1]) == e(π, [s] - [z])`.

This lesson uses a toy pairing that makes the algebra visible (it tracks the hidden scalars); real systems do this on pairing-friendly elliptic curves.

## Build It

### Step 1: Finite-field polynomials (eval in `F_q`)

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


def mod_norm(x: int, mod: int) -> int:
    if mod <= 1:
        raise ValueError("mod must be > 1")
    return x % mod


def mod_inv(x: int, mod: int) -> int:
    x = mod_norm(x, mod)
    if x == 0:
        raise ZeroDivisionError("division by zero in field")
    return pow(x, -1, mod)


def poly_trim(coeffs: Sequence[int]) -> List[int]:
    out = list(coeffs)
    while len(out) > 0 and out[-1] == 0:
        out.pop()
    return out


def poly_eval(coeffs: Sequence[int], x: int, mod: int) -> int:
    x = mod_norm(x, mod)
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + (c % mod)) % mod
    return acc
```

We represent a polynomial by a coefficient list `[a0, a1, ..., ad]` meaning `f(x) = Σ a_i x^i`. `poly_eval` uses Horner’s method to evaluate in `F_q`.

### Step 2: Divide by `(x - z)` via synthetic division

```python
def poly_divmod_x_minus_z(coeffs: Sequence[int], z: int, mod: int) -> Tuple[List[int], int]:
    z = mod_norm(z, mod)
    if len(coeffs) == 0:
        raise ValueError("polynomial must be non-empty")

    desc = [c % mod for c in reversed(coeffs)]  # a_n .. a_0
    b: List[int] = [desc[0]]
    for i in range(1, len(desc)):
        b.append((desc[i] + z * b[i - 1]) % mod)

    remainder = b[-1]
    quotient = list(reversed(b[:-1]))
    return poly_trim(quotient), remainder
```

KZG openings need the quotient polynomial `q(x) = (f(x) - f(z)) / (x - z)`. Dividing by a monic linear term `(x - z)` can be done efficiently with synthetic division; the remainder is exactly `f(z)`.

### Step 3: A toy bilinear group (additive notation + pairing)

```python
@dataclass(frozen=True)
class ToyBilinearGroup:
    q: int
    p: int
    g: int

    def __post_init__(self) -> None:
        if self.q <= 2:
            raise ValueError("q must be > 2")
        if self.p <= 2:
            raise ValueError("p must be > 2")
        if not (2 <= self.g < self.p):
            raise ValueError("g must be in [2, p-1]")

        if pow(self.g, self.q, self.p) != 1:
            raise ValueError("g must have order q in Z_p*")

    def elem(self, scalar: int) -> ToyElement:
        return ToyElement(self, scalar)

    def zero(self) -> ToyElement:
        return ToyElement(self, 0)

    def gen(self) -> ToyElement:
        return ToyElement(self, 1)

    def pair(self, a: ToyElement, b: ToyElement) -> ToyElement:
        if a.group is not self or b.group is not self:
            raise TypeError("pairing requires elements from this group")
        return ToyElement(self, (a.scalar * b.scalar) % self.q)


@dataclass(frozen=True)
class ToyElement:
    group: ToyBilinearGroup
    scalar: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "scalar", self.scalar % self.group.q)

    def __add__(self, other: ToyElement) -> ToyElement:
        if other.group is not self.group:
            raise TypeError("cannot add elements from different groups")
        return ToyElement(self.group, self.scalar + other.scalar)

    def __sub__(self, other: ToyElement) -> ToyElement:
        if other.group is not self.group:
            raise TypeError("cannot subtract elements from different groups")
        return ToyElement(self.group, self.scalar - other.scalar)

    def __neg__(self) -> ToyElement:
        return ToyElement(self.group, -self.scalar)

    def __mul__(self, k: int) -> ToyElement:
        if not isinstance(k, int):
            raise TypeError("can only scalar-multiply by int")
        return ToyElement(self.group, self.scalar * k)

    def __rmul__(self, k: int) -> ToyElement:
        return self.__mul__(k)

    def int_value(self) -> int:
        return pow(self.group.g, self.scalar, self.group.p)
```

Real KZG uses elliptic-curve groups `G1`, `G2` and a target group `GT` with a bilinear pairing `e`. Here we use a tiny prime-order subgroup and keep the hidden scalar around so we can implement `pair([a],[b]) = [a·b]` directly.

### Step 4: KZG setup, commit, open, verify

```python
@dataclass(frozen=True)
class KZGParams:
    group: ToyBilinearGroup
    max_degree: int
    g1_powers: Tuple[ToyElement, ...]  # [s^i] in G1 for i=0..max_degree
    g2: ToyElement  # [1] in G2
    g2_s: ToyElement  # [s] in G2


def toy_group_for_demo() -> ToyBilinearGroup:
    q = 1019
    p = 2039
    g = 4
    return ToyBilinearGroup(q=q, p=p, g=g)


def kzg_setup(max_degree: int, *, group: ToyBilinearGroup | None = None, s: int) -> KZGParams:
    if max_degree < 0:
        raise ValueError("max_degree must be >= 0")
    if group is None:
        group = toy_group_for_demo()

    s = mod_norm(s, group.q)
    if s == 0:
        raise ValueError("s must be non-zero in the field")

    powers: List[ToyElement] = []
    cur = 1
    for _ in range(max_degree + 1):
        powers.append(group.elem(cur))
        cur = (cur * s) % group.q

    g2 = group.gen()
    g2_s = s * g2
    return KZGParams(
        group=group,
        max_degree=max_degree,
        g1_powers=tuple(powers),
        g2=g2,
        g2_s=g2_s,
    )


def kzg_commit(params: KZGParams, coeffs: Sequence[int]) -> ToyElement:
    poly = [c % params.group.q for c in coeffs]
    if len(poly) == 0:
        raise ValueError("polynomial must be non-empty")
    if len(poly) - 1 > params.max_degree:
        raise ValueError("polynomial degree exceeds SRS max_degree")

    acc = params.group.zero()
    for i, c in enumerate(poly):
        acc = acc + (c * params.g1_powers[i])
    return acc


def kzg_open(params: KZGParams, coeffs: Sequence[int], z: int) -> Tuple[int, ToyElement]:
    poly = [c % params.group.q for c in coeffs]
    if len(poly) == 0:
        raise ValueError("polynomial must be non-empty")
    if len(poly) - 1 > params.max_degree:
        raise ValueError("polynomial degree exceeds SRS max_degree")

    z = mod_norm(z, params.group.q)
    y = poly_eval(poly, z, params.group.q)
    quotient, remainder = poly_divmod_x_minus_z(poly, z, params.group.q)
    if remainder != y:
        raise AssertionError("internal error: remainder theorem mismatch")
    pi = kzg_commit(params, quotient if len(quotient) > 0 else [0])
    return y, pi


def kzg_verify(params: KZGParams, commitment: ToyElement, z: int, y: int, proof: ToyElement) -> bool:
    if commitment.group is not params.group or proof.group is not params.group:
        raise TypeError("commitment/proof must be in params.group")

    z = mod_norm(z, params.group.q)
    y = mod_norm(y, params.group.q)

    left = params.group.pair(commitment - (y * params.group.gen()), params.g2)
    right = params.group.pair(proof, params.g2_s - (z * params.g2))
    return left == right
```

`kzg_commit` computes `C = Σ a_i·[s^i] = [f(s)]`. `kzg_open` computes `y=f(z)` and the witness `π=[q(s)]` where `q(x) = (f(x)-f(z))/(x-z)`. `kzg_verify` checks the pairing equation that enforces `f(s) - y = q(s)·(s - z)` without revealing `s`.

Run it:

`python3 code/main.py`

## Use It

Production KZG implementations use pairing-friendly curves (e.g. BLS12-381) and carefully specified serialization and subgroup checks.

- Ethereum EIP-4844 (“blob KZG”): `c-kzg-4844` and related bindings (reference implementation for verifying KZG commitments/openings on BLS12-381).
- Rust: `ark-poly-commit` (KZG10) + `ark-bls12-381` (BLS12-381 curve + pairings).
- ZK frameworks: Plonk-ish systems often expose KZG commitments via libraries like `halo2` ecosystems or curve-specific crates.

## Pitfalls

- **Toxic waste leakage:** if someone learns `s`, they can forge openings for commitments (binding breaks). Ceremony security is “1 honest contributor”.
- **Wrong field / modulus:** mixing `F_r` (scalar field) with `F_p` (curve base field) or using the wrong modulus silently breaks correctness.
- **Degree/SRS mismatch:** committing/opening a polynomial of degree `> max_degree` is undefined; always enforce SRS bounds.
- **Ambiguous polynomial encoding:** sign conventions, coefficient ordering, and trimming leading zeros must match across prover/verifier.
- **Not hiding by default:** basic KZG is binding but not hiding; ZK systems add blinding (randomness) so the commitment doesn’t leak information.

## Ship It

This lesson ships a PR-review checklist you can reuse whenever you review KZG-related code:

- `outputs/kzg-opening-review-checklist.md`

Use it to sanity-check: SRS handling, degree bounds, quotient computation, pairing equation wiring, and serialization assumptions.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that verification passes and that tampering with `y`, `π`, or `z` fails.
2. Medium. Change the polynomial coefficients and the opening point `z` in `code/main.py`. Predict how `y` and `π` should change, then run and confirm.
3. Hard. Pick a real KZG library (e.g. Ethereum’s `c-kzg-4844` bindings or a Rust KZG10 implementation). Verify one real opening end-to-end and list the extra checks required beyond this toy (serialization, subgroup checks, blinding, batch verification).

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| SRS | “setup parameters” | Public group elements like `[s^i]` that let anyone commit/open without knowing `s`. |
| Toxic waste | “the secret from the ceremony” | The trapdoor scalar `s`; if it leaks, binding is gone. |
| Commitment | “a hash of the polynomial” | A single group element `C = [f(s)]` binding you to `f`. |
| Opening / witness | “a proof for one point” | A single group element `π = [q(s)]` proving `f(z)=y`. |
| Pairing | “magic that multiplies exponents” | A bilinear map enabling `e([a],[b]) = e([1],[1])^{ab}` checks. |

## Further Reading

- Kate, Zaverucha, Goldberg, *Constant-Size Commitments to Polynomials and Their Applications* (2010) — the original KZG polynomial commitment scheme.
- “Powers of Tau” ceremony notes (various write-ups) — how multi-party setups reduce trust to “at least one honest contributor”.
