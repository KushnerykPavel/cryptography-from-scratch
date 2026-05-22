# BGW & Information-Theoretic MPC
> Secret-share once, compute forever, reconstruct at the end.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/17-fhe-and-mpc/06-yao-garbled-circuits`, `phases/17-fhe-and-mpc/07-gmw` (contrast), comfort with modular arithmetic + polynomials
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Shamir secret sharing makes addition “free” in MPC
- Compute Lagrange coefficients for interpolation at `x=0`
- Implement Shamir share/reconstruct over a prime field
- Distinguish degree growth (after multiplication) from BGW degree reduction
- Apply BGW-style multiplication to evaluate a small arithmetic circuit

## The Problem

You want multiple parties to compute on private data without revealing it. Think: a consortium of banks wants to compute a fraud score that is a function of all their private signals; or a group of labs wants to train/evaluate a model on sensitive aggregates; or a set of companies wants to compute a shared KPI without exposing individual numbers.

If you just “encrypt everything” you quickly run into problems: fully homomorphic encryption is powerful but heavy, and many workflows want *information-theoretic* privacy (privacy that does not rely on computational hardness assumptions) when an honest majority exists.

BGW is the classic blueprint: represent secrets as points on random polynomials (Shamir sharing), then evaluate an *arithmetic circuit* gate-by-gate. Addition is local. Multiplication is the hard part — not because of math, but because it makes the hidden polynomial’s degree grow unless you actively reduce it.

## The Concept

### Shamir sharing in one picture

To share a secret `s ∈ F_p` among `n` parties with threshold `t`, pick a random degree-`t` polynomial:

`f(x) = s + a1 x + a2 x^2 + ... + at x^t  (mod p)`

Give party `i` the point `(i, f(i))`. Any `t+1` points uniquely determine `f(x)`, so they can recover `f(0)=s`. Any `t` or fewer points reveal nothing about `s`.

### Why addition is easy

If `a` is shared by `f(x)` and `b` is shared by `g(x)`, then `a+b` is shared by `(f+g)(x)`. Every party can compute:

`(a+b)_i = f(i) + g(i)  (mod p)`

No messages.

### Why multiplication is not “just multiply your shares”

If you multiply pointwise:

`h(i) = f(i) * g(i)`

then `h(x) = f(x)g(x)` is a polynomial of degree `2t`. That means you now need `2t+1` shares to reconstruct — and if you keep multiplying, the degree keeps growing.

BGW’s fix is a **degree reduction** sub-protocol: after multiplying shares, the parties collaborate to convert a degree-`2t` sharing of `ab` into a fresh degree-`t` sharing of the *same secret* `ab`, without learning it.

### Degree reduction as “re-share then recombine”

The key fact is linearity: for a degree-`2t` polynomial `h`, there exist public coefficients `λ_i` such that:

`h(0) = Σ_i λ_i h(i)`

BGW has the parties:
1) locally compute `h(i) = f(i)g(i)`
2) *re-share* each `h(i)` via a fresh degree-`t` polynomial (so each `h(i)` becomes a Shamir-sharing)
3) recombine those re-sharings using the public `λ_i` to get a fresh degree-`t` sharing of `h(0)=ab`

That’s what you’ll implement below.

## Build It

### Step 1: Prime-field arithmetic
```python
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple


Share = Tuple[int, int]  # (party_id, value)


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse of 0 does not exist")
    t0, t1 = 0, 1
    r0, r1 = p, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ValueError("a is not invertible modulo p")
    return t0 % p


def mod_div(a: int, b: int, p: int) -> int:
    return (a % p) * mod_inv(b, p) % p


def poly_eval(coeffs: Sequence[int], x: int, p: int) -> int:
    x %= p
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc
```
Everything happens in a finite field `F_p`. You need modular inversion for interpolation, and polynomial evaluation to create shares.

### Step 2: Lagrange interpolation + Shamir share/reconstruct
```python
def lagrange_coeffs_at_zero(xs: Sequence[int], p: int) -> List[int]:
    xs = list(xs)
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")
    if any(x % p == 0 for x in xs):
        raise ValueError("x coordinates must be non-zero for sharing")

    coeffs: List[int] = []
    for i, xi in enumerate(xs):
        num = 1
        den = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = (num * xj) % p
            den = (den * (xj - xi)) % p
        coeffs.append(num * mod_inv(den, p) % p)
    return coeffs


def shamir_share(
    secret: int,
    n: int,
    t: int,
    p: int,
    *,
    rng: random.Random | None = None,
    coeffs: Sequence[int] | None = None,
) -> List[Share]:
    if n <= 0:
        raise ValueError("n must be positive")
    if t < 0 or t >= n:
        raise ValueError("require 0 <= t < n")

    if coeffs is None:
        if rng is None:
            rng = random.Random()
        poly = [secret % p] + [rng.randrange(0, p) for _ in range(t)]
    else:
        poly = [c % p for c in coeffs]
        if len(poly) != t + 1:
            raise ValueError("coeffs must have length t+1")
        if poly[0] != secret % p:
            raise ValueError("coeffs[0] must equal secret mod p")

    return [(i, poly_eval(poly, i, p)) for i in range(1, n + 1)]


def shamir_reconstruct(shares: Sequence[Share], p: int) -> int:
    if len(shares) == 0:
        raise ValueError("need at least one share")
    xs = [x for x, _ in shares]
    ys = [y % p for _, y in shares]
    lambdas = lagrange_coeffs_at_zero(xs, p)
    return sum((lam * y) % p for lam, y in zip(lambdas, ys)) % p
```
`lagrange_coeffs_at_zero` gives the public weights for “evaluate at `x=0` from sample points”. Shamir sharing is just “pick a random polynomial with `f(0)=secret`, hand out `f(1)..f(n)`”. Reconstruction is the weighted sum.

### Step 3: Local ops + BGW multiplication (degree reduction)
```python
def shamir_add(a: Sequence[Share], b: Sequence[Share], p: int) -> List[Share]:
    if len(a) != len(b):
        raise ValueError("share sets must have same size")
    out: List[Share] = []
    for (i1, v1), (i2, v2) in zip(a, b):
        if i1 != i2:
            raise ValueError("party ids must align")
        out.append((i1, (v1 + v2) % p))
    return out


def shamir_scalar_mul(shares: Sequence[Share], k: int, p: int) -> List[Share]:
    return [(i, (k % p) * (v % p) % p) for i, v in shares]


def _bgw_degree_reduce_from_degree_2t(
    degree_2t_shares: Sequence[Share],
    *,
    t: int,
    p: int,
    rng: random.Random,
) -> List[Share]:
    n = len(degree_2t_shares)
    if n < 2 * t + 1:
        raise ValueError("need n >= 2t+1 for degree-2t reconstruction")

    dealers = list(degree_2t_shares[: 2 * t + 1])
    dealer_ids = [i for i, _ in dealers]
    lambdas = lagrange_coeffs_at_zero(dealer_ids, p)
    lambda_by_dealer = {i: lam for i, lam in zip(dealer_ids, lambdas)}

    party_ids = [i for i, _ in degree_2t_shares]
    subshares_by_party: Dict[int, List[int]] = {pid: [] for pid in party_ids}

    for dealer_id, dealer_value in dealers:
        poly = [dealer_value % p] + [rng.randrange(0, p) for _ in range(t)]
        for pid in party_ids:
            subshares_by_party[pid].append(poly_eval(poly, pid, p))

    reduced: List[Share] = []
    for pid in party_ids:
        acc = 0
        for (dealer_id, _), sub in zip(dealers, subshares_by_party[pid]):
            acc = (acc + lambda_by_dealer[dealer_id] * sub) % p
        reduced.append((pid, acc))
    return reduced


def bgw_multiply(
    a: Sequence[Share],
    b: Sequence[Share],
    *,
    t: int,
    p: int,
    rng: random.Random,
) -> List[Share]:
    if len(a) != len(b):
        raise ValueError("share sets must have same size")
    if len(a) < 2 * t + 1:
        raise ValueError("need n >= 2t+1 for multiplication")

    local_products: List[Share] = []
    for (i1, va), (i2, vb) in zip(a, b):
        if i1 != i2:
            raise ValueError("party ids must align")
        local_products.append((i1, (va % p) * (vb % p) % p))

    return _bgw_degree_reduce_from_degree_2t(local_products, t=t, p=p, rng=rng)
```
Additions stay degree-`t`. Multiplication produces a degree-`2t` sharing, so we “re-share then recombine” to get back to degree-`t`. This is the conceptual core of BGW’s multiplication gate.

### Step 4: Evaluate a tiny arithmetic circuit
```python
@dataclass(frozen=True)
class CircuitInput:
    a: int
    b: int
    c: int
    d: int


def bgw_demo_circuit(
    inp: CircuitInput,
    *,
    n: int,
    t: int,
    p: int,
    rng: random.Random,
) -> int:
    share_a = shamir_share(inp.a, n, t, p, rng=rng)
    share_b = shamir_share(inp.b, n, t, p, rng=rng)
    share_c = shamir_share(inp.c, n, t, p, rng=rng)
    share_d = shamir_share(inp.d, n, t, p, rng=rng)

    share_a_plus_b = shamir_add(share_a, share_b, p)
    share_mul = bgw_multiply(share_a_plus_b, share_c, t=t, p=p, rng=rng)
    share_out = shamir_add(share_mul, share_d, p)

    return shamir_reconstruct(share_out[: t + 1], p)
```
This is the MPC workflow: secret-share all inputs, compute gate-by-gate (adds are local; multiplies call the BGW sub-protocol), then reconstruct only the final output.

Run it:
python3 code/main.py

## Use It

BGW is the “information-theoretic, arithmetic-circuit” sibling of GMW (Boolean-circuit) and the ancestor of modern honest-majority MPC stacks.

- Production frameworks (honest-majority, Shamir-based families): MP-SPDZ (Shamir/BGW-like variants), SCALE-MAMBA (SPDZ family), various academic implementations.
- If you want fewer assumptions but heavier crypto: SPDZ/Beaver triples (computational), or Yao/GMW for Boolean circuits.

Rule of thumb:
- **BGW/Shamir-based**: simple math, fast in LAN, needs honest majority and a field, good for arithmetic.
- **Yao/GMW**: works well for Boolean circuits; different tradeoffs for communication/rounds.
- **SPDZ**: handles malicious security with preprocessing, popular in practice.

## Pitfalls

1. **Wrong threshold condition.** This toy uses `n >= 2t+1` for multiplication/degree reduction. Malicious security needs stronger conditions and extra checks (VSS/MACs).
2. **Reusing randomness.** Degree-reduction polynomials must be fresh; reusing them can leak structure across multiplications.
3. **Forgetting “mod p” everywhere.** One missing reduction can silently break interpolation or equality checks.
4. **Mixing up “t” meanings.** Some texts use degree `t-1` for a “t-out-of-n” threshold; this lesson uses “degree t” with “threshold t” in the common MPC convention.
5. **Assuming the from-scratch protocol is production-safe.** Real BGW variants must address cheating, message authentication, and robustness.

## Ship It

Save `outputs/bgw-review-checklist.md` and use it when you:
- review MPC protocol code paths (especially “multiply gate / degree reduction”)
- design parameter checks (`p`, `n`, `t`, domain separation, RNG requirements)
- sanity-check what security model you’re actually in (semi-honest vs malicious)

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that additions are local but multiplication triggers the degree-reduction step.
2. Medium. Extend `bgw_demo_circuit` to compute `((a+b)*(c+d)) + (a*c)` and verify it matches the cleartext value mod `p`.
3. Hard. Production integration: read about SPDZ and explain (in a paragraph) what preprocessing buys you versus this BGW-style online-only protocol.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Shamir sharing | “threshold sharing” | A secret is `f(0)` for a random polynomial `f`; shares are `f(1)..f(n)` |
| Threshold `t` | “up to t corrupted” | Any `t` shares leak nothing; `t+1` reconstruct |
| Arithmetic circuit | “adds and multiplies” | Computation expressed as `+`/`*` over a field, evaluated gate-by-gate |
| Degree growth | “multiplication problem” | Multiplying degree-`t` polynomials yields degree `2t`, raising reconstruction threshold |
| Degree reduction | “refresh / reshare” | Interactive step that converts degree-`2t` shares into fresh degree-`t` shares of the same secret |

## Further Reading

- Ben-Or, Goldwasser, Wigderson, *Completeness Theorems for Non-Cryptographic Fault-Tolerant Distributed Computation* (1988) — the classic BGW result and model.
- Shamir, *How to share a secret* (1979) — threshold secret sharing via polynomials.
- Cramer, Damgård, Dziembowski, *On the Complexity of Verifiable Secret Sharing and Multiparty Computation* (2000) — why malicious security needs more machinery.
