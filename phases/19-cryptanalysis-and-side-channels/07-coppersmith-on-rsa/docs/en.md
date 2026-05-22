# Coppersmith’s Method (Idea) — Small Roots Mod N (Toy)

> If an unknown part is small enough, “mod N” stops hiding it.

**Type:** Build
**Languages:** Python
**Prerequisites:** Modular arithmetic; RSA basics; polynomials
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what it means for a polynomial to have a root modulo N
- Compute polynomial evaluation modulo N
- Implement a brute-force “small root” search on tiny parameters
- Distinguish the *idea* of Coppersmith from the lattice machinery that makes it fast
- Apply the idea to a stereotyped-message RSA scenario (known prefix + small unknown)

## The Problem

RSA is secure when plaintexts are properly padded and structured randomness is used. But real systems sometimes produce structured plaintexts: “known header + small unknown”, “timestamp + small counter”, “format string + short ID”.

If the unknown part is small, you can often build a modular polynomial equation whose root is the unknown. Coppersmith’s method (lattice-based) can find that small root efficiently for real key sizes under certain bounds.

This lesson demonstrates the construction and the goal. We use brute force instead of lattices so it stays stdlib-only and deterministic.

## The Concept

You want `f(x0) ≡ 0 (mod N)` where `x0` is small. If you can find `x0`, you recover the hidden piece.

In a stereotyped-message RSA example with small exponent `e=3`:

`c ≡ (m0 + x)^3 (mod N)`

Rearrange into:

`f(x) = (m0 + x)^3 − c ≡ 0 (mod N)`

If `x` is small enough, Coppersmith can find it. In this toy demo, we just brute force x.

## Build It

### Step 1: Build a modular polynomial with a small root
```python
def build_stereotyped_message_polynomial(m0: int, e: int, c: int, n: int) -> List[int]:
    if e != 3:
        raise ValueError("demo uses e=3")
    a3 = 1
    a2 = (3 * m0) % n
    a1 = (3 * (m0 % n) * (m0 % n)) % n
    a0 = (pow(m0, 3, n) - c) % n
    return [a3, a2, a1, a0]
```
For `e=3`, `(m0+x)^3 = x^3 + 3m0 x^2 + 3m0^2 x + m0^3`. Subtract `c` to build a polynomial that is zero modulo `N` at the true `x`.

### Step 2: Find the small root by brute force (toy)
```python
def find_small_root_bruteforce(coeffs: List[int], n: int, x_bound: int) -> Optional[int]:
    for x in range(x_bound):
        if poly_eval_mod(coeffs, x, n) == 0:
            return x
    return None
```
This is not Coppersmith. It is the “what we want” behavior on tiny parameters.

### Step 3: Recover the full message from m0 + x
```python
recovered_m = m0 + x
```
Once `x` is known, the structured message `m0 + x` is fully recovered.

Run it:
python3 code/main.py

## Use It

- In production, avoid structured/predictable RSA plaintexts; use standard padding/KEM constructions.
- Treat “known prefix + small unknown” as a red flag in RSA encryption and signatures.
- For real Coppersmith work, use vetted tooling/libraries; implementing lattice reduction correctly is non-trivial.

## Pitfalls

- Using small `e` with structured messages and no padding.
- Assuming “mod N” hides a small unknown automatically.
- Forgetting that partial information can be enough (not only full plaintext).
- Rolling your own padding/formatting.
- Treating brute force behavior as indicative of real bounds (Coppersmith bounds are nuanced).

## Ship It

Save a checklist for spotting “small unknown” RSA risks: `outputs/rsa-small-root-risk-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that brute force recovers the small x.
2. Medium. Change `x_bound` and show when the root is no longer found.
3. Hard. Extend the polynomial construction to include the full cubic expansion and still recover x on toy parameters.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Small root | “x is tiny” | A solution x0 with |x0| below some bound relative to N and degree |
| Stereotyped message | “structured plaintext” | Plaintext has known structure plus a small unknown component |
| Coppersmith | “lattice magic” | A method to find small modular roots using lattice reduction (LLL) |
| Brute force | “try all x” | Exponential in unknown size; only works in toy settings |

## Further Reading

- Coppersmith, “Small Solutions to Polynomial Equations, and Low Exponent RSA Vulnerabilities” (1997) — foundational result
- “A Gentle Tutorial for Lattice-Based Cryptanalysis” — practical overview of small-root attacks and constructions
