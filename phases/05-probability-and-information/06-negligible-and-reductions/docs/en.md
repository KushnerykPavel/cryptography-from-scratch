# Negligible Functions & Reductions

> A scheme is secure if no polynomial-time adversary has non-negligible advantage — and a reduction proves that breaking the scheme would break a hard primitive.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 05 · 04 (Computational Indistinguishability) · 05 (Hybrid Argument)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- State the formal definition of negligible and identify negligible vs non-negligible functions using polynomial witnesses.
- Explain why 1/n^100 is NOT negligible and exhibit the witnessing polynomial.
- Compute concrete security: primitive_bits − log₂(total_loss) and required_primitive_bits = target + log₂(total_loss).
- Chain multiple reductions and multiply their loss factors to get total loss.
- Determine whether a claimed security bound is still acceptable after reduction loss at a target security parameter.

## The Problem

Two phrases appear in every modern crypto proof:

- "the adversary's advantage is **negligible**"
- "by a **reduction**, if A breaks the scheme, B breaks the primitive"

Lesson 04 gave you a point-check for negligibility (`is_negligible(ε, n)`).
Lesson 05 used reductions informally. This lesson pins both concepts down
precisely and gives you the algebraic tools to reason about them in proofs.

Without this, you cannot:
- Verify whether a claimed security bound is actually negligible.
- Compute how much security budget a reduction consumes.
- Check whether a chain of reductions still leaves a meaningful security guarantee.

## The Concept

### Negligible functions — the formal definition

`ε : ℕ → ℝ≥0` is **negligible** (written `ε = negl(n)`) if:

```
for every polynomial p, ∃ N such that ∀ n > N: ε(n) < 1/p(n)
```

Equivalently: `ε` goes to zero faster than every inverse polynomial.

| Function | Negligible? | Reason |
|----------|------------|--------|
| `2^{-n}` | ✓ | exponential decay beats any polynomial |
| `e^{-n}` | ✓ | same |
| `1/n!`   | ✓ | factorial grows faster than any polynomial |
| `n^{-log n}` | ✓ | superpolynomial decay |
| `1/n`    | ✗ | **is** 1/poly — the polynomial `p(n) = n` witnesses it |
| `1/n²`   | ✗ | **is** 1/poly — `p(n) = n²` witnesses it |
| `1/n^{100}` | ✗ | **still** 1/poly — `p(n) = n^{100}` witnesses it |
| `0.001`  | ✗ | constant, never goes below 1/p for large p |

**Common mistake**: `1/n^{100}` looks tiny but is not negligible. Negligible
means below *every* inverse polynomial — if you find even one `p` for which
`ε(n) ≥ 1/p(n)` infinitely often, `ε` is non-negligible.

### Closure properties

Negligible functions are closed under:

| Operation | Result |
|-----------|--------|
| `negl + negl` | negligible |
| `poly · negl` | negligible |
| `negl · negl` | negligible |

**Not** closed under:
- `negl / negl` — could be anything
- `1 / negl` — non-negligible (it grows superpolynomially)

These closures are what make the hybrid argument work: polynomial hops each
contributing a negligible per-hop advantage sum to a negligible total.

### Non-negligible functions

`f` is **non-negligible** if there exists a polynomial `p` and infinitely many
`n` with `f(n) ≥ 1/p(n)`.

An adversary is said to **break** a scheme if its advantage is non-negligible.
A security proof proceeds by contradiction: assume non-negligible advantage,
then show it implies a non-negligible advantage against a hard primitive.

### Reductions — the formal structure

A **reduction** from scheme X to primitive Y is a PPT algorithm B such that:

```
Adv_B(Y, n) ≥ Adv_A(X, n) / q(n)
```

for some polynomial `q(n)` (the **loss factor**).

If `Adv_A` is non-negligible and `q` is polynomial, then `Adv_A / q` is still
non-negligible — contradicting the assumed hardness of Y.

The proof template:

```
1. Assume ∃ PPT adversary A with non-negligible Adv_A(X).
2. Construct PPT algorithm B that:
   - receives a Y-challenge
   - simulates A's environment using the Y-challenge
   - outputs whatever A outputs (with appropriate translation)
3. Show Adv_B(Y) ≥ Adv_A(X) / q(n).
4. Since Adv_B is non-negligible and Y is assumed hard, contradiction. ∎
```

### Reduction tightness and concrete security

The **loss factor** `q(n)` directly eats into concrete security:

```
Adv_scheme ≤ Adv_primitive × q(n)
scheme_bits = primitive_bits - log2(q(n))
```

A **tight reduction** has `q(n) = 1` — no security loss. A reduction with
`q(n) = 2^{30}` costs 30 bits of security.

At concrete security parameters this matters enormously:

| Primitive | Loss | Scheme security |
|-----------|------|----------------|
| 128-bit AES-PRF | ×1 (tight) | 128 bits |
| 128-bit AES-PRF | ×2^{30} | 98 bits |
| 256-bit AES-PRF | ×2^{30} | 226 bits |

This is why NIST post-quantum candidates target 256-bit primitives — their
reductions have large loss factors from the multi-query security proof.

### Composed reductions

When scheme X reduces to Y which reduces to Z:

```
Adv_C(Z) ≥ Adv_A(X) / (q1 × q2)
```

The total loss is the **product** of individual losses. Three reductions with
loss 4 each give total loss 64 — 6 bits eaten.

## Build It

### Step 1: negligibility classification

```python
def is_negligible_function(fn, *, test_start=10, test_end=200, poly_degrees=(1,2,3)):
    for d in poly_degrees:
        for n in range(test_start, test_end + 1):
            try:
                if fn(n) >= 1.0 / (n ** d):
                    return False
            except (OverflowError, ZeroDivisionError):
                pass
    return True

def is_non_negligible_function(fn, *, test_range, poly_degree=1):
    return any(fn(n) >= 1.0 / (n ** poly_degree) for n in test_range)
```

`is_non_negligible_function(lambda n: 1/n**100, test_range=range(10,201), poly_degree=100)` returns `True` — the d=100 polynomial witnesses non-negligibility.

### Step 2: reduction algebra

```python
def reduction_advantage(adv_adversary, poly_loss):
    return adv_adversary / poly_loss    # Adv_B >= Adv_A / poly_loss

def compose_reductions(losses):
    result = 1.0
    for loss in losses:
        result *= loss
    return result                       # total loss = product
```

### Step 3: concrete security calculator

```python
def security_bits(adv):
    return -math.log2(adv)

def concrete_security(primitive_security_bits, total_loss):
    return primitive_security_bits - math.log2(total_loss)

def required_primitive_security(target_scheme_bits, total_loss):
    return target_scheme_bits + math.log2(total_loss)
```

`concrete_security(128, 64) = 128 − 6 = 122 bits`. Every doubling of the loss costs one bit.

Run it:

```
python3 code/main.py
```

## Use It

Real-world security proofs express exactly these quantities:

- **TLS 1.3 HKDF security**: reduction from PRF to HMAC with loss `q_H`
  (number of hash queries). At `n = 128` and `q_H = 2^{60}`, you need
  HMAC at 188 bits to achieve 128-bit scheme security.
- **GCM authentication**: loss factor from the polynomial hash forgery bound
  is `L²/2^{128}` where `L` = message length. Long messages eat security bits.
- **Post-quantum KEM (Kyber/ML-KEM)**: reduction from Module-LWE has
  loss involving the number of decapsulation queries; this is why the NIST
  standard targets 3 security levels (I / III / V) at 128 / 192 / 256 bits.

## Attack It

**The `1/n^{100}` trap**: A developer claims their scheme is "negligibly
insecure" because the adversary's advantage is `1/n^{100}` — which is
astronomically small at `n = 128`. But it is *not* negligible. With
`p(n) = n^{100}` as the polynomial witness, `f(n) = 1/p(n)` and the
definition fails. The correct claim is "it has negligible advantage if
the underlying primitive is hard", not "the advantage itself is negligible".

**The tight-reduction fallacy**: A proof shows `Adv_B ≥ Adv_A / q(n)` but
does not verify `q(n)` is polynomial. If `q(n) = 2^n` the reduction is
useless — `Adv_A / 2^n` can be negligible even when `Adv_A` is not.

## Ship It

This lesson ships a reusable concrete-security calculator prompt:

- `outputs/prompt-concrete-security.md`

Use it when auditing claimed security levels in protocol specs, NIST
submissions, or library documentation.

## Exercises

1. Easy: classify each function as negligible or non-negligible:
   `2^{-√n}`, `1/n^{log n}`, `n · 2^{-n}`, `(log n) / n`. For the
   non-negligible ones, exhibit a polynomial witness.

2. Medium: a MAC has a security proof with loss `q` (number of MAC queries).
   If you allow `q = 2^{30}` queries and want 128-bit security, what is the
   minimum primitive security level? What if `q = 2^{50}`?

3. Hard: two reductions compose: R1 (loss `n²`) from scheme X to primitive Y,
   and R2 (loss `2n`) from Y to primitive Z. If Z is 256-bit secure, what is
   the concrete security of X at `n = 128`? Is it still ≥ 128 bits?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| negligible | "essentially zero" | below every inverse polynomial for large n |
| non-negligible | "meaningful" | ≥ 1/p(n) for some polynomial p, infinitely often |
| reduction | "proof by contradiction" | PPT B that turns A's advantage into a primitive break |
| loss factor | "tightness" | how much the reduction divides the adversary's advantage |
| tight reduction | "no overhead" | loss = 1; scheme security = primitive security |
| concrete security | "actual bits" | primitive_bits - log2(total_loss) |
| security bits | "k-bit secure" | advantage ≤ 2^{-k} |

## Test Vectors

Source: definitions of security_bits (-log2), concrete_security, required_primitive_security,
reduction_advantage, compose_reductions.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Katz & Lindell, *Introduction to Modern Cryptography*, §3.2–3.3](https://www.cs.umd.edu/~jkatz/imc.html) — negligible functions, reductions
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*, §2.3](https://toc.cryptobook.us/) — concrete security, tight reductions
- [Goldreich, *Foundations of Cryptography, Vol. 1*, §1.3](https://www.wisdom.weizmann.ac.il/~oded/foc-vol1.html) — formal definition of negligible
- [Bernstein, "Comparing proofs of security for lattice-based encryption"](https://cr.yp.to/papers.html) — concrete security in post-quantum schemes
