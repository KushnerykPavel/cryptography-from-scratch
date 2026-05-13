# Index Calculus & Discrete Log

> Smooth group elements turn discrete logs into linear algebra.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 7, 9, 10, 13
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why generic discrete-log attacks cost about `sqrt(q)` group operations.
- Build a toy index-calculus solver in a prime-order subgroup of `F_p*`.
- Collect smooth relations over a factor base and solve factor-base logs with modular linear algebra.
- Use a descent step to recover `x` from `h = g^x`.
- Explain why index calculus breaks finite-field DLP faster than generic attacks, while elliptic-curve groups resist this style of attack.

## The Problem

Diffie-Hellman, DSA, Schnorr, and many zero-knowledge protocols assume this task is hard:

```text
given p, g, h = g^x mod p, recover x
```

Baby-step giant-step and Pollard rho solve this generically in about `sqrt(q)` work for a group of order `q`. That is already much better than brute force, but it treats the group as a black box. Finite fields are not black boxes. Their elements are ordinary integers modulo `p`, and many of those integers factor over small primes.

Index calculus exploits that extra structure. Instead of searching for `x` directly, it first learns the logs of small "factor base" elements. Once those logs are known, any target that can be nudged into a smooth integer yields its discrete log immediately.

## The Concept

### Smoothness, again

The Quadratic Sieve lesson used smooth values of `x^2 - n` to factor integers. Index calculus uses smooth values of `g^k mod p` to solve discrete logs.

Pick a small factor base:

```text
B = {3, 5, 11, 17, ...}
```

If:

```text
g^k mod p = 3^a * 5^b * 11^c * 17^d
```

then taking logs base `g` gives a linear equation:

```text
k = a*log_g(3) + b*log_g(5) + c*log_g(11) + d*log_g(17)  (mod q)
```

Collect enough equations and solve for the unknown factor-base logs.

### Why this lesson uses a subgroup

The full group `F_p*` has order `p - 1`, often composite. Linear equations modulo a composite require extra care: pivots may not have inverses. To keep the implementation focused, this lesson works in the order-`q` quadratic-residue subgroup of a safe prime:

```text
p = 1019
p - 1 = 2 * 509
q = 509
g = 4
```

Because `q` is prime, Gaussian elimination modulo `q` behaves like ordinary field linear algebra.

### Relation collection

For each exponent `k`, compute:

```text
value = g^k mod p
```

Keep it only when `value` factors completely over the factor base.

Example:

```text
g = 4, p = 1019
4^18 mod 1019 = 867
867 = 3 * 17^2
```

So:

```text
18 = log_g(3) + 2*log_g(17)  (mod 509)
```

Each smooth value is one row in the matrix.

### Final descent

After the factor-base logs are known, solve a target:

```text
h = g^x
```

Search for a small shift `t` such that:

```text
h * g^t mod p
```

is smooth over the factor base. If:

```text
h * g^t = product(f_i ^ e_i)
```

then:

```text
x + t = sum(e_i * log_g(f_i))  (mod q)
x = sum(e_i * log_g(f_i)) - t  (mod q)
```

For `h = 504`, the code finds:

```text
t = 3
504 * 4^3 mod 1019 = 667 = 23 * 29
log_g(504) = log_g(23) + log_g(29) - 3 = 123 mod 509
```

## Build It

### Step 1: Small primes and inverses

The lesson starts with tiny number-theory utilities: trial primality, distinct prime factors, and modular inverse by the extended Euclidean algorithm.

```python
def mod_inverse(a: int, modulus: int) -> int:
    a %= modulus
    old_r, r = a, modulus
    old_s, s = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r != 1:
        raise ValueError("inverse does not exist")
    return old_s % modulus
```

### Step 2: Build the subgroup

Find a primitive root of `F_p*`, then raise it to `(p - 1) / q` to get a generator of the order-`q` subgroup.

```python
def subgroup_generator(p: int, q: int) -> int:
    root = primitive_root(p)
    generator = pow(root, (p - 1) // q, p)
    return generator
```

For `p = 1019` and `q = 509`, the generator is `4`.

### Step 3: Choose the factor base

A factor-base prime must itself live in the subgroup. The membership test is:

```text
a^q ≡ 1 (mod p)
```

For this toy group and bound `50`, the base is:

```text
[3, 5, 11, 17, 19, 23, 29, 31, 43]
```

### Step 4: Collect smooth relations

The relation collector scans `g^k mod p` and keeps values that factor over the base.

```python
def collect_relations(p, g, q, base, needed=None):
    relations = []
    for exponent in range(1, q):
        value = pow(g, exponent, p)
        exponents = factor_over_base(value, base)
        if exponents is not None:
            relations.append(Relation(exponent, value, exponents))
```

The first few relations include:

```text
4^5  mod 1019 = 5
4^9  mod 1019 = 261 = 3^2 * 29
4^18 mod 1019 = 867 = 3 * 17^2
```

### Step 5: Solve factor-base logs

Gaussian elimination modulo `q` solves:

```text
matrix * logs = exponents  (mod q)
```

The code keeps collecting relations until the matrix has full rank.

```text
log_g(3)  = 479
log_g(5)  = 5
log_g(11) = 378
...
```

### Step 6: Descend the target

The target descent searches for a shift that makes `h*g^t` smooth, then subtracts the shift.

```python
def index_calculus_log(p, g, q, h, bound=50):
    base = factor_base_for_subgroup(p, q, bound)
    logs = factor_base_logs(p, g, q, base)
    _, _, _, result = descend_target(p, g, q, h, base, logs)
    return result
```

Example output:

```text
log_g(706) = 37
log_g(504) = 123
log_g(967) = 400
```

## Use It

For real finite-field discrete logs, use SageMath, PARI/GP, Magma, or specialist tools. Real attacks use much more sophisticated relation collection, large-prime variants, sparse linear algebra, descent trees, and for large prime fields the Number Field Sieve for discrete logarithms.

For cryptographic engineering, the lesson is parameter selection. Finite-field Diffie-Hellman groups need large safe primes and conservative subgroup handling. Modern protocols often prefer elliptic-curve or post-quantum groups because known index-calculus attacks do not transfer cleanly to well-chosen elliptic curves.

## Attack It

The attack is the lesson: finite-field DLP has non-generic structure. Smoothness lets an attacker amortize work.

After factor-base logs are known, each new target only needs a descent. That is why index calculus is especially important for shared public parameters. If many users share the same finite-field group, an attacker can spend a large precomputation once and then solve individual targets more cheaply.

This is one reason standardized finite-field groups are chosen very carefully, and why small custom groups are dangerous.

## Ship It

This lesson ships `outputs/prompt-dlp-parameter-review.md`, a prompt for reviewing finite-field discrete-log parameters. It checks subgroup order, generator validation, small-subgroup hazards, and whether the group size is remotely appropriate against index-calculus attacks.

## Exercises

1. Easy: Verify by direct exponentiation that `4^123 mod 1019 = 504`.
2. Medium: Increase the factor-base bound and count how many shifts the descent needs for every target `g^x`.
3. Hard: Adapt the solver to the full group `F_p*` by solving the linear system modulo each prime-power factor of `p - 1`, then recombining with CRT.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Discrete log | "Undo exponentiation" | Given `h = g^x`, recover `x` modulo the order of `g` |
| Factor base | "Small primes" | Elements whose logs are learned first so smooth targets become linear equations |
| Smooth relation | "A lucky power" | A value `g^k mod p` that factors entirely over the factor base |
| Index calculus | "DLP by linear algebra" | Relation collection plus linear algebra plus descent for non-generic groups |
| Descent | "Reduce the target" | Multiply the target by known powers until it factors over known elements |
| Prime-order subgroup | "The clean part of the group" | A subgroup where logs are modulo a prime `q`, so linear algebra has inverses |
| Generic attack | "Works on any group" | Attacks such as BSGS or Pollard rho that do not exploit representation-specific structure |

## Test Vectors

Source: project-internal educational examples over the order-509 quadratic-residue subgroup of `F_1019*`, cross-checked by direct modular exponentiation.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) — Discrete logarithms and index-calculus algorithms.
- [Daniel J. Bernstein, SafeCurves: Discrete logs](https://safecurves.cr.yp.to/disc.html) — Why generic and non-generic attacks matter for group choices.
- [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) — Finite-field and elliptic-curve key-agreement guidance.
