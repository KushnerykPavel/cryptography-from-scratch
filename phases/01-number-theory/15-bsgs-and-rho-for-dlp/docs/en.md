# Baby-Step Giant-Step & Pollard's Rho for DLP

> Generic discrete-log attacks make "half the bits" the real security level.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 12, 14
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Solve small discrete logarithms with Baby-Step Giant-Step.
- Explain the `O(sqrt(q))` time and memory tradeoff behind BSGS.
- Build Pollard's rho for DLP with Floyd cycle detection.
- Recover the secret exponent from a collision in the random walk.
- Explain why a 256-bit prime-order group gives about 128-bit generic DLP security.

## The Problem

Discrete-log protocols publish values like this:

```text
h = g^x
```

The public sees `g` and `h`. The secret is `x`. Brute force tries `g^0, g^1, g^2, ...` until it finds `h`, so a group of order `q` costs up to `q` steps.

That is not the best generic attack. Generic means the attacker only uses the group operation, not special structure like smooth finite-field elements from the index-calculus lesson. Baby-Step Giant-Step and Pollard's rho both solve DLP in about `sqrt(q)` group operations.

That square root changes security estimates. A group with `2^128` elements does not give 128-bit generic DLP security. It gives about 64-bit security. To target 128-bit generic security, use a prime-order group around `2^256`.

## The Concept

### Meet in the middle

Write the unknown exponent as:

```text
x = i*m + j
```

where `m = ceil(sqrt(q))`. Then:

```text
h = g^x = g^(i*m + j)
h * g^(-i*m) = g^j
```

Baby-Step Giant-Step stores the right side for every baby step `j`, then scans the left side for every giant step `i`.

```text
baby table:
  g^0 -> 0
  g^1 -> 1
  g^2 -> 2
  ...
  g^(m-1) -> m-1

giant scan:
  h
  h*g^(-m)
  h*g^(-2m)
  ...
```

When a giant value equals a baby value:

```text
h*g^(-i*m) = g^j
h = g^(i*m+j)
x = i*m + j
```

BSGS is deterministic and simple. Its weakness is memory: the table has about `sqrt(q)` entries.

### Pollard's rho for DLP

Pollard's rho keeps only a few states. Each state tracks:

```text
value = g^a * h^b
```

A deterministic-looking random walk updates `(value, a, b)` while preserving that invariant. Eventually two states collide:

```text
g^a * h^b = g^A * h^B
```

Since `h = g^x`:

```text
g^(a + x*b) = g^(A + x*B)
a + x*b = A + x*B       (mod q)
x*(b - B) = A - a       (mod q)
```

Solve the linear congruence and verify the candidate by checking `g^x = h`.

### Why rho matters

Pollard's rho has the same expected `sqrt(q)` time as BSGS but uses constant memory. That makes it the practical generic baseline for large prime-order groups.

```text
Attack cost against prime-order group q:

trial search:      q
BSGS:             sqrt(q) time, sqrt(q) memory
Pollard rho:      sqrt(q) expected time, constant memory
index calculus:   faster in some finite fields, not generic
```

## Build It

### Step 1: Square roots and inverses

BSGS needs `ceil(sqrt(order))`. Collision recovery needs modular inverses.

```python
def ceil_sqrt(n: int) -> int:
    root = isqrt(n)
    return root if root * root == n else root + 1
```

The inverse is the same extended-Euclidean pattern from earlier number-theory lessons.

### Step 2: Baby steps

Build a table from group element to exponent:

```python
def baby_step_table(p: int, g: int, order: int) -> dict[int, int]:
    width = ceil_sqrt(order)
    table = {}
    value = 1
    for exponent in range(width):
        table.setdefault(value, exponent)
        value = (value * g) % p
    return table
```

For `p = 23`, `g = 5`, `order = 22`, the baby table begins:

```text
1 -> 0
5 -> 1
2 -> 2
10 -> 3
4 -> 4
```

### Step 3: Giant steps

Scan `h, h*g^(-m), h*g^(-2m), ...` until a value appears in the baby table.

```python
def baby_step_giant_step(p, g, h, order):
    width = ceil_sqrt(order)
    table = baby_step_table(p, g, order)
    giant_stride = mod_inverse(pow(g, width, p), p)
    value = h % p
```

For:

```text
g = 5, h = 8, p = 23
```

the result is:

```text
x = 6
5^6 = 15625 = 8 mod 23
```

### Step 4: Rho states

Pollard's rho stores a state as:

```python
@dataclass(frozen=True)
class RhoState:
    value: int
    a: int
    b: int
```

The invariant is:

```text
value = g^a * h^b
```

The walk partitions the group into three buckets:

```python
if bucket == 0:
    value *= g
elif bucket == 1:
    value *= h
else:
    value *= value
```

The exponent counters update in lockstep so the invariant remains true.

### Step 5: Collision recovery

When Floyd cycle detection finds two states with the same `value`, solve:

```text
x*(b - B) = A - a mod order
```

The code uses a small linear-congruence solver so the toy full group `F_23*` works even though its order `22` is composite. For prime-order cryptographic subgroups, the collision equation usually has one candidate.

### Step 6: Compare BSGS and rho

The wrapper exposes both attacks:

```python
def discrete_log(p: int, g: int, h: int, order: int, method: str = "bsgs") -> int:
    if method == "bsgs":
        return baby_step_giant_step(p, g, h, order)
    if method == "rho":
        result, _ = pollard_rho_dlp(p, g, h, order)
        return result
```

Example outputs over the order-509 subgroup of `F_1019*`:

```text
log_4(706) = 37
log_4(504) = 123
log_4(967) = 400
```

Run it:

```
python3 code/main.py
```

## Use It

Production systems do not solve their own discrete logs. They choose groups where the best known attacks are too expensive, validate public inputs, and use audited protocol libraries.

For experimentation, SageMath and PARI/GP provide discrete-log functions. For protocol implementation, use audited libraries such as libsodium, RustCrypto, OpenSSL, BoringSSL, or language-native wrappers around well-reviewed primitives.

Your from-scratch code is useful because it calibrates security claims. If a protocol says "256-bit elliptic-curve group," you should hear "about 128-bit security against generic Pollard rho." If a finite-field group is small or has suspicious structure, the index-calculus lesson becomes relevant too.

## Attack It

The attack is generic DLP.

Suppose a custom Diffie-Hellman service uses a subgroup of size about `2^40`. Brute force sounds expensive. Pollard rho lowers the work to about:

```text
sqrt(2^40) = 2^20
```

That is not a cryptographic barrier. A laptop can explore that scale.

BSGS can also break it with a table of about `2^20` entries. Pollard rho is more memory-friendly, so it is the attack to keep in mind when sizing prime-order groups.

This lesson also connects to subgroup attacks. If a protocol accidentally accepts small-order public keys, the attacker does not need `sqrt(q)` work against the real group. They can force the computation into a tiny subgroup and recover pieces of the secret directly.

## Ship It

This lesson ships `outputs/prompt-dlp-generic-attack-review.md`, a review prompt for checking whether a DLP-based design has enough group size, prime-order subgroup handling, and input validation against generic attacks.

## Exercises

1. Easy: Verify by direct exponentiation that `5^6 mod 23 = 8`.
2. Medium: Count the number of table entries BSGS needs for group orders `2^20`, `2^32`, and `2^64`.
3. Hard: Implement Pollard's kangaroo for the case where `x` is known to lie inside a short interval `[a, b]`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Discrete log | "Undo exponentiation" | Given `h = g^x`, recover `x` modulo the order of `g` |
| Generic attack | "Works anywhere" | An attack that only uses group operations, not representation-specific structure |
| Baby step | "Small exponent table" | Stored values `g^j` for `0 <= j < ceil(sqrt(q))` |
| Giant step | "Jump by sqrt(q)" | Values `h*g^(-i*m)` checked against the baby table |
| Pollard rho | "Random walk attack" | A cycle-finding DLP attack with expected `sqrt(q)` time and constant memory |
| Collision | "Two states meet" | Two walk states with equal group value but different exponent counters |
| Prime-order subgroup | "The safe subgroup" | A subgroup where nonzero collision denominators have inverses modulo the order |

## Test Vectors

Source: project-internal educational examples over `F_23*` and the order-509 quadratic-residue subgroup of `F_1019*`, cross-checked by direct modular exponentiation.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) — Discrete logarithms, BSGS, Pollard rho, and Pohlig-Hellman.
- [Daniel J. Bernstein, SafeCurves: Discrete logs](https://safecurves.cr.yp.to/disc.html) — Generic attack costs for elliptic-curve groups.
- [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) — Finite-field and elliptic-curve key-agreement guidance.
