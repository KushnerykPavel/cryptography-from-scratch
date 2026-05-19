# Montgomery Ladder & Constant-Time Scalar Mul

> Do the same work for every scalar bit, so timing and power traces stop spelling your secret.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-elliptic-curves/03-scalar-multiplication (double-and-add + why it leaks)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why double-and-add leaks scalar bits through its variable control flow and why this is fatal for ECDH private keys and per-signature nonces
- Implement the Montgomery ladder using two accumulators (`R0`, `R1`) that perform exactly one addition and one doubling per scalar bit regardless of the bit value
- Distinguish the operation trace of double-and-add from the fixed-pattern trace of the Montgomery ladder using the `trace_*` toy functions
- Apply the toy `recover_bits_from_trace` function to demonstrate that double-and-add's trace is sufficient to reconstruct the scalar
- Identify the remaining side-channel risks in a Python ladder implementation and explain what additional measures (constant-time field ops, `cswap`, complete formulas) real libraries use

## The Problem

In the previous lesson you learned several fast ways to compute `k · P`. They were correct and efficient, but they had a fatal property: **their control flow depends on the scalar bits**.

That’s a problem because in real protocols `k` is secret:

- ECDH: `k` is your private key, and `P` is the peer’s public key.
- ECDSA / Schnorr signing: `k` is a per-signature nonce (leaking it reveals the long-term signing key).

If an attacker can distinguish “this iteration did only a double” vs “this iteration did double+add” (timing, power, cache), they can read off information about `k`. The goal of this lesson is to build a scalar multiplication routine whose **operation pattern per bit is fixed**.

## The Concept

### Why double-and-add leaks (SPA intuition)

Double-and-add looks like:

- Always: `R = 2R`
- Sometimes: `R = R + P` (only if the bit is 1)

That “sometimes” is the leak: the *presence* of the addition reveals the bit.

### The Montgomery ladder in one paragraph

The Montgomery ladder keeps two running points, typically:

- `R0 = 0 · P` (identity)
- `R1 = 1 · P` (the input point)

Then for each scalar bit from MSB→LSB it performs **exactly one add and one double**, regardless of the bit value, and only changes *where* the results are stored:

- If the bit is `0`:
  - `R1 = R0 + R1`
  - `R0 = 2 · R0`
- If the bit is `1`:
  - `R0 = R0 + R1`
  - `R1 = 2 · R1`

So every bit does the same two high-level operations. In constant-time implementations, even the “swap”/selection is done without branches (using a conditional swap, `cswap`).

### A reality check

This lesson improves the *algorithmic* pattern, but it does not make the Python code truly constant-time:

- the interpreter, big integers, and memory allocation vary with values,
- the point addition formulas still branch on edge cases.

The correct takeaway is: **use audited libraries for production**, but understand the ladder so you can recognize (and review) constant-time structure in real implementations.

## Build It

You’ll implement two scalar multiplication methods over a short-Weierstrass curve:

- `scalar_mul_double_and_add` (the leaky baseline)
- `scalar_mul_montgomery_ladder` (fixed add+double pattern per bit)

You’ll also implement toy trace functions to visualize the leakage.

### Step 1: Implement the ladder (fixed-pattern loop)

Use two accumulators `R0` and `R1`, initialized to `𝒪` and `P`. Process bits MSB→LSB.

```python
from main import Curve, Point, scalar_mul_montgomery_ladder

toy = Curve(p=97, a=0, b=1)
G = Point(10, 15)
print(scalar_mul_montgomery_ladder(toy, 37, G))
```

### Step 2: Visualize the side-channel signal (toy traces)

For learning, we model “what the attacker sees” as a trace string with:

- `D` for doubling
- `A` for an addition that depends on the scalar bit

Double-and-add produces traces with a variable number of `A`s, while the ladder produces an idealized fixed-length pattern per bit.

```python
from main import recover_bits_from_trace, trace_double_and_add, trace_montgomery_ladder

k = 37
t = trace_double_and_add(k)
print(t)
print(recover_bits_from_trace(t))
print(trace_montgomery_ladder(k))
```

Run it:

```
python3 code/main.py
```

## Use It

In real code you should not implement scalar multiplication yourself.

If you want to use ladder-style constant-time scalar multiplication in practice, use a library that already does it:

- X25519 (Curve25519) key exchange is standardized in RFC 7748 and implemented in constant-time by major libraries.
- In Python, `cryptography` exposes X25519:

```python
from cryptography.hazmat.primitives.asymmetric import x25519

sk = x25519.X25519PrivateKey.generate()
pk = sk.public_key()
shared = sk.exchange(pk)
```

Under the hood, this is a carefully engineered ladder-style scalar multiplication with additional protocol details (like scalar clamping and input handling).

## Attack It

The “attack” here is the simplest form of side-channel analysis: read the scalar bits from the control flow of double-and-add.

Our toy function `trace_double_and_add(k)` produces a string that contains an `A` if and only if the current scalar bit was 1. `recover_bits_from_trace(...)` shows that this is already enough to reconstruct the bit pattern (LSB-first).

The ladder’s goal is that an attacker cannot distinguish per-bit behavior so easily, because each bit does the same two operations. In real life you still need:

- constant-time field operations,
- constant-time selection (`cswap`),
- complete formulas / careful handling of special cases.

## Ship It

This lesson ships a constant-time scalar multiplication review prompt:

- `outputs/prompt-ec-montgomery-ladder-checklist.md`

## Exercises

1. Easy: For the toy curve, verify `scalar_mul_double_and_add(curve, k, P) == scalar_mul_montgomery_ladder(curve, k, P)` for `k ∈ [0..200]`.
2. Medium: For random 256-bit scalars on secp256k1, compare the output of your ladder to a trusted library (`ecdsa`), and record edge cases you had to handle (`k=0`, `P=𝒪`, negatives).
3. Hard (reviewer mindset): Find all branches in your implementation that still depend on secret data, and explain how real libraries avoid them.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Side-channel | “Timing/power leak” | Secret-dependent behavior observable through time, power, cache, EM, etc. |
| SPA | “Simple power analysis” | Recover secret bits by visually distinguishing operations (e.g., add vs double). |
| Constant-time | “No timing leak” | A design goal: secret-independent control flow and memory access patterns. |
| Montgomery ladder | “Constant-time scalar mul” | A fixed-pattern double+add scheme using two accumulators and (ideally) `cswap`. |

## Test Vectors

This lesson’s vectors are in `tests/vectors.json` and include:

- a small toy curve for quick sanity checks,
- secp256k1 points cross-checked against the `ecdsa` library.

## Further Reading

- Kocher (1996): Timing attacks on implementations.
- Hankerson–Menezes–Vanstone: *Guide to Elliptic Curve Cryptography* (scalar multiplication + ladders).
- RFC 7748: X25519 and X448 (ladder-style scalar multiplication on Montgomery curves).
