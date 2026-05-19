# Montgomery Curves — X25519 on Curve25519

> X25519 is “ECDH without y”: a Montgomery ladder on the u-coordinate with careful clamping and encoding rules.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** 03-elliptic-curves/04-montgomery-ladder, 01-number-theory/03-modular-inverse-and-fast-exp  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why X25519 operates on only the u-coordinate (x-only) instead of full `(x, y)` points and how the Montgomery ladder maintains this invariant using projective `(X:Z)` pairs
- Implement scalar clamping for Curve25519 by clearing the lowest 3 bits, clearing the highest bit, and setting bit 254, and explain the security rationale for each step
- Compute the RFC 7748 X25519 function end-to-end: decode 32-byte inputs, clamp the scalar, run the ladder, and encode the 32-byte output
- Identify the all-zero output check, explain when it triggers (small-order input points), and describe how to implement the check in a side-channel-resistant way
- Distinguish Montgomery curve arithmetic from short Weierstrass point addition and explain which features make Curve25519 well-suited for high-performance, low-footgun ECDH

## The Problem

You’ll see X25519 everywhere: TLS 1.3, Signal-style protocols, WireGuard, modern SSH, and more. In many systems it’s the default ECDH choice because it’s fast, widely implemented, and designed to reduce footguns.

But if you only know short-Weierstrass point arithmetic (“a point is (x, y) and we add them”), X25519 can look alien:

- inputs and outputs are 32-byte strings, not “points”,
- it works on only the **u-coordinate** (x-coordinate), not (x, y),
- it applies **clamping** to scalars,
- it asks you to check whether the output is **all-zero** and abort.

If you don’t understand those design choices, you can’t review real code, you can’t debug interoperability issues, and you won’t recognize the security invariants that X25519 is trying to enforce.

This lesson builds X25519 from scratch (in Python), using the standard RFC 7748 ladder formulas and test vectors.

## The Concept

### Montgomery curves (the form)

A Montgomery curve over a field `F_p` is commonly written:

```text
B·y^2 = x^3 + A·x^2 + x
```

Curve25519 is a specific Montgomery curve with:

- `p = 2^255 − 19`
- `A = 486662`
- `B = 1`

X25519 does *not* operate on `(x, y)` points directly. It takes:

- a 32-byte “scalar” `k` (private key material),
- a 32-byte “u-coordinate” `u` (the peer’s public key),

and outputs a 32-byte `u` value.

### Why “x-only” works

For Montgomery curves there are special formulas that let you do scalar multiplication using only x-coordinates in projective form:

- represent a u-coordinate as a projective pair `(X:Z)` meaning `x = X/Z (mod p)`,
- maintain an invariant that lets you compute:
  - a doubling `x([2]P)` from `x(P)`,
  - a “differential addition” `x(P+Q)` from `x(P)`, `x(Q)`, and `x(P−Q)`.

The Montgomery ladder arranges the loop so that the “difference” is always the input point, so you never need full point addition in affine coordinates.

### Clamping (why your scalar is not “just a number”)

X25519 takes 32 random bytes and “clamps” them:

- clear the lowest 3 bits,
- clear the highest bit,
- set bit 254.

This forces the scalar into a safe shape (notably, a multiple of the cofactor), reducing certain classes of failures and attacks when combined with the all-zero check.

### The all-zero output check

RFC 7748 notes that if the input corresponds to a small-order point, X25519 can output the all-zero value. Many protocols treat that as a failure: if you accept it, an attacker can sometimes force a predictable shared secret.

## Build It

You’ll implement the RFC 7748 X25519 routine:

1. decode inputs (little-endian bytes → integers mod `p`),
2. clamp the scalar,
3. run the Montgomery ladder in x-only `(X:Z)` coordinates,
4. encode the output back to 32 bytes.

### Step 1: Encode/decode and clamp

The wire format is 32 bytes, little-endian. For X25519, the top bit of the final byte must be masked on decode.

```python
from main import clamp_scalar25519, decode_u_coordinate, encode_u_coordinate

k = clamp_scalar25519(bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
u = decode_u_coordinate(bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000"))
print(k, u)
print(encode_u_coordinate(u).hex())
```

### Step 2: Field arithmetic mod p

All operations run modulo `p = 2^255 - 19`:

- addition/subtraction/multiplication reduce mod `p`,
- inversion uses Fermat’s little theorem (`a^(p-2) mod p`) or extended Euclid.

### Step 3: Montgomery ladder (x-only)

Implement the RFC 7748 ladder with a conditional swap (`cswap`) per bit.

The important mental model is:

- keep two running points `(X2:Z2)` and `(X3:Z3)`,
- they always represent consecutive multiples of the input point.

### Step 4: X25519 as a function

Now wrap it into `x25519(scalar32, u32) -> out32` and add a helper for basepoint multiplication `x25519_basepoint(scalar32)`.

Run it:

```
python3 code/main.py
```

## Use It

In real systems, do not implement X25519 yourself. Use a constant-time, audited library.

In Python, `cryptography` exposes X25519:

```python
from cryptography.hazmat.primitives.asymmetric import x25519

alice_sk = x25519.X25519PrivateKey.generate()
alice_pk = alice_sk.public_key()

bob_sk = x25519.X25519PrivateKey.generate()
bob_pk = bob_sk.public_key()

alice_shared = alice_sk.exchange(bob_pk)
bob_shared = bob_sk.exchange(alice_pk)
assert alice_shared == bob_shared
```

## Attack It

The classic “attack” you must remember for X25519 is **small-order inputs**.

If an attacker can send you a public key that corresponds to a point of small order (dividing the curve’s cofactor), the output of X25519 can become the all-zero value. If your protocol treats “all-zero” as a valid shared key, the attacker may force a predictable shared secret.

RFC 7748’s guidance is simple: after computing `K`, check if it is the all-zero string and abort if so (implemented in a side-channel-resistant style, e.g., OR all bytes and compare to zero).

## Ship It

This lesson ships an X25519 review prompt:

- `outputs/prompt-x25519-review-checklist.md`

## Exercises

1. Easy: Implement `is_all_zero(shared32)` and test it against a few hand-made inputs (including `00..00`).
2. Medium: Using your X25519, implement a toy ECDH handshake that derives a symmetric key via `HKDF(shared || pkA || pkB)`. Verify that both sides match.
3. Hard (review mindset): List every place constant-time matters in X25519, and identify which ones your Python code does *not* satisfy.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Montgomery curve | “A special elliptic curve form” | Curves of the form `B·y^2 = x^3 + A·x^2 + x` that admit efficient x-only formulas. |
| u-coordinate | “The x-coordinate” | The Montgomery x-coordinate used as the public value in X25519 (encoded as 32 bytes). |
| (X:Z) | “Projective coordinates” | Represents `x = X/Z (mod p)` without doing an inversion each step. |
| `cswap` | “Constant-time swap” | Conditional swap typically implemented without branches to avoid leaking scalar bits. |
| Clamping | “Mask some bits” | Forces scalar bytes into a safe shape (multiple of cofactor, fixed top bits) before laddering. |
| All-zero check | “Reject zero key” | Detects small-order input cases that would yield a predictable shared secret. |

## Test Vectors

Source: RFC 7748 (January 2016). Code must pass `tests/vectors.json`, which includes:

- the two X25519 input/output vectors,
- the Curve25519 ECDH example (Alice/Bob),
- the iterative test (1 and 1,000 iterations).

## Further Reading

- RFC 7748 — *Elliptic Curves for Security* (X25519/X448 definitions + vectors).
- Bernstein (2006) — *Curve25519: new Diffie-Hellman speed records* (design motivations).
