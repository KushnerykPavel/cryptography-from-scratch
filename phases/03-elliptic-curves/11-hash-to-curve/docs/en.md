# Hashing to Curves — RFC 9380

> “Don’t invent a map to the curve — use a suite (DST + hash-to-field + map + cofactor clearing) that’s designed to behave like a random oracle.”

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-elliptic-curves/02-weierstrass-and-point-addition, 03-elliptic-curves/08-nist-p256 (recommended)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why naive "try `x = H(m) mod p`, lift to curve, retry" fails as a hash-to-curve strategy — covering rejection-sampling bias, variable-time behavior, and biased point distribution
- Implement `expand_message_xmd` (SHA-256) to expand `(msg, DST)` into uniform bytes, explaining how the DST prevents cross-protocol collision between different protocols hashing the same message
- Compute `hash_to_field` by slicing uniform bytes into field-sized chunks reduced mod `p`, and use it to produce the two field elements needed by the RO suite
- Apply the Simplified SWU (`map_to_curve_simple_swu`) to deterministically map a field element to a P-256 point without rejection sampling, using the `sqrt_ratio` helper
- Distinguish the `encode_to_curve` (NU, one field element) from the `hash_to_curve` (RO, two field elements added together) suites and explain when each distribution guarantee is required

## The Problem

You keep seeing protocols that say “hash the message to a curve point”:

- BLS signatures hash messages to a pairing group.
- VRFs and some ZK constructions hash labels into elliptic-curve points.
- “Hash-to-group” appears in PAKEs, OPRFs, VOPRFs, and modern identity protocols.

If you naively do something like “`x = H(m) mod p; y = sqrt(x^3 + ax + b)`”, you hit three real problems:

1. **It often fails** (most `x` don’t land on the curve), so you add retries… which becomes variable-time and messy.
2. **It’s not a random oracle**: the distribution of points can be biased or distinguishable (especially if you use only one field element).
3. **Domain separation is easy to get wrong**: two protocols that “hash-to-curve” the same message can accidentally hash to the *same* point and create cross-protocol confusion or replay bugs.

RFC 9380 standardizes a safe pattern: a ciphersuite fixes the hash function, a domain separation tag (DST), the “hash-to-field” procedure, the curve mapping, and cofactor clearing.

## The Concept

Think of hash-to-curve as a pipeline with named parts (and fixed parameters).

```
msg + DST
   │
   ▼
expand_message(msg, DST, …)     (acts like a random oracle to bytes)
   │
   ▼
hash_to_field(...)              (turn bytes into field elements u[i] ∈ Fp)
   │
   ▼
map_to_curve(u[i])              (deterministically land on the curve)
   │
   ▼
(optional) add mapped points    (RO suites add two points: Q0 + Q1)
   │
   ▼
clear_cofactor(...)             (force result into the prime-order subgroup)
   │
   ▼
P  (a point in the target group)
```

Two encodings matter:

- `encode_to_curve` (“NU” suites): uses **one** field element `u[0]` and maps once. Output is deterministic but *not* a random oracle distribution.
- `hash_to_curve` (“RO” suites): uses **two** field elements `u[0], u[1]`, maps twice, adds the results, then clears the cofactor. This gives random-oracle-like behavior under standard assumptions.

In this lesson we implement the **P-256** suites from RFC 9380:

- `P256_XMD:SHA-256_SSWU_RO_`
- `P256_XMD:SHA-256_SSWU_NU_`

P-256 has **cofactor `h = 1`**, so “clear cofactor” is the identity — but you still keep the step in your mental model, because many curves (e.g., BLS12-381) require it.

## Build It

### Step 1: `expand_message_xmd` (SHA-256)

RFC 9380 defines `expand_message_xmd` for hash functions like SHA-256. It expands `(msg, DST)` into `len_in_bytes` “uniform bytes”, with careful DST handling so concatenations can’t collide.

```python
uniform = expand_message_xmd(msg, dst, len_in_bytes, hash_fn=sha256)
```

### Step 2: `hash_to_field` (Fp)

To feed a curve mapping, we need elements of the base field `Fp`. `hash_to_field` slices the uniform bytes into chunks, interprets each chunk as an integer, and reduces mod `p`.

```python
u = hash_to_field_fp(msg, count=2, dst=dst, p=P256_P, k=128, hash_fn=sha256)
```

### Step 3: `map_to_curve_simple_swu` (P-256)

P-256 is a short Weierstrass curve with `A != 0` and `B != 0`, so RFC 9380 recommends **Simplified SWU** (SSWU). The suite fixes `Z = -10` for P-256.

The key trick: instead of retrying until something is square, SSWU uses a structured formula and a `sqrt_ratio` helper that always returns *some* square root.

### Step 4: `encode_to_curve` vs `hash_to_curve`

- NU suite: `P = map_to_curve(u[0])`
- RO suite: `P = map_to_curve(u[0]) + map_to_curve(u[1])`

This repository’s implementation lives in `code/main.py`.

Run it:

```
python3 code/main.py
```

## Use It

In production, you generally should **not** implement hash-to-curve yourself. Use an audited implementation of RFC 9380 suites:

- BLS libraries (e.g., `blst`, `arkworks`, `py_ecc`) implement standardized hash-to-curve for BLS12-381 groups.
- For Weierstrass curves like P-256 or secp256k1, use a vetted library or a reference implementation that explicitly claims RFC 9380 compatibility.

If you *must* interoperate, treat the suite string (including the DST rules) as part of the protocol specification. Tiny differences (e.g., “NU vs RO”, or DST mismatch) will silently produce different points.

## Attack It

**Attack theme:** missing or incorrect domain separation (DST).

If two different protocols do:

```
P = hash_to_curve(msg, DST="")
```

then the exact same `msg` hashes to the exact same curve point in both contexts. That makes it much easier to accidentally “sign in one protocol, verify in another” when message formats overlap (or to replay proofs across contexts).

The fix is simple and non-negotiable: always use a protocol-specific DST constructed according to RFC 9380’s domain separation requirements (and use the standardized suite DST when one is defined).

## Ship It

This lesson ships an audit/review prompt:

- `outputs/prompt-hash-to-curve-review-checklist.md`

## Exercises

1. Easy: For a fixed message `m`, show that changing the DST changes the output point (and explain why that’s a *feature*).
2. Medium: Add a helper that outputs `u[0], u[1]` (RO) and verify it matches RFC 9380 Appendix J vectors for at least two messages.
3. Hard: Read RFC 9380 Section 8.7 (secp256k1 suite). Explain why secp256k1 can’t use the “plain” SSWU mapping directly and needs an isogeny map.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| DST (domain separation tag) | “context string” | A protocol-specific tag mixed into hashing so different protocols can’t accidentally share points. |
| `expand_message_xmd` | “hash-to-bytes” | A safe expander that turns `(msg, DST)` into enough uniform bytes for `hash_to_field`. |
| `hash_to_field` | “hash mod p” | A structured way to derive one or more field elements from uniform bytes, with security parameter `k`. |
| SSWU | “map-to-curve” | A deterministic mapping that lands on a Weierstrass curve without retries. |
| `sqrt_ratio` | “square root helper” | Returns `sqrt(u/v)` when possible, else `sqrt(Z*u/v)`, avoiding rejection sampling. |
| Cofactor clearing | “subgroup fix” | Maps a curve point into the prime-order subgroup; essential for curves with cofactor > 1. |

## Test Vectors

This lesson uses RFC 9380 suite test vectors:

- `tests/vectors.json` copies Appendix J.1.1 / J.1.2 (P-256 suites).
- `tests/test_vectors.py` checks `hash_to_field`, the SSWU map outputs, and the final `P` points.

## Further Reading

- RFC 9380 — Hashing to Elliptic Curves (suites + test vectors)
- The `hash2curve` reference repository linked from RFC 9380 (for cross-checking and interoperable implementations)
