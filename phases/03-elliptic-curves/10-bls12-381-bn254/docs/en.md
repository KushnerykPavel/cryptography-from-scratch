# BLS12-381 & BN254 — Pairing-Friendly Curves

> Pairings are easy to misuse: the curve choice and the subgroup rules are part of the security.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** 03-elliptic-curves/09-pairings-weil-tate, 03-elliptic-curves/11-hash-to-curve (or RFC 9380 familiarity)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Distinguish BN254 from BLS12-381 in terms of their embedding degree, base field sizes, and why modern security analyses place BN254 at ~100–103 bits rather than 128 bits in `GT`
- Explain why a point being "on curve" is not sufficient for pairing protocols and why cofactor clearing or explicit subgroup membership checks are required
- Implement a bilinearity check `e(aP, bQ) == e(P, Q)^(ab)` using `py_ecc` to verify that a library pairing behaves correctly on BN254 and BLS12-381 generators
- Apply the subgroup-check forgery pattern to demonstrate how accepting a public key outside the prime-order subgroup allows a naive BLS verifier to accept a forged signature
- Identify the correct full pipeline for hash-to-curve: map-to-curve followed by cofactor clearing, and explain why skipping cofactor clearing produces valid-looking but dangerous points

## The Problem

If you work on zero-knowledge systems, blockchains, or BLS signatures, you will keep seeing two curve names:

- **BN254** (a.k.a. BN128 / alt_bn128 / BN256 in various codebases): common in zkSNARK verification on Ethereum because of precompiles.
- **BLS12-381**: common in BLS signatures, signature aggregation, and many modern ZK stacks targeting ~128-bit security.

The trap is that “pairing-friendly curve” does *not* mean “any curve that has a pairing is fine.” Two projects can both say “we use pairings” while silently differing on:

- which curve family and parameter sizes they chose,
- which groups are used for keys vs signatures vs commitments (`G1` vs `G2`),
- whether points are validated to be **on curve** and in the **prime-order subgroup**.

If you can’t audit those choices, you can’t safely review:

- BLS signature verification code (subgroup bugs are a common footgun),
- zkSNARK verifier code (curve mismatch, wrong subgroup, wrong encoding),
- protocol migrations (BN254 → BLS12-381, or the reverse for performance reasons).

This lesson builds a small “curve audit harness” so you can answer: *what curve is this*, *what security target does it plausibly meet*, and *what validation rules must be enforced*.

## The Concept

### 1) What “pairing-friendly” really means

For protocols you usually see a pairing:

```text
e : G1 × G2 → GT
```

where `G1` and `G2` are prime-order groups of size `r` (same `r`), and `GT` is a multiplicative group (also of order `r`) inside an extension field.

The curve is “pairing-friendly” when:

- the embedding degree `k` is small enough that the pairing is computable (`k = 12` for both BN254 and BLS12-381),
- but large enough that discrete log in `GT ⊆ F_{p^k}^*` is still hard.

### 2) Why BN254 vs BLS12-381 is not just “254 vs 381 bits”

Both curves have:

- a ~254-bit prime subgroup order `r` (so the generic `sqrt(r)` attack on `G1/G2` is ~127-bit work),
- embedding degree `k = 12`.

But pairing security is constrained by attacks in the extension field and the curve family properties. Modern analyses put **BN254 around ~100–103 bits** of security in `GT`, not 128-bit, while **BLS12-381 targets ~128-bit**. (See “Further Reading”.)

### 3) The subgroup rule (the most common real bug)

The pairing is defined on the `r`-torsion. If your protocol assumes `P ∈ G1` (order `r`), it is not enough to check “on curve.”

For BLS12-381 in particular:

- mapping a random field element to the curve gives a point on the curve,
- but it may *not* land in the prime-order subgroup,
- so you must **clear the cofactor** (or do an equivalent subgroup check).

Protocols that skip subgroup checks can accept degenerate keys and signatures.

## Build It

We’ll build a tiny audit harness around the `py_ecc` reference implementation:

- extract curve parameters (modulus, subgroup order, embedding degree),
- compute one “known pairing value” (generator pairing) and check bilinearity,
- demonstrate why `map_to_curve` is not enough on BLS12-381,
- reproduce a minimal “missing subgroup checks” forgery pattern.

### Step 1: Curve profiles + a bilinearity check

```python
from main import bilinearity_check, curve_profile

print(curve_profile("bn254").to_json())
print(curve_profile("bls12_381").to_json())

print(bilinearity_check("bn254", a=123, b=456))
print(bilinearity_check("bls12_381", a=123, b=456))
```

What you’re sanity-checking here:

- base field size (`p` bits),
- scalar field size (`r` bits),
- that the library pairing satisfies `e(aP, bQ) = e(P, Q)^(ab)` on generators.

### Step 2: “On curve” vs “in subgroup” on BLS12-381

`hash_to_curve` (RFC 9380) is *two* steps: map-to-curve then cofactor clearing. This demo intentionally calls the mapping step first:

```python
from main import bls_map_to_curve_g1_demo

print(bls_map_to_curve_g1_demo(b"hello", b"DST"))
```

Expected:

- `on_curve = True`
- `in_subgroup = False` (often)
- `in_subgroup_after_clear = True`

This is exactly the rule you must enforce in real protocols: either clear the cofactor (standard) or do a subgroup check (costly unless optimized).

### Step 3: A minimal subgroup-check forgery pattern

Here is a sharp edge you want burned into your brain:

> If a verifier accepts a public key that is not in the prime-order subgroup, pairing-based verification can become trivial.

```python
from main import bls_subgroup_forgery_demo

print(bls_subgroup_forgery_demo(b"message", b"pk-seed"))
```

This demo constructs:

- a “public key” in the cofactor subgroup of `G1` (not the `r`-subgroup),
- a “signature” equal to the identity point in `G2`,
- and shows a naive verifier can accept it, while a strict verifier rejects it.

Run it:

```
python3 code/main.py
```

## Use It

### BLS signatures in a real library

`py_ecc` ships BLS ciphersuites that implement the full standard pipeline (hash-to-curve, subgroup rules, serialization formats):

```python
from py_ecc.bls import G2ProofOfPossession as bls_pop

sk = 42
pk = bls_pop.SkToPk(sk)
msg = b"hello"
sig = bls_pop.Sign(sk, msg)

print(bls_pop.Verify(pk, msg, sig))
```

In production ecosystems you’ll often see:

- `blst` (fast BLS12-381 implementation, used widely),
- `arkworks` / `blstrs` in Rust,
- or curve operations exposed as precompiles / native code in clients.

### BN254 in zkSNARK verification

BN254 is heavily used on Ethereum because precompiles expose:

- G1 addition / scalar multiplication (EIP-196),
- pairing checks (EIP-197).

In a real verifier, you don’t “roll your own pairing.” You call a precompile (or a vetted library) and you enforce the input encoding and subgroup rules the precompile expects.

## Attack It

**Attack theme:** accepting points not in the prime-order subgroup.

If an implementation:

1. accepts a public key in the cofactor subgroup, and
2. accepts the identity signature, and
3. skips subgroup validation,

then the pairing equation can collapse to `1 = 1` and the verifier can accept a forged “signature.”

This lesson’s `bls_subgroup_forgery_demo` shows the shape of the bug. The fix is protocol hygiene:

- reject identity points (`pk != 𝒪`, `sig != 𝒪`),
- validate points are on curve and in the correct subgroup,
- use standard hash-to-curve (RFC 9380) rather than ad-hoc mappings.

## Ship It

This lesson ships a review prompt you can use when auditing pairing-friendly curve usage in code:

- `outputs/prompt-pairing-curve-audit-checklist.md`

## Exercises

1. Easy: Extend `CurveProfile` to also report `r`’s bit security estimate (`~r_bits/2`) and print it for both curves.
2. Medium: Add a `bls_map_to_curve_g2_demo` that mirrors the `G1` demo but for `G2`.
3. Hard: Modify `bls_verify_strict` to additionally reject non-canonical encodings (hint: you’ll need a serialization layer and “strict decoding” rules).

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Embedding degree `k` | “pairing parameter” | Smallest `k` where `E[r]` and `μ_r` live in `F_{p^k}` so pairings can be computed. |
| `G1`, `G2`, `GT` | “the pairing groups” | Prime-order groups of size `r` (for `G1/G2`) and the target multiplicative group (for `GT`). |
| Cofactor clearing | “hash-to-curve step” | A map from an arbitrary curve point into the prime-order subgroup by multiplying by the cofactor (or an equivalent fast method). |
| Subgroup check | “validate the point” | Ensuring the point has order `r` (not just “on curve”). |
| BN254 / alt_bn128 | “the Ethereum pairing curve” | A pairing-friendly BN curve used in zkSNARK verification; efficient but not a 128-bit target in `GT` by modern estimates. |
| BLS12-381 | “BLS signatures curve” | A pairing-friendly BLS12 curve designed for ~128-bit security targets and used widely for BLS and ZK. |

## Test Vectors

Vectors in `tests/vectors.json` cover:

- `BN254` and `BLS12-381` parameter extraction (from `py_ecc` constants),
- generator pairing values (after final exponentiation),
- BLS12-381 `map_to_curve` vs `clear_cofactor` subgroup behavior,
- the subgroup-check forgery demo (naive vs strict verifier).

Sources:

- RFC 9380 (hashing to curves)
- BLS signatures (CFRG draft; for domain separation tags and standard pipeline)
- Ethereum EIPs for BN254 precompiles (EIP-196 / EIP-197)
- Recent pairing-curve security analyses (see Further Reading)

## Further Reading

- [RFC 9380: Hashing to Elliptic Curves](https://www.rfc-editor.org/rfc/rfc9380.html) — the standard map-to-curve + cofactor clearing pipeline.
- [BLS Signatures (CFRG draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/03/) — ciphersuites, DSTs, and required subgroup rules.
- [EIP-196](https://eips.ethereum.org/EIPS/eip-196) and [EIP-197](https://eips.ethereum.org/EIPS/eip-197) — BN254 precompiles on Ethereum.
- [LOVE a Pairing](https://eprint.iacr.org/2021/1029.pdf) — pairing-curve security estimates (includes BN254 vs BLS12-381 discussion).
