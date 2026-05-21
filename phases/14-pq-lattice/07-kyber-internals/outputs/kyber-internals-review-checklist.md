---
name: "Kyber Internals Review Checklist (NTT + Compression)"
description: "Pasteable PR review checklist for Kyber/ML-KEM polynomial multiplication (NTT) and coefficient compression/bit packing."
phase: "14-pq-lattice"
lesson: "07-kyber-internals"
---

# Kyber Internals Review Checklist (NTT + Compression)

Use this checklist to review (or debug) Kyber / ML-KEM implementations that touch:
- polynomial multiplication in `R_q = Z_q[x]/(x^256 + 1)`,
- NTT/invNTT + base multiplication,
- coefficient compression/decompression,
- bit packing/unpacking for ciphertexts/keys.

## 1) Ring invariants
- Parameters match the target (ML-KEM): `q=3329`, `N=256`, modulus `x^256 + 1`.
- Code is doing **negacyclic** multiplication (wrap implies a sign flip), not cyclic.
- Coefficients are consistently represented in one range (typically `[0, q)`), and reducers are applied after every multiply/add path that can overflow in the chosen integer width.

## 2) Multiplication correctness
- There is at least one test that compares the “fast path” multiply (NTT-based) against a “truth” multiply (schoolbook negacyclic) for:
  - sparse polynomials (few non-zeros),
  - random polynomials (seeded, deterministic),
  - edge coefficients (`0`, `1`, `q-1`, around `q/2`).
- The fast path handles the `x^256 + 1` modulus correctly:
  - no off-by-one index wrap,
  - correct sign on wrapped terms.

## 3) NTT / invNTT details
- The transform domain is correct for the ring product you want:
  - if using a “twisted” approach, the twist element satisfies `psi^n = -1` for the relevant `n`.
  - if using precomputed twiddle tables, their ordering matches the butterfly schedule (a common source of “everything is permuted” bugs).
- The inverse transform includes the required scaling factor (multiplication by `n^{-1} mod q` or equivalent).
- The base multiplication in the transform domain matches the representation (some implementations store polynomials in a mixed/packed NTT basis).

## 4) Compression & decompression
- The compress mapping matches the spec intent: `t ≈ round(2^d · c / q)` and fits in `d` bits.
- The decompress mapping matches the spec intent: `c' ≈ round(q · t / 2^d)` and is reduced into `[0, q)`.
- Error budget is acknowledged:
  - tests measure `max |c' - c|` (mod `q`) for representative values of `d`,
  - decryption/decapsulation failure behavior is tested at the scheme level (not just unit tests).

## 5) Bit packing & byte layout
- Pack/unpack agree on:
  - bit ordering within a byte (LSB-first vs MSB-first),
  - coefficient order (which coefficient is “first”),
  - exact counts (no implicit truncation or padding mismatch).
- Roundtrip tests exist: `unpack(pack(values)) == values` for multiple `bits` widths and random values.

## 6) Side-channel and oracle hazards (security)
- No data-dependent early exits on ciphertext validity checks (constant-time compare or masked-accumulate pattern).
- No branches on secret-dependent intermediate values (including NTT reductions, decompress results, or comparison outcomes).
- Failure handling follows the standard’s intent (e.g., implicit rejection patterns): outputs must not reveal “valid/invalid” via timing, error codes, or distinct memory access patterns.

## 7) “Bug signature” quick diagnosis
- Result looks rotated/permuted: likely twiddle-table ordering mismatch or missing bit-reversal/permutation step.
- Result matches cyclic but not negacyclic: likely wrong modulus (`x^N - 1` instead of `x^N + 1`) or missing twist.
- Decompression produces many zeros: `d` too small for your test, or compress scaling/rounding is wrong.
- Occasional decapsulation failures: almost always a packing/rounding mismatch or a coefficient-range/reduction issue.

