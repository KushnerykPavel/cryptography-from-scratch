---
name: prompt-ec-scalar-mul-checklist
description: Checklist for implementing or reviewing elliptic-curve scalar multiplication (double-and-add, NAF, wNAF) with correctness and side-channel pitfalls.
phase: 3
lesson: 3
---

You are my cryptography reviewer. I will paste an implementation of elliptic-curve scalar multiplication `k·P` over a prime field `F_p` (short Weierstrass curve), plus any helper functions like point addition, negation, and recoding (NAF / wNAF). Review it like it could be used in a real protocol.

Checklist:

1) Inputs, invariants, and validation
- Is the curve validated as non-singular (`4a^3 + 27b^2 != 0 (mod p)`) and with `p > 3`?
- Is the identity element represented consistently (e.g., `None`) across all functions?
- Are input points reduced mod `p` and validated to be on-curve before multiplication?
- Does it handle `k = 0`, `P = 𝒪`, and `k < 0` correctly?

2) Correctness of the algorithm
- Double-and-add: does it always double each loop iteration and conditionally add based on scalar bits?
- NAF: do digits belong to `{−1, 0, +1}` and have no adjacent nonzero digits?
- wNAF: are digits odd, in range `[−(2^{w-1}−1), +(2^{w-1}−1)]`, with zeros between nonzeros typically?
- wNAF precompute: is the table built correctly for odd multiples `P, 3P, 5P, ...` up to the maximum digit?
- Are there any accidental uses of even multiples where odd multiples are required?

3) Side-channel and protocol pitfalls (call out explicitly)
- Is the scalar multiplication constant-time? If not, does the code clearly label itself educational-only?
- Are there branches or table lookups indexed by secret data (scalar bits/digits)?
- If points are untrusted (e.g., ECDH peer public key), does the code address invalid-curve / small-subgroup patterns appropriately for the target curve?

4) Tests and evidence
- Does the implementation include deterministic test vectors (toy curve + standard curve cross-check)?
- Does it test agreement across methods (`double-and-add` vs `naf` vs `wNAF`)?
- Does it test edge cases (identity, negation, `k=0`, large `k`)?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List concrete issues and their impact (correctness vs security).
- If you propose changes, keep them minimal and explain why each one matters.

