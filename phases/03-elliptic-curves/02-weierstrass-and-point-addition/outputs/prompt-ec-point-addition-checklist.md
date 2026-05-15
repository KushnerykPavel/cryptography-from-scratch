---
name: prompt-ec-point-addition-checklist
description: Checklist for implementing or reviewing short-Weierstrass affine point addition (edge cases, validation, and common security pitfalls).
phase: 3
lesson: 2
---

You are my cryptography reviewer. I will paste an implementation of elliptic-curve point addition over a prime field `F_p` for a short Weierstrass curve `y^2 = x^3 + a·x + b (mod p)`. Review it like it could be used in a real protocol.

Checklist:

1) Model and invariants
- What represents the identity element `𝒪`? Is it handled consistently?
- Is the curve checked to be non-singular (`4a^3 + 27b^2 != 0 (mod p)`) and with `p > 3`?
- Are points reduced modulo `p` and checked to satisfy the curve equation?

2) Edge cases in addition
- Does it correctly implement `P + 𝒪 = P` and `𝒪 + Q = Q`?
- Does it correctly implement `P + (−P) = 𝒪` (the vertical-line case `x1 == x2` and `y1 == −y2`)?
- Does it correctly implement doubling (`P == Q`) with slope `(3x^2 + a)/(2y)`?
- Does it correctly handle doubling when `y == 0` (tangent is vertical, result is `𝒪`)?
- Are there any divisions by `0 (mod p)` that could raise or return nonsense?

3) Algebra correctness
- Are the formulas for `x3` and `y3` correct: `x3 = λ^2 − x1 − x2`, `y3 = λ(x1 − x3) − y1` (mod p)?
- After computing the result, does the implementation preserve the invariant “result is on curve”?

4) Security pitfalls (call out explicitly)
- Is scalar multiplication constant-time? If not, label it educational-only.
- Does the code validate untrusted input points before multiplication (invalid-curve / small-subgroup patterns)?
- If the target curve has a cofactor, is subgroup membership enforced or cofactor-clearing used?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List concrete issues and their impact (correctness vs security).
- If you propose changes, keep them minimal and explain why each one matters.

