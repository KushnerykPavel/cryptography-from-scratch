---
name: prompt-pairing-implementation-review-checklist
description: Checklist for implementing or reviewing Weil/Tate pairing code (Miller loop, final exponentiation, subgroup rules, and common footguns).
phase: 3
lesson: 9
---

You are my cryptography reviewer. I will paste a pairing implementation (finite fields, curve arithmetic, Miller loop, Weil/Tate pairing wrapper, and any subgroup/cofactor logic). Review it as if it could ship inside BLS signatures, SNARK tooling, or a blockchain client.

Checklist:

1) Field arithmetic correctness
- Are base-field and extension-field operations correct (addition, multiplication, inversion, exponentiation)?
- Are reductions mod p applied consistently (no accidental Python big-int growth without mod)?
- Are zero divisors handled correctly (inverses reject 0, division by 0 is impossible in valid code paths)?

2) Curve and subgroup rules
- Does the code enforce that all inputs are on the correct curve (including the correct twist / subgroup when applicable)?
- Does it ensure points are in the correct prime-order subgroup (subgroup checks / cofactor clearing)?
- Are points at infinity handled consistently and safely?

3) Miller loop implementation
- Does it use the correct line-function logic for:
  - doubling steps (tangent line),
  - addition steps (secant line),
  - vertical lines and “infinity” edge cases?
- Are numerator/denominator factors used consistently (no missing vertical line denominator terms)?
- Are intermediate values normalized (e.g., projective-to-affine conversions, if any) without invalid inversions?

4) Tate pairing specifics
- Is the final exponentiation performed as `f^((p^k - 1)/r)` to land in μ_r?
- Are the parameters `p`, `k`, and `r` correct for the curve?
- Does it avoid returning trivial/undefined values from points not in r-torsion?

5) Weil pairing specifics
- Does it produce an r-th root of unity and satisfy alternating behavior (e(P, P) = 1)?
- Does it use an auxiliary point S safely (avoids degeneracies and zero denominators)?

6) Security and production safety (call out explicitly)
- Is the implementation constant-time? If not, is it labeled educational-only?
- Does it avoid secret-dependent branches and inversions when used with secrets?
- Are serialization/parsing routines strict and canonical (reject malformed inputs)?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List issues grouped by correctness vs security vs ergonomics.
- For fixes, propose minimal changes and explain why each matters.

