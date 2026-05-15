---
name: prompt-ec-arithmetic-library-review
description: Checklist for implementing or reviewing a short-Weierstrass elliptic-curve arithmetic library (validation, encodings, scalar mul, and coordinate systems).
phase: 3
lesson: 12
---

You are my cryptography reviewer. I will paste an educational elliptic-curve arithmetic library for short Weierstrass curves over a prime field `F_p`, including point addition/doubling, scalar multiplication, SEC1 encoding/decoding, and modular square roots. Review it like it might be used in a real protocol.

Checklist:

1) Curve and field assumptions
- Is the curve validated as non-singular (`4a^3 + 27b^2 != 0 (mod p)`) and with `p > 3`?
- If the code assumes `p` is prime, is that documented (and/or checked where feasible)?
- Are parameters (`p, a, b`) normalized modulo `p` consistently?

2) Point representation and invariants
- Is the identity element represented consistently (`None`, or a specific projective marker like `Z=0`)?
- Are points normalized mod `p` before comparisons and operations?
- Does the API reject points that are not on the curve (especially on public entrypoints like decoding)?

3) Group law correctness (affine)
- Are all edge cases handled: `𝒪`, `P + (-P)`, `P == Q` doubling, `y == 0` doubling, vertical lines, and denominator `0`?
- Does point negation compute `(x, -y mod p)` correctly?
- Does the implementation avoid silently accepting invalid intermediate points?

4) Scalar multiplication
- Does it handle `k=0`, `P=𝒪`, and `k<0` correctly?
- If multiple strategies exist (double-and-add, NAF/wNAF, ladder), do they agree on shared vectors?
- If a ladder is claimed to be constant-time, does the code avoid secret-dependent branches and secret-indexed lookups (and does it explicitly disclaim runtime limits in Python)?

5) Coordinate systems (projective/Jacobian)
- Are projective formulas correct and do they handle infinity correctly?
- Does scalar multiplication avoid inversions inside the main loop (and only invert at the end)?
- Are mixed-addition and conversion-to-affine steps correct and safe?

6) SEC1 encodings and modular square roots
- Does compressed decoding compute `y` from `x` using a correct modular square root routine?
- Are invalid encodings rejected cleanly (wrong length/prefix, non-residues, off-curve results)?
- Does serialization choose prefix `0x02/0x03` based on `y` parity, and does it use the right coordinate byte length?

7) Subgroup and protocol-level validation (call out explicitly)
- Does the code clearly distinguish “on-curve” from “in the right subgroup”?
- For curves with cofactor > 1, does it provide either subgroup checks (`n·P = 𝒪`) or cofactor clearing?
- Does it warn that protocol rules (clamping, hash-to-curve rules, domain separation) are out of scope?

8) Evidence (tests)
- Are there deterministic vectors (toy curve + at least one standard curve)?
- Do tests cover invalid inputs (bad encodings, off-curve points, non-residue square roots)?
- Are different scalar multiplication variants cross-checked against each other?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List concrete issues grouped by: correctness, security, ergonomics/testability.
- If you suggest changes, keep them minimal and explain why each matters.

