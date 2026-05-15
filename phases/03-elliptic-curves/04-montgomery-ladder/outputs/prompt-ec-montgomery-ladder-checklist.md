---
name: prompt-ec-montgomery-ladder-checklist
description: Checklist for implementing or reviewing Montgomery-ladder / double-and-add-always scalar multiplication with constant-time goals.
phase: 3
lesson: 4
---

You are my cryptography reviewer. I will paste an implementation of elliptic-curve scalar multiplication `k·P` intended to follow a Montgomery-ladder / double-and-add-always structure, plus helper functions like point addition/doubling, negation, and point validation. Review it like it could be used in a real protocol.

Checklist:

1) Inputs, invariants, and validation
- Is the curve validated as non-singular (`4a^3 + 27b^2 != 0 (mod p)`) and with `p > 3`?
- Is the identity element represented consistently across all functions?
- Are input points reduced mod `p` and validated to be on-curve before multiplication?
- Does it handle `k = 0`, `P = 𝒪`, and `k < 0` correctly?

2) Correctness of ladder logic
- Does it process bits MSB→LSB (or document the chosen direction)?
- Per bit, does it always perform exactly one “add” and one “double”, updating `(R0, R1)` according to the bit value?
- If it uses an invariant (e.g., `R1 == R0 + P` or `R1 == (processed+1)·P`), is it maintained after each iteration?

3) Constant-time goals (call out explicitly)
- Are there branches on secret data (scalar bits, secret-dependent edge cases, secret-dependent early exits)?
- Are there secret-indexed table lookups or secret-dependent memory access patterns?
- If there is a conditional swap (`cswap`) or conditional move (`cmove`), is it implemented in a constant-time style for the target language/runtime?
- Does the code clearly label itself educational-only if it is not constant-time?

4) Point formulas and special cases
- Are additions/doublings complete or are there exceptional cases (e.g., `P == Q`, `P == -Q`, `y == 0`) that cause branching or errors?
- If complete formulas are not used, does the implementation explain why and test the edge cases?

5) Evidence (tests)
- Does it include deterministic vectors (toy curve + at least one standard curve)?
- Does it test equality against an independent method/library?
- Does it test edge cases: `k=0`, negative `k`, identity input, and a few random scalars?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List concrete issues and their impact (correctness vs security).
- If you propose changes, keep them minimal and explain why each one matters.

