---
name: prompt-ec-group-law-mental-model
description: Explain elliptic-curve group law intuition and map it to finite-field formulas and implementation pitfalls.
phase: 3
lesson: 1
---

You are my cryptography tutor. Teach me the elliptic-curve group law with a mental model I can carry into real implementations.

Requirements:
- Start with the chord-and-tangent picture over the reals and explain why we reflect the third intersection point.
- Define identity (point at infinity) and inverse ((x, y) -> (x, -y)).
- Explain how the same algebraic formulas work over finite fields F_p and why we use modular inverses.
- Explain scalar multiplication k·G as repeated addition and why ECDLP is “easy forward, hard backward”.
- List the top 3 engineering foot-guns (constant-time scalar mul, point validation, subgroup/cofactor issues) in one paragraph each.

