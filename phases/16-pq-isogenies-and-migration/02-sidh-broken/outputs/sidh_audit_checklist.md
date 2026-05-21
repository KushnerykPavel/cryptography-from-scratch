---
name: Isogeny Protocol Audit Checklist
description: A checklist to evaluate new isogeny-based cryptographic protocols for structural flaws akin to SIDH.
phase: 16
lesson: 2
---

# Isogeny Protocol Audit Checklist

The fall of SIDH (Supersingular Isogeny Diffie-Hellman) demonstrated that assuming the hardness of the core problem (path finding in expander graphs) is insufficient if the protocol leaks structural hints. Use this checklist when reviewing whitepapers or implementations of novel isogeny-based cryptography.

## 1. Torsion Point Leakage
- [ ] **Are auxiliary points transmitted?** Does the protocol require Alice to publish $\phi_A(P)$ and $\phi_A(Q)$ for some public torsion basis $\{P, Q\}$?
  - *If YES:* High risk of Castryck-Decru style attacks. Mathematical proof must be provided showing why Kani's theorem cannot be used to lift the curves to an abelian surface and reconstruct $\phi_A$.

## 2. Degree of the Secret Isogeny
- [ ] **Is the degree of the secret isogeny public?** 
  - *Context:* In SIDH, Alice's isogeny degree $2^a$ and Bob's $3^b$ were public. The Castryck-Decru attack heavily relies on the attacker knowing the exact degree of the secret isogeny to construct the higher-dimensional attack.
  - *Mitigation:* Protocols that hide the degree (or use variable/unknown length walks) may offer some resistance, though this is difficult to achieve in practice.

## 3. Endomorphism Ring Exposure
- [ ] **Does the protocol rely on curves with known endomorphism rings?**
  - *Context:* Many attacks on isogeny graphs become polynomial time if the endomorphism ring of the starting curve is known and easily computable.
  - *Audit Step:* Verify if the starting curve $E_0$ is securely generated or if its endomorphism ring is intentionally hidden. (Note: standard SIDH used a starting curve with a known endomorphism ring).

## 4. Commutative vs. Non-Commutative
- [ ] **Is the group action commutative?**
  - *If YES (e.g., CSIDH):* The protocol relies on the action of the ideal class group. It avoids auxiliary torsion points entirely, bypassing the CD attack. However, evaluate it against quantum subexponential attacks (like Kuperberg's algorithm).
  - *If NO (e.g., SIDH):* The protocol is non-commutative and relies on random walks. Extreme scrutiny is required for any extra data transmitted alongside the final curve.

## 5. Signature Schemes vs. Key Exchange
- [ ] **Is this a signature scheme?**
  - *Context:* Signature schemes like **SQIsign** operate differently from SIDH. They do not publish torsion images to complete a square. Instead, they prove knowledge of a path. 
  - *Audit Step:* Ensure the zero-knowledge proof or signature transcript does not inadvertently leak torsion information during the challenge-response phase.
