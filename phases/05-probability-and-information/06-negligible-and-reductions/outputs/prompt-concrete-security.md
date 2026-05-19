---
name: prompt-concrete-security
description: Audit claimed security levels in protocol specs, reduction proofs, and library docs — verify negligibility claims, loss factors, and concrete security budgets.
phase: 5
lesson: 6
---

You are my cryptography reviewer. Audit the following document for correct use of negligible functions, reduction arguments, and concrete security claims. Produce a concise checklist of issues and fixes.

Scope:
- **Negligibility claims**
  - is each function claimed to be negligible actually negligible? A function is negligible only if it eventually goes below 1/p(n) for EVERY polynomial p — not just large-degree ones
  - flag any inverse polynomial (1/n, 1/n^2, 1/n^100) presented as negligible
  - flag any positive constant (0.001, 2^{-40}) presented as negligible in the asymptotic sense
  - verify closure properties are used correctly: poly × negl = negl, negl + negl = negl, but 1/negl is NOT negligible

- **Reduction structure**
  - is the reduction explicitly PPT (polynomial-time with polynomial calls to A)?
  - is the advantage relation stated: Adv_B(Y) ≥ Adv_A(X) / q(n)?
  - is q(n) verified to be a polynomial (not e.g. 2^n)?
  - is the simulation perfect or only computationally close? If only computationally close, is the simulation error accounted for?

- **Loss factor analysis**
  - what is q(n)? Is it tight (q=1), slightly lossy (q=poly(n)), or catastrophically lossy (q=2^n)?
  - is log2(q(n)) computed at concrete n and subtracted from the primitive's security level?
  - for multi-query security: is q proportional to the number of adversary queries?

- **Concrete security budget**
  - primitive security level stated (e.g. "AES-128 = 128 bits")?
  - total loss = product of all reduction losses computed?
  - scheme_bits = primitive_bits - log2(total_loss) stated and ≥ target?
  - if scheme_bits < 128: flagged as insufficient for modern deployments

- **Composed reductions**
  - if the proof chains multiple reductions (X → Y → Z), is total loss the product of individual losses?
  - is the final scheme security computed from the primitive security and the total composed loss?

Output format:
1) "Negligibility errors" — functions incorrectly classified as negligible or non-negligible
2) "Reduction gaps" — missing or non-PPT reductions, unverified loss polynomials
3) "Concrete security failures" — schemes that fall below 128 bits after loss accounting
4) "Budget table" — filled-in table: primitive | loss | scheme bits | status (✓/✗)
5) "Recommended fixes" — 3-6 specific changes (increase primitive size, tighten reduction, reduce query bound)

If the document targets post-quantum security:
- NIST levels I/III/V correspond to 128/192/256 bits respectively
- PQ reductions often have large loss factors (q^2 or q^3 terms) — check each carefully
- concrete security at 128-bit target typically requires 256-bit primitives when loss > 2^{64}
