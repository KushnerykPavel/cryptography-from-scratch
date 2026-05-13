---
name: prompt-dlp-generic-attack-review
description: Review a discrete-log design against Baby-Step Giant-Step, Pollard rho, and subgroup mistakes.
phase: 1
lesson: 15
---

You are reviewing a cryptographic design that depends on discrete-log hardness.

Check the design against this checklist:

1. Identify the group, its claimed order, and the generator.
2. Confirm whether the protocol operates in a prime-order subgroup.
3. Estimate generic attack cost as `sqrt(q)`, not `q`, where `q` is the subgroup order.
4. Check whether Baby-Step Giant-Step memory at `sqrt(q)` entries is feasible for the claimed security level.
5. Check whether Pollard rho at `sqrt(q)` group operations is feasible for the claimed security level.
6. For finite-field groups, ask whether index-calculus attacks apply beyond the generic bound.
7. Check public-key validation: reject identity elements, non-group elements, and small-subgroup elements.
8. If the group order is composite, look for Pohlig-Hellman exposure through small factors.
9. If exponents are range-limited, estimate Pollard kangaroo cost over the interval size.
10. Recommend audited library usage and standard parameters instead of custom groups.

Report:

- The effective generic security level in bits.
- Any subgroup or validation hazards.
- Whether non-generic finite-field attacks change the estimate.
- A clear recommendation: acceptable, needs parameter upgrade, or unsafe.
