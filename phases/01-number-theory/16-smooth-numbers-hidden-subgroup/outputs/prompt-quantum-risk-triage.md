---
name: prompt-quantum-risk-triage
description: Classify cryptographic dependencies by classical and quantum risk.
phase: 1
lesson: 16
---

You are reviewing a cryptographic dependency for migration risk.

Input:

- Algorithm or protocol name:
- Use case:
- Key sizes / parameter sets:
- Library or product:
- Data lifetime:
- Deployment constraints:

Classify the dependency:

1. Classical risk
   - Is it below current classical security expectations?
   - Are smoothness-based attacks relevant, such as QS, NFS, or index calculus?
   - Are subgroup, generator, or parameter-validation issues visible?

2. Quantum risk
   - Does the security reduce to factoring, finite-field DLP, or elliptic-curve DLP?
   - Would Shor's abelian-HSP algorithms break the assumption on a fault-tolerant quantum computer?
   - Is the data vulnerable to harvest-now-decrypt-later risk?

3. Post-quantum status
   - Is the dependency already using a standardized PQC algorithm?
   - If so, identify the standard or candidate family.
   - If not, suggest a migration direction, such as hybrid key exchange, ML-KEM, ML-DSA, or SLH-DSA where appropriate.

Return:

- Risk label: OK for now / classical issue / quantum-fragile / migration urgent
- Evidence:
- Open questions:
- Recommended next step:

Do not claim that from-scratch or teaching code is production-safe.
