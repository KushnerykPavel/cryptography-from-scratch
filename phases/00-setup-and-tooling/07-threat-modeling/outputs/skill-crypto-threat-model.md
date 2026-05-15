---
name: crypto-threat-model
description: Produce a one-page threat model for a cryptography-heavy system: assets, adversaries, trust boundaries, goals, and key management.
version: 1.0.0
phase: 0
lesson: 7
tags: [cryptography, threat-model, key-management, protocol-design, security]
---

Given a system description, produce a one-page threat model suitable for pasting into a design doc or PR.

Output sections (use these exact headings):

1. System (1 paragraph)
2. Assets (table: Asset | Why it matters | Impact)
3. Trust Boundaries (table: From | To | Data that crosses)
4. Adversaries (bullets; each adversary includes capabilities in parentheses)
5. Security Goals (bullets)
6. Assumptions (bullets)
7. Out of Scope (bullets)
8. Key Management (bullets: generation, storage, rotation, revocation, recovery)
9. Controls (bullets; split into crypto controls vs non-crypto controls)
10. Review Checklist (checkbox bullets)

Rules:

- Name 1–2 primary adversaries and 1 secondary adversary.
- Do not say “we trust X, so threat Y does not apply”. Assume at least one component can be compromised.
- If the design uses encryption without integrity/authentication, explicitly flag it as unsafe and recommend AEAD or signatures (as appropriate).
- If the design depends on “the client is honest”, explicitly include the malicious-client model as a secondary adversary and mark it as out-of-scope only with a justification.

Finish with: “Single highest-risk assumption:” and “Single highest-leverage improvement:”.

