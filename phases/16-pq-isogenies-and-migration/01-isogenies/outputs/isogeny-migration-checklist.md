---
name: "Isogeny-Based PQC Migration Checklist (SIDH/SIKE → Alternatives)"
description: "Paste-ready review checklist + prompt to identify SIDH/SIKE usage, assess blast radius, and migrate to supported post-quantum KEMs."
phase: "16-pq-isogenies-and-migration"
lesson: "01-isogenies"
---

# Isogeny-Based PQC Migration Checklist (SIDH/SIKE → Alternatives)

Use this when you suspect a repo/system includes SIDH/SIKE (or adjacent isogeny-graph constructions) and you need an actionable plan.

## Fast Triage (10 minutes)

1) **Identify primitives (by exact name)**
- Search for: `SIDH`, `SIKE`, `p434`, `p503`, `p610`, `p751`, `isogeny`, `supersingular`, `Montgomery curve`, `Fp2`, `j-invariant`
- Common library clues: `PQCLEAN_SIKE`, `libsike`, `sikep*`, `SIDH_*` constants, “3-isogeny / 4-isogeny chains”

2) **Where is it used?**
- KEM/key exchange (TLS, custom handshake, device pairing)
- PKE wrapper around SIDH primitives
- Any “hybrid” mode (classical + SIKE)

3) **Immediate risk statement**
- If it’s SIDH/SIKE: treat as **cryptographically broken** (key recovery attacks exist). Plan removal and emergency rotation.

## Engineering Checklist (PR review)

### A) Inventory & blast radius
- List every usage site: `file path | module | protocol role | key material lifetime`.
- Identify captured-traffic risk (HNDL): recorded handshakes protecting long-lived secrets.
- Identify stored artifacts: public keys in databases, certificates/configs, device firmware keys.

### B) Removal plan (safe-by-default)
- Remove or disable negotiation paths that can select SIDH/SIKE.
- Delete dead code *after* rollout to avoid accidental re-enable.
- Add tests that assert “no SIKE/SIDH” in negotiated cipher suites / config.

### C) Replacement direction (practical)
- Prefer **standardized PQ KEMs** (e.g., ML-KEM) for key establishment.
- Use a **hybrid** during transition if compatibility requires it (classical + PQ), but never rely on the broken component for security.
- Keep crypto-agility: algorithm IDs/versioning + key rotation hooks.

### D) Key & session rotation
- Rotate affected secrets:
  - long-lived private keys used in key establishment
  - any keys derived from compromised sessions (if applicable)
- Consider forced re-handshake / session cache invalidation where relevant.

### E) Verification (what “done” means)
- Static checks:
  - No SIDH/SIKE symbols or parameter sets remain in build outputs.
  - No config/flags can enable SIDH/SIKE in production builds.
- Dynamic checks:
  - Integration tests prove negotiated KEM is the intended replacement.
  - Interop tests with clients/servers actually deployed.

## Paste-Ready Prompt (for an AI/code reviewer)

You are a security engineer reviewing a codebase for isogeny-based PQC usage and migration risk.

1) Search for any SIDH/SIKE/isogeny-graph cryptography usage and list every location with file paths.
2) For each location, classify the role (KEM/key exchange, PKE, signature, toy/demo) and the exposure (internet-facing, internal-only, test-only).
3) If SIDH/SIKE is present, propose a concrete removal/migration plan:
   - replacement primitive(s)
   - rollout steps (feature flags, canary, compatibility)
   - key/session rotation actions
   - tests to prevent reintroduction
4) Output a prioritized table: `Component | Where | Role | Risk | Fix | Owner | ETA`.

Constraints:
- Assume SIDH/SIKE is broken and must not be used for security.
- Prefer standardized PQ primitives and hybrid-first migration.
- Be explicit about what you verified vs assumed.

