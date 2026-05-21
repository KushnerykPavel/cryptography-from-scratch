---
name: "PQC Migration Audit Prompt (Classical Crypto Exposure)"
description: "Paste-ready checklist + prompt to inventory RSA/ECDH/ECDSA usage, assess HNDL risk, and plan a hybrid-first post-quantum migration."
phase: "14-pq-lattice"
lesson: "01-why-quantum-breaks-classical"
---

# PQC Migration Audit Prompt (Classical Crypto Exposure)

Use this to audit a repository or system design for post-quantum risk. It is intentionally “hybrid-first”: replace what Shor breaks, increase margins where Grover reduces them, and keep the plan executable.

## Paste-Ready Prompt

You are a security engineer doing a post-quantum (PQC) readiness audit. Analyze the codebase/system described below and produce:

1) **Inventory (by location)**: list every place classical crypto is used (file path / module / service), including:
- Key exchange / KEM (RSA key transport, (EC)DH, ECDH)
- Signatures (RSA, ECDSA, Ed25519/EdDSA, certificates)
- Symmetric crypto (AES-128/256, ChaCha20)
- Hashes / MACs (SHA-256/512, HMAC, HKDF)
- Protocols / formats (TLS config, SSH, JWT/JWS/JWE, X.509, S/MIME, PGP, package signing)

2) **Classify impact**:
- **Broken by Shor** (must replace): RSA, finite-field DH, ECDH, ECDSA/EdDSA where discrete log security matters.
- **Reduced margin by Grover/BHT** (usually bump parameters, don’t panic): symmetric key search, hash preimages/collisions.

3) **Threat model**:
- Identify long-lived confidentiality needs (10–30 years).
- Identify **harvest-now, decrypt-later** exposure (capturable ciphertext, stored encrypted blobs).
- Identify integrity/availability risks (software update signing, identity, key rotation).

4) **Migration plan (hybrid-first)**:
- What to change first (highest risk + lowest dependency cost).
- Where hybrid makes sense (e.g., classical + ML-KEM for key establishment, classical + ML-DSA for signatures).
- Backward compatibility requirements (clients, cert formats, hardware constraints).
- Rollout strategy (feature flags, canaries, telemetry, key/cert rotation windows).

5) **Crypto-agility checklist**:
- Are algorithms negotiated/configurable without redeploying code?
- Are keys/certificates versioned and rotatable?
- Is there a single “crypto API layer” or are primitives scattered?
- Are there test vectors and interoperability tests for protocol changes?

6) **Concrete outputs**:
- A prioritized table: `Component | Primitive | Quantum impact | Fix | Owner | ETA`.
- A list of PR-sized tasks (each should be reviewable within a day or two).

### Inputs
- Codebase/system summary:
  - (paste architecture diagram / key flows / repo tree)
- Any compliance constraints:
  - (FIPS, government profiles, industry standards)
- Any ecosystem constraints:
  - (mobile, embedded, browsers, load balancers, HSMs, PKI)

### Output requirements
- Be explicit about what is an assumption vs what you verified from code.
- Name the *role* of each primitive (KEM vs signature vs KDF vs MAC).
- Use clear language: “broken by Shor” vs “reduced margin by Grover”.

## Quick Reference (for reviewers)

- **Replace (Shor):** RSA, (EC)DH, ECDH, ECDSA/EdDSA (where discrete-log assumptions apply).
- **Bump margins (Grover/BHT):** AES-128 → prefer AES-256; keep SHA-256/512 but understand margins and protocol security levels.
- **Default strategy:** hybrid during transition + crypto-agility so you can rotate again as standards and implementations mature.

