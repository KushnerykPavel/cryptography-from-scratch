---
name: csidh-review-and-migration-checklist
description: Decision guide + review checklist for CSIDH/isogeny-based proposals and safe migration plans.
phase: 16-pq-isogenies-and-migration
lesson: 03-csidh
---

# CSIDH / Isogeny-Based KEX — Review + Migration Checklist

Use this when you see a proposal to use “CSIDH”, “supersingular isogenies”, “commutative group action”, or any isogeny-based key exchange in a design doc / PR.

## 1) Fast triage

- **What exact construction is proposed?** `CSIDH` (class-group action) vs `SIDH/SIKE` (torsion-point images) vs “something isogeny-ish”.
- **What is the intended security goal?** Key exchange (KEX), KEM, signatures, or identity/PAKE? The risk profile differs.
- **What deployment tier is this?** Public Internet, internal service mesh, embedded, long-term archival, etc.

## 2) Red flags (stop-the-line)

- “We implemented it from scratch.” (Isogeny code is extremely easy to get subtly wrong.)
- “We don’t need constant-time; it’s server-side.” (Remote timing exists; KEX secrets are long-lived enough to matter.)
- “We’ll validate it with a few test vectors.” (You need much more: side-channel evaluation, fuzzing, differential tests, and protocol-level validation.)
- “We’ll just swap ECDH for CSIDH.” (PQ migration usually needs hybrid or negotiated modes and careful failure handling.)

## 3) Questions that must be answered in writing

- **Threat model.** What quantum capability is assumed? What classical attacker capability (timing, cache, micro-architectural, fault)?
- **Interoperability.** Who else implements this, and how will keys/ciphersuites be negotiated?
- **Key validation.** What checks prevent invalid-curve / malformed public keys from driving secret-dependent branches?
- **Side channels.** What is the plan for constant-time arithmetic, constant-time isogeny evaluation, and constant-time key derivation?
- **Parameter management.** Where do parameters come from? How are they versioned? How are upgrades handled?

## 4) Engineering review checklist

- **Constant-time discipline**
  - No secret-dependent branches, table lookups, or early exits in field ops / ladder / isogeny eval.
  - Blinding or dummy isogenies are used if required by the algorithm variant.
- **Validation**
  - Public keys are validated (curve membership / invariants / subgroup checks as applicable).
  - Rejection sampling does not leak information.
- **KDF & transcript binding**
  - Shared secret is never used directly; a KDF binds it to protocol context.
  - The transcript includes algorithm identifiers and parameter versions.
- **Testing**
  - Differential tests vs a known-good reference (e.g., Sage or a vetted implementation) for small parameters.
  - Property tests: invariants preserved under isogeny, group-law identities, edge-case rejection.
- **Observability**
  - Metrics for failures, validation rejects, and fallback behavior (without leaking secrets).

## 5) Migration plan template (use for PQ rollout)

- **Step 0 (inventory):** List every place ECDH (or RSA) appears: TLS, SSH, app-layer KEX, device provisioning, cert issuance.
- **Step 1 (hybrid):** Deploy **hybrid KEX** (classical + PQ) where both must succeed, and bind both into the transcript.
- **Step 2 (negotiation):** Ensure downgrade resistance (algorithm negotiation must be authenticated).
- **Step 3 (monitor):** Track handshake failure rates and CPU cost; watch for DoS amplification.
- **Step 4 (flip):** Make PQ mandatory only after sustained success and clear rollback procedures.

## 6) What this course’s toy implementation does / does not prove

- It shows the *math plumbing* (finite fields, elliptic-curve arithmetic, Vélu isogenies) on tiny parameters.
- It does **not** provide production-safe CSIDH, does **not** cover constant-time evaluation, and does **not** validate real-world security claims.

