---
name: "PQ Migration Audit Checklist (PR/Design Review)"
description: "A paste-ready checklist for reviewing a post-quantum migration change: inventory, negotiation, hybrid combiner, rollout, and telemetry."
phase: "16-pq-isogenies-and-migration"
lesson: "09-pq-migration-lab"
---

# PQ Migration Audit Checklist (PR/Design Review)

Use this when reviewing a PR or design doc that touches TLS, certificates, key exchange, signatures, or “crypto glue” code.

## 1) Scope & boundaries (inventory)

- What are the exact **trust boundaries** (client→edge, edge→API, API→DB, service mesh, batch jobs, backups)?
- For each boundary, list:
  - protocol (TLS 1.2/1.3, SSH, JOSE/JWT, custom)
  - key establishment (ECDH group / KEM / hybrid)
  - authentication (certs, tokens, signatures)
  - symmetric crypto (AEAD mode, key sizes)
  - hash/KDF (HKDF, HMAC, SHA-2/SHA-3)
  - key lifetimes (session, cert validity, archive retention)
- Which dependencies implement crypto (OpenSSL/BoringSSL/AWS-LC, language runtime, KMS, HSM, SDKs)?

## 2) Algorithm agility (is this change reversible?)

- Is the algorithm choice **configuration-driven** (not hard-coded)?
- Are algorithm identifiers validated/parsed (reject unknown / malformed / unsafe names)?
- Is there a clear policy layer:
  - `allowed` vs `preferred` vs `banned`
  - “must be hybrid” for specific boundaries
  - emergency kill-switch (“disable PQ KEM X globally”)

## 3) Negotiation & downgrade resistance

- If this involves negotiation (TLS groups/ciphers, SSH KEX, protocol versions):
  - Do we log/measure what was **offered** and what was **selected**?
  - Is there an explicit policy gate that can **fail closed** when required?
  - Are we protected against **silent fallback** (unexpected negotiation results)?
- If there is a “hybrid” mode:
  - Is hybrid treated as a first-class negotiated suite, or is it an app-layer hack?
  - Is the negotiation result bound into the key schedule context (transcript binding)?

## 4) Hybrid combiner (if you combine secrets)

When combining `classical_shared` and `pq_shared`:

- Do we use an **extract-then-expand** KDF (HKDF-style), not just `SHA256(Z1 || Z2)`?
- Are secrets combined in a way that remains secure if one input is biased or later broken?
- Is the KDF context (`info`) domain-separated (protocol + suite + role + version)?
- Is the transcript hashed with unambiguous encoding (length-prefix or structured encoding)?

## 5) Key size & performance (does this break the network?)

- Have we measured:
  - handshake size (cert chains, KEM keys/ciphertexts)
  - MTU/fragmentation and any middlebox issues
  - CPU cost on servers and clients
  - memory pressure in proxies, sidecars, and HSMs
- Are there compatibility fallbacks for constrained clients (IoT, old SDKs)?

## 6) Long-lived data risk (HN-DL)

- Identify data that must remain confidential for years:
  - backups, archives, recordings, stored messages, database dumps
- Is there a plan for:
  - re-encrypting archives
  - rotating envelope keys
  - shortening key lifetimes where possible

## 7) Rollout plan (how do we ship safely?)

- Is there a staged rollout: `off` → `hybrid` → `pq-preferred` → `pq-required`?
- Are canaries and feature flags in place?
- Do we have an explicit **rollback** strategy?
- Is there an on-call playbook for:
  - handshake failures
  - performance regressions
  - emergency disable of a specific PQ algorithm

## 8) “Break glass” scenario (assume a scheme breaks)

If tomorrow a PQ candidate is broken:

- Can we quickly disable it (config, feature flag, kill-switch)?
- Can we rotate affected keys/certs?
- Can we detect which services/clients negotiated the broken option (telemetry)?
- Do we have a communication plan (internal + customer-facing)?

## Output expectation (what “good” looks like)

A solid migration change comes with:
- an inventory table (boundary → algorithms → lifetimes),
- a policy statement (allowed/preferred/banned),
- rollout stages with telemetry + downgrade alarms,
- and a verified key schedule (hybrid combiner + transcript binding if applicable).

