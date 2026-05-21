---
name: Shor (Quantum) Migration Checklist
description: Practical checklist to inventory RSA/ECC usage, assess quantum risk, and plan a post-quantum migration for key exchange and signatures.
phase: 14-pq-lattice
lesson: 02-shors-algorithm
---

# Shor (Quantum) Migration Checklist

Use this when reviewing crypto choices, planning a PQ migration, or auditing a system that uses RSA/ECC.

This checklist assumes the Shor threat model: if large-scale fault-tolerant quantum computers become practical, **RSA, finite-field DH, and elliptic-curve DH/ECDSA** are no longer secure at their intended security levels.

## 0) Scope: what you are protecting

- What must remain confidential, and for how long (days / months / years / decades)?
- Is this “real-time secrecy” (TLS session today) or “long-term secrecy” (stored backups, encrypted archives)?
- Is the threat “decrypt later” (record traffic now, break later)?

If long-term confidentiality matters, PQ migration urgency goes up even if quantum capability is uncertain.

## 1) Inventory: where RSA/ECC live (non-negotiable)

For each system/component, record:

- Protocol: TLS, SSH, QUIC, S/MIME, PGP, VPN, custom protocol, firmware update, package signing, JWT, etc.
- Primitive:
  - Key exchange: RSA key transport, (EC)DH, (EC)DHE.
  - Signature: RSA-PSS/PKCS#1 v1.5, ECDSA, EdDSA.
- Role: client, server, CA, HSM, IoT device, offline signer.
- Key sizes/curves: RSA-2048/3072, P-256/P-384, Ed25519, etc.
- Lifetimes: certificate validity, device lifetime, rotation policy.
- Constraints: latency, bandwidth, memory/flash, CPU, hardware accelerators.

Deliverable: a table you can sort by “highest risk + hardest to change”.

## 2) Risk triage: prioritize what to migrate first

- If the system uses **static RSA key transport** or **static (EC)DH**, treat as top priority.
- If confidentiality must last years: prioritize key exchange first (traffic capture risk).
- If integrity must last years (e.g., firmware signing): prioritize signatures.
- Identify “can’t update” endpoints (embedded/IoT) and legacy clients; they dominate timelines.

## 3) Design decision: where PQ fits

Key exchange:

- Prefer **hybrid key exchange** during transition (classical + PQ KEM) to hedge unknowns.
- Decide the KEM (e.g., ML-KEM/Kyber) and parameter set per your security target.

Signatures:

- Decide whether you need PQ signatures now (code signing, long-lived artifacts) or later.
- Pick a signature family compatible with your constraints and ecosystem (e.g., ML-DSA/Dilithium vs Falcon tradeoffs).

Policy:

- Define “crypto agility” requirements: how you will swap algorithms again without redesigning protocols.

## 4) Implementation checklist (engineering)

- Ensure protocol/library support exists for PQ/hybrid in your environment (TLS terminator, client SDKs, HSM support, etc.).
- Confirm key/cert/toolchain implications:
  - certificate sizes,
  - handshake sizes,
  - MTU fragmentation risk,
  - logging/telemetry changes.
- Confirm operational lifecycle:
  - key generation,
  - rotation,
  - revocation,
  - backup/restore.
- Plan for staged rollout:
  - canary clients,
  - feature flags,
  - fallback paths,
  - metrics (handshake failures, latency, packet loss).

## 5) Validation checklist (security + correctness)

- Interop tests across:
  - multiple client implementations,
  - multiple servers/terminators,
  - multiple OS/versions.
- Negative tests:
  - mutate KEM ciphertext/signature → must fail,
  - downgrade attempts → must be rejected or detected,
  - mixed-mode clients (PQ-capable vs legacy).
- Performance tests:
  - tail latencies,
  - CPU spikes,
  - bandwidth/packet counts,
  - memory pressure on constrained endpoints.

## 6) Common failure modes (grep-for-this list)

- “We upgraded TLS” but still use RSA key transport for some clients.
- “We added PQ” but forgot downgrade resistance (client silently falls back).
- Certificates or keys break tooling (parsers, load balancers, proxies, monitoring).
- Handshake packets exceed MTU → fragmentation → intermittent failures.
- Long-lived signed artifacts (firmware, documents) still rely on ECDSA without a PQ plan.

## 7) Output: what good looks like

- A living inventory table with owners + deadlines per system.
- A migration plan with:
  - target algorithms,
  - rollout phases,
  - measurable acceptance criteria,
  - rollback plan.
- A “crypto agility” decision recorded in an ADR/design doc.

