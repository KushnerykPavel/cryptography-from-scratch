---
name: PQ Migration Decision Guide
description: A reusable decision guide for migrating classical cryptographic primitives to post-quantum safe alternatives, with migration paths, risk levels, and concrete action items.
phase: 20-capstones
lesson: 03-pq-messenger
---

# PQ Migration Decision Guide

## 1. Threat Model: Why Migrate?

A cryptographically relevant quantum computer (CRQC) running Shor's algorithm would break:

- RSA (key exchange, signatures, encryption)
- Classic DH and ECDH (including X25519, X448)
- ECDSA and EdDSA (Ed25519, P-256, P-384)

It would not break (but would weaken):

- Symmetric ciphers: AES-128 -> AES-256 restores the security margin
- Hash functions: SHA-256 -> SHA-384/SHA-512 restores the security margin
- HMAC-based MACs: same advice as hash functions

The "harvest now, decrypt later" (HNDL) attack means adversaries can capture encrypted traffic today and decrypt it once a CRQC exists. Long-lived secrets (health records, financial data, government communications) are at risk immediately.

---

## 2. Primitive-by-Primitive Migration Map

| Classical Primitive | PQ Replacement | NIST Standard | Migration Priority |
|---------------------|---------------|---------------|--------------------|
| RSA-2048 key exchange | ML-KEM-768 or ML-KEM-1024 | FIPS 203 | Critical |
| ECDH (X25519, P-256) | ML-KEM-768 | FIPS 203 | Critical |
| RSA-PSS signatures | ML-DSA-65 or ML-DSA-87 | FIPS 204 | High |
| ECDSA / EdDSA | ML-DSA-44 (min) | FIPS 204 | High |
| RSA-OAEP encryption | ML-KEM + AEAD hybrid | FIPS 203 | Critical |
| AES-128-GCM | AES-256-GCM | - | Medium (double key length) |
| SHA-256 | SHA-384 or SHA-512 | - | Low |
| HMAC-SHA256 | HMAC-SHA384 | - | Low |

---

## 3. Hybrid Transition Strategy

During the migration period, run classical + PQ in parallel and combine via HKDF:

```
session_key = HKDF(
    salt   = random_salt,
    IKM    = classical_shared_secret || pq_shared_secret,
    info   = b"hybrid-session-v1",
    length = 32
)
```

This provides:

- Security if the PQ algorithm is broken (classical still protects you)
- Security if the classical algorithm is broken by a CRQC (PQ still protects you)
- A clear upgrade path: drop the classical component once PQ is trusted in your jurisdiction

---

## 4. Decision Tree

```
Does the data need to stay confidential for > 5 years?
  YES -> HNDL risk is real. Prioritize KEM migration now.
  NO  -> Lower urgency, but schedule migration within 2-3 years.

Is the primitive used for key exchange / encryption?
  YES -> Replace with ML-KEM (FIPS 203) or hybrid.
  NO  -> Continue below.

Is the primitive used for authentication / signatures?
  YES -> Replace with ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).
  NO  -> Assess case by case.

Is this a symmetric primitive (AES, HMAC, SHA)?
  YES -> Double the key/output length. No PQ replacement needed.
```

---

## 5. Interoperability Checklist

Before deploying PQ primitives in production:

- [ ] Confirm your TLS library supports hybrid KEMs (e.g., X25519Kyber768 in BoringSSL/OpenSSL 3.x)
- [ ] Check that your HSM / key store supports 1184-byte ML-KEM-768 public keys
- [ ] Update certificate lifetimes: ML-DSA certificates are larger (2-5 KB vs 0.5 KB for P-256)
- [ ] Verify that your protocol allows negotiating PQ cipher suites (TLS 1.3 extension, IKEv2 transform)
- [ ] Test against NIST CAVP test vectors for FIPS 203/204/205 compliance
- [ ] Implement and test hybrid KEM fallback for peers that do not support PQ yet

---

## 6. Key Size Reference

| Algorithm | Public Key | Private Key | Ciphertext / Signature |
|-----------|-----------|-------------|----------------------|
| X25519 (classical) | 32 B | 32 B | 32 B shared secret |
| RSA-3072 (classical) | 384 B | 1.2 KB | 384 B ciphertext |
| ML-KEM-512 | 800 B | 1632 B | 768 B ciphertext |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B ciphertext |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B ciphertext |
| ML-DSA-44 | 1312 B | 2528 B | 2420 B signature |
| ML-DSA-65 | 1952 B | 4000 B | 3293 B signature |
| SLH-DSA-128s | 32 B | 64 B | 7856 B signature |

---

## 7. Timeline Guidance

| Year | Recommended Action |
|------|--------------------|
| Now (2025-2026) | Inventory all uses of classical asymmetric crypto. Begin hybrid KEM deployment in new systems. |
| 2026-2028 | Complete hybrid migration for all long-lived-data systems. Enforce PQ-only for new deployments. |
| 2028-2030 | Deprecate classical-only cipher suites. Complete migration to ML-KEM / ML-DSA across the estate. |
| Post-2030 | Monitor CRQC development. Maintain crypto-agility to swap algorithms without protocol changes. |

---

## 8. Crypto-Agility Pattern

Encode the algorithm identifier alongside every ciphertext/signature so future migration is a config change, not a code change:

```python
# Store: algorithm_id (1 byte) || ciphertext
ALGO_HYBRID_V1 = 0x01

def wrap_ciphertext(ciphertext: bytes) -> bytes:
    return bytes([ALGO_HYBRID_V1]) + ciphertext

def unwrap_ciphertext(data: bytes) -> tuple[int, bytes]:
    return data[0], data[1:]
```

---

## 9. Further Reading

- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- NIST SP 800-208 (stateful HBS): https://csrc.nist.gov/publications/detail/sp/800-208/final
- ETSI TR 103 619: Migration strategies and recommendations for quantum-safe cryptography
- NSA CNSA 2.0 Suite: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF
