---
name: "ML-KEM Integration Checklist"
description: "A practical PR-review checklist for safely adding ML-KEM (Kyber / FIPS 203) key establishment to real systems."
phase: "14-pq-lattice"
lesson: "06-kyber-ml-kem"
---

# ML-KEM (Kyber / FIPS 203) Integration Checklist

Use this as a PR review checklist when adding ML-KEM to a production system. It assumes your project consumes ML-KEM as a black-box KEM API: `KeyGen`, `Encaps`, `Decaps`.

## 1) Correct primitive usage
- The design treats ML-KEM as a KEM (shared-secret establishment), not “encrypt arbitrary data”.
- Application data encryption uses an AEAD (e.g., AES-GCM or ChaCha20-Poly1305) with keys derived from the KEM shared secret.
- The shared secret output is always passed through a KDF / transcript binding step as required by the chosen API.

## 2) Hybrid strategy (if applicable)
- Hybrid is explicit: the code combines a classical and a PQ shared secret with a well-defined combiner (e.g., `SHA3-256(classical || pq)`).
- The combiner is ordered and domain-separated (e.g., protocol label, version, role).
- The protocol has a clear rollback story: if PQ is disabled, is it intentional and visible (config/telemetry), not silent?

## 3) Key and ciphertext handling
- All inputs are length-checked before parsing (public keys, secret keys, ciphertexts).
- Public keys are authenticated in the protocol (certificates, signatures, pinning, TOFU with rotation rules).
- Secret keys are stored with the same security posture as other long-term private keys (at rest encryption, least privilege, HSM/TEE where relevant).

## 4) Decapsulation safety (CCA and “validity” leakage)
- Decapsulation is treated as sensitive: no error messages, logs, or metrics reveal whether decapsulation “succeeded”.
- Timing and branching on secret-dependent values are avoided in the decapsulation path where the implementation supports it.
- The implementation performs a re-encryption check / implicit rejection (as required by ML-KEM-style FO transforms) and does not expose a ⊥-style error to attackers.

## 5) Side-channel and fault model (deployment specific)
- If you run on shared hardware (multi-tenant, mobile, embedded), you have an explicit side-channel posture (constant-time library choice, mitigations, isolation).
- If fault attacks matter (smartcards/IoT), there is a plan for fault-resistant implementations and response behavior.

## 6) Interoperability and versioning
- Algorithm identifiers are unambiguous (e.g., ML-KEM-512 vs 768 vs 1024; avoid “Kyber” ambiguity in wire formats).
- Serialization formats are specified and tested (byte lengths, endianness, accepted encodings).
- There are test vectors and cross-implementation tests (at least one external implementation in CI or pre-release testing).

## 7) Randomness and determinism
- Keygen uses a CSPRNG that meets your platform requirements (and is correctly seeded).
- Any deterministic “seeded keygen” use is deliberate and documented (it is not a general replacement for secure RNG).
- The code never reuses encapsulation randomness across different public keys (unless the API is explicitly deterministic and binds the key).

## 8) Operational readiness
- Telemetry does not leak secrets: no logging of keys, ciphertexts, or shared secrets; no “decaps failed” counters visible to attackers.
- Rate limits exist where online attackers can force expensive operations.
- There is a migration plan: algorithm agility, rollout flags, compatibility windows, and deprecation timelines.

## Reviewer sign-off
- [ ] Correct primitive usage + AEAD integration
- [ ] Hybrid combiner (if used) is sound and domain-separated
- [ ] Key/ciphertext validation + authentication in protocol
- [ ] Decapsulation path has no validity leakage
- [ ] Side-channel posture is appropriate for deployment
- [ ] Interop tests + vectors exist
- [ ] RNG use is correct
- [ ] Operational controls (logging, rate limits, migration) in place

