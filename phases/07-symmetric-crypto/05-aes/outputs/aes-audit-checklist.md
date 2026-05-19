---
name: AES Audit Checklist
description: A practical checklist for reviewing AES usage in code and system designs (modes, nonces/IVs, padding, keys, and common foot-guns).
phase: 07-symmetric-crypto
lesson: 05-aes
---

# AES Audit Checklist (PR review / design review)

## 1) Stop-the-line questions
- Is this using an **AEAD** (AES-GCM / AES-CCM / ChaCha20-Poly1305) when integrity is required? If not, why?
- Is anyone attempting to “implement AES” or “implement GCM” from scratch? If yes, stop and require an audited library.
- Is the mode **ECB**? If yes, stop: ECB leaks patterns.

## 2) Mode-specific checks

### AES-GCM
- Nonce/IV uniqueness is enforced for a given key (never reuse the same nonce with the same key).
- Tag verification is mandatory and checked before using plaintext (fail closed).
- Nonce length is explicit (12 bytes is the most common standard; if not 12, ensure the library handles it correctly).
- Associated data (AAD) is used when there is metadata that must be authenticated (headers, protocol fields, key IDs).

### AES-CTR
- Nonce + counter is **never reused** for the same key (nonce reuse turns CTR into a two-time pad).
- Counter increment and wraparound behavior is specified and tested.
- Integrity is provided separately (e.g., HMAC) if not using AEAD.

### AES-CBC
- IV is random/unpredictable per message (never reuse IV with the same key).
- Padding is well-defined (typically PKCS#7) and validated safely.
- Integrity/authentication is provided (CBC is malleable without a MAC/AEAD).

## 3) Key handling checks
- Key sizes are explicit (128/192/256-bit) and match requirements.
- Keys come from a KDF/KMS, not from raw passwords or hardcoded constants.
- Keys are scoped: different keys for different purposes (encryption vs MAC; different contexts).
- Rotation strategy exists (how often, how to re-encrypt, key IDs/versioning).

## 4) Data & API checks
- Clear separation of `{ciphertext, nonce/iv, tag, aad}` in serialization (no ambiguous concatenation).
- All parameters needed for decryption are stored/transmitted (nonce/iv and tag are not “optional”).
- Errors are handled consistently (no silent fallbacks like “try decrypt again with a different mode”).

## 5) Correctness & regression checks
- Implementation is validated against authoritative vectors (FIPS 197 / NIST CAVP for AES; official test vectors for the chosen mode).
- Unit tests cover: wrong key, wrong tag, wrong nonce, truncated inputs, tampered ciphertext.
- Interop tests exist if multiple languages/services encrypt/decrypt the same payloads.

## 6) Side-channel & deployment checks
- Constant-time behavior matters in shared environments; prefer mature libraries and safe primitives.
- Avoid exposing “padding error vs MAC error” distinctions in networked protocols.

## Copy/paste prompt (useful outside the course)
Paste this into a code review tool or LLM:

“Review this code/design for AES usage. Identify the mode, nonce/IV rules, integrity guarantees, key management, serialization format, and error handling. Flag ECB usage, nonce reuse risks (CTR/GCM), CBC padding/oracle risks, missing authentication, and missing test vectors. Recommend an audited library and AEAD where appropriate.”
