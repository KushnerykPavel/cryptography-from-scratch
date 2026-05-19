---
name: rsa-padding-decision-guide
description: A practical checklist for choosing and reviewing RSA padding (OAEP, PSS, PKCS#1 v1.5).
version: 1.0.0
phase: 8
lesson: 02
tags: [cryptography, rsa, oaep, pss, pkcs1]
---

Use this guide in PR reviews, audits, and interop specs when you see “RSA encryption” or “RSA signatures”.

## Quick decisions

| Goal | Use | Default parameters | Avoid |
|------|-----|--------------------|-------|
| Encrypt a short plaintext (or symmetric key) | **RSAES-OAEP** | `Hash = SHA-256`, `MGF1 = SHA-256`, `label = empty` | Textbook RSA, PKCS#1 v1.5 encryption unless forced by legacy interop |
| Sign a message | **RSASSA-PSS** | `Hash = SHA-256`, `MGF1 = SHA-256`, `saltLen = MAX_LENGTH` (or `hLen`) | Textbook RSA signatures; ad-hoc “sign the plaintext integer” |
| Legacy signature interop | **RSASSA-PKCS1-v1_5** | `Hash = SHA-256` | Mixing hashes, custom ASN.1, accepting multiple encodings |

Rule of thumb: RSA is easy to misuse. If you control both sides, prefer modern primitives (X25519 + AEAD for encryption; Ed25519 for signatures) unless you have a strong reason to stick with RSA.

## Interop spec template (paste into docs)

Encryption (RSA-OAEP):
- Key: RSA `nBits = ____` (minimum: 2048 in production)
- OAEP hash: `SHA-256`
- MGF1 hash: `SHA-256`
- Label: empty / `None` (must match exactly on both sides)
- Ciphertext length: `k = ceil(nBits / 8)` bytes

Signatures (RSA-PSS):
- Key: RSA `nBits = ____` (minimum: 2048 in production)
- PSS hash: `SHA-256`
- MGF1 hash: `SHA-256`
- Salt length policy: `MAX_LENGTH` (preferred) / fixed `32` (interop) / fixed `hLen`
- Signature length: `k = ceil(nBits / 8)` bytes

## Code review checklist

1. Encryption uses **OAEP**, not raw RSA or v1.5 (unless you have explicit legacy interop + mitigations).
2. Signatures use **PSS** (or v1.5 signatures only when required), never “RSA on the message integer”.
3. OAEP/PSS hash + MGF1 hash are explicitly set and match the interop spec.
4. OAEP label is explicit (usually empty) and consistent across languages.
5. Decryption failures do not leak padding validity through different errors, timing, retries, or logs.
6. No “helpful” fallback: do not try OAEP then v1.5 then raw RSA automatically.
7. Inputs are length-checked (`ciphertext`/`signature` must be exactly `k` bytes).
8. RSA is only used to encrypt a **random session key**, not bulk data (use hybrid encryption).
9. Keys are >= 2048 bits in production and come from a vetted source (HSM / OS key store / audited library).
10. Tests include negative cases: wrong label, wrong hash, wrong salt policy, mutated ciphertext/signature.

## Red flags

- “We implemented OAEP/PSS ourselves for performance.”
- Any PKCS#1 v1.5 decryption exposed to attackers (network-facing, API-facing, or attacker-controlled ciphertexts).
- Errors that distinguish “bad padding” vs “bad key” vs “bad format”.
- OAEP with `Hash=SHA-256` but `MGF1=SHA-1` (unless an interop spec forces it).
- Accepting multiple padding modes on the same endpoint (“auto-detect”).

## If you’re stuck with PKCS#1 v1.5 encryption

Treat it as a legacy compatibility mode:
- Prefer OAEP for all new endpoints and new tokens.
- Remove any detailed error messages; keep uniform failure behavior.
- Rate-limit and monitor failures (padding-oracle attacks are query-driven).
- Plan migration: new key material + OAEP-only endpoints.

