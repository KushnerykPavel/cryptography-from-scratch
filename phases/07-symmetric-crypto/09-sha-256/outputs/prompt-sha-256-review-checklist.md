---
name: prompt-sha-256-review-checklist
description: PR review checklist for safe SHA-256 usage (bytes/encoding, MAC vs hash, length-extension traps, comparisons).
phase: 07
lesson: 09
---

You are reviewing code that uses SHA-256. Use this checklist to decide whether it’s correct and safe.

## 1) What is SHA-256 being used for?
Pick the intent, then evaluate against the matching rules:

- **Fingerprint / dedupe / caching key** (non-secret): OK if inputs are canonicalized.
- **Integrity check** (download verification): OK only if the expected digest comes from a trusted channel.
- **Authentication / signed token / “MAC”**: SHA-256 alone is usually wrong; prefer **HMAC-SHA256** or an **AEAD**.
- **Password hashing**: SHA-256 is wrong; use a password KDF (Argon2id / scrypt / PBKDF2 with strong parameters).
- **Key derivation**: Prefer HKDF (HMAC-based), not ad-hoc `sha256(secret || context)`.

## 2) Are inputs canonical bytes?
Checklist:

- The code hashes **bytes**, not a language-level “string object”.
- If a string is hashed, the encoding is explicit and stable (usually UTF-8).
- If the input is structured (JSON, headers, claims), the serialization is canonical (ordering, whitespace, normalization).
- There is no accidental double-encoding (e.g., hashing a hex digest string instead of the raw bytes).

## 3) Is SHA-256 being used as a MAC (keyed integrity)?
Red flags:

- `sha256(secret || message)`
- `sha256(message || secret)`
- `sha256(secret + message)` in any language
- “token = sha256(secret, message)” where the API is really concatenation

If you see any of these, propose:

- Replace with **HMAC-SHA256** (`hmac.new(key, msg, hashlib.sha256)` in Python).
- Ensure constant-time comparison (`hmac.compare_digest`).

## 4) Length-extension risk (Merkle–Damgård footgun)
If the design exposes `sha256(secret || message)` and allows an attacker to append data to `message`, it can be vulnerable to length extension (the attacker can compute a valid digest for `message || extra` without knowing the secret).

Mitigations:

- Use HMAC (designed to avoid this).
- If you must build a “commitment”, use an explicit domain separator and hash structured data with lengths.

## 5) Are comparisons done safely?
If a digest is treated as a secret (token, API key hash check, MAC tag), require constant-time compare:

- Python: `hmac.compare_digest(a, b)`

Avoid:

- `a == b` for secret comparisons in security-sensitive code paths.

## 6) Output formats and storage
Checklist:

- `digest` is 32 bytes; `hexdigest` is 64 hex characters.
- If storing/transmitting, the code documents which representation is used (raw bytes vs hex vs base64).
- If storing hashes for integrity, store the hash with algorithm metadata (e.g., `sha256:<hex>`), not “just a hex string”.

## 7) Quick “what to ask the author”
- What threat model is this for: corruption, attacker modification, or authentication?
- Where does the expected digest / key come from?
- What canonicalization rules define the exact bytes being hashed?
- Why SHA-256 specifically (vs SHA-3, BLAKE3, or an AEAD/HMAC/KDF)?

