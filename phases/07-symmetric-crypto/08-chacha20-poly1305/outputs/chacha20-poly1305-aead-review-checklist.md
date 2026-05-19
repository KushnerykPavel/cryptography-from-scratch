---
name: "ChaCha20-Poly1305 AEAD Review Checklist"
description: "PR review + integration checklist for using AEAD_CHACHA20_POLY1305 safely (nonce rules, AAD, tag verification, framing)."
phase: "07-symmetric-crypto"
lesson: "08-chacha20-poly1305"
---

# ChaCha20-Poly1305 AEAD Review Checklist

Use this checklist when reviewing code that implements or wraps ChaCha20-Poly1305 (RFC 8439), or when designing a message format.

## Nonce rules (highest priority)
- [ ] Nonce is 96 bits (12 bytes) for the IETF variant (not 8 bytes, not 24 bytes).
- [ ] Nonce uniqueness is guaranteed **per key** (never reuse `(key, nonce)`).
- [ ] The nonce generation policy is documented (counter, random, or structured).
- [ ] If nonces are counters, they are stored durably (crash/restart must not repeat).
- [ ] If nonces are random, the system can tolerate the collision risk (and the RNG is sound).

## Tag verification (must be strict)
- [ ] Decrypt rejects if tag verification fails (no plaintext returned).
- [ ] Tag comparison uses a constant-time compare (or library-provided verify).
- [ ] The tag is exactly 16 bytes and always checked.

## AAD usage (what is authenticated but not encrypted?)
- [ ] AAD covers all security-critical metadata (protocol version, sender id, message type, key id, sequence number, etc.).
- [ ] AAD is identical on encrypt and decrypt paths (same serialization, same bytes).
- [ ] The code doesn’t accidentally authenticate a *different* header than the one being parsed.

## Framing / serialization (avoid ambiguity)
- [ ] Message format is unambiguous and versioned, e.g.:
  - `version || key_id || nonce || aad_len || aad || ciphertext || tag`
- [ ] Lengths are validated before allocation (reject absurd sizes).
- [ ] Nonce and tag are never parsed from attacker-controlled offsets without bounds checks.

## Variant / API mismatches
- [ ] The code consistently uses the same variant across languages/services:
  - ChaCha20-Poly1305 (IETF, 12-byte nonce) vs XChaCha20-Poly1305 (24-byte nonce).
- [ ] The code doesn’t “roll its own” by mixing ChaCha20 and Poly1305 without the RFC’s one-time key derivation.

## Misuse tests (add these to CI)
- [ ] **Tamper test:** flip 1 bit of ciphertext → decrypt must reject.
- [ ] **Tag tamper test:** flip 1 bit of tag → decrypt must reject.
- [ ] **AAD tamper test:** modify AAD → decrypt must reject.
- [ ] **Nonce reuse test (negative):** reusing nonce is detected by design (or forbidden by API contract and exercised in tests).

## Operational guidance (production)
- Prefer audited libraries over from-scratch code.
- Treat nonce strategy as part of the protocol, not an implementation detail.
- Log failures carefully: “tag invalid” is useful; dumping plaintext is not.

