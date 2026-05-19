---
name: stream-cipher-integration-checklist
description: Practical checklist for designing, reviewing, and auditing stream cipher usage (nonce/counter rules + integrity).
version: 1.0.0
phase: 07
lesson: 02
tags: [cryptography, symmetric-crypto, stream-cipher, chacha20, nonce, aead, code-review]
---

Use this checklist any time you see “we encrypt by XORing with a keystream” or “we use ChaCha20/CTR”.

If any **red flag** is hit, stop the review and redesign (or switch to AEAD).

## Quick decision guide

- If you need confidentiality **and** integrity: use an **AEAD** (e.g. ChaCha20-Poly1305, AES-GCM).
- If you truly need raw stream encryption (rare): you must separately provide integrity (MAC) and define nonce/counter rules.
- If the design mentions “RC4”: replace it.

## Checklist (copy into PR review)

### Primitive choice
- [ ] Uses a modern primitive (ChaCha20 or AES-CTR), not RC4 or a custom PRNG.
- [ ] If used for network messages or stored data: uses AEAD (preferred) instead of raw stream cipher.

### Key management
- [ ] Key length matches the primitive (ChaCha20 = 32 bytes).
- [ ] Keys come from a KDF (or secure random generator), not from passwords directly.
- [ ] Rekeying story exists if the key is long-lived (rotation or per-session derivation).

### Nonce + counter rules (most important)
- [ ] **Uniqueness guarantee:** the same `(key, nonce)` pair never repeats.
- [ ] Nonce generation is explicit:
  - counter-based (monotonic) OR
  - random with collision plan (storage/checking or statistically safe bounds).
- [ ] Counter behavior is defined:
  - starting value (ChaCha20-IETF commonly starts at `1`)
  - increment per 64-byte block
  - what happens on wraparound (32-bit counter ⇒ max 2^32 blocks per nonce).
- [ ] Any streaming API prevents accidental “reset to counter=1” with the same nonce.

**Red flag:** “nonce is random” with no mention of collisions, persistence, or scale.

### Message format and integrity
- [ ] Packet format is unambiguous and versioned (e.g. `version || nonce || ciphertext || tag`).
- [ ] Integrity is covered:
  - AEAD tag validated before using plaintext, OR
  - MAC over `nonce || ciphertext` (and any metadata) with a distinct MAC key.
- [ ] Replay/ordering is handled if relevant (sequence numbers, timestamps, session binding).

**Red flag:** “we decrypt and then parse JSON” without an authenticity check first.

### Associated data (AEAD designs)
- [ ] All metadata that must be authenticated (protocol version, sender id, message type) is included as AAD.

### Foot-guns to search for in code
- [ ] Any reuse of the same nonce constant.
- [ ] Nonce derived from low-entropy sources (timestamps alone, `rand()%N`, user ids).
- [ ] Encryption called twice with the same `(key, nonce)` in a loop.
- [ ] Nonce generation differs across platforms/languages (interop mismatch).
- [ ] Ciphertext malleability exploited unintentionally (bit flips change meaning).

### Testing requirements
- [ ] Test vectors exist (for primitives: official RFC/NIST vectors).
- [ ] Roundtrip tests exist (decrypt(encrypt(m)) = m).
- [ ] Negative tests exist (wrong key/nonce/tag rejected).

## “Ask me to review” prompt

Paste this into your LLM/code-review tool alongside the code and protocol spec:

1. Identify the primitive and mode (raw stream vs AEAD).
2. Prove (or refute) nonce uniqueness per key. If refuted, show the concrete two-time-pad leak.
3. Check integrity: can an attacker flip bits to change meaning without detection?
4. List the exact fields on the wire and what is authenticated.
5. Recommend the smallest redesign that removes all red flags.

