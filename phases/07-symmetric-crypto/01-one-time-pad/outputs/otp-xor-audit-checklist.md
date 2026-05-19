---
name: otp-xor-audit-checklist
description: PR review checklist for XOR-based encryption, OTP-like designs, stream ciphers, and AES-CTR usage (spot key/nonce reuse and missing authenticity).
phase: 7
lesson: 1
---

# XOR / OTP / Stream Cipher Audit Checklist

Use this checklist when you see any of the following in code or protocols:
- `^` on bytes, “XOR encryption”, “Vernam”, “OTP”, “one-time pad”
- AES-CTR, ChaCha20, Salsa20, “keystream”
- “Encrypt = XOR with mask”, “decrypt = XOR again”

## Quick triage (30 seconds)
1. **Is there authentication?** If not, the scheme is malleable. Prefer an AEAD.
2. **Can the keystream ever repeat?** If yes, you have a two-time pad class failure.
3. **Is the “key” actually random bytes?** Passwords, timestamps, counters, and `random` output are not OTP keys.

## Questions to ask (confidentiality)
- What is the exact construction?
  - OTP: `c = p XOR k`
  - Stream cipher: `c = p XOR stream(key, nonce, counter, ...)`
  - CTR mode: `c = p XOR AES(key, nonce||counter)`
- What is guaranteed to be unique per message?
  - OTP: the full key `k` must never repeat.
  - Stream cipher / CTR: the **(key, nonce)** pair must never repeat.
- Is the nonce generated randomly or sequentially?
  - Random is fine if collision probability is managed.
  - Sequential is fine if counters never reset and state is persisted.
- Is the nonce length large enough for the message volume?
- Are you truncating nonces or using only part of an IV?

## Questions to ask (integrity)
- If a bit flips in ciphertext, what happens after decryption?
  - If you can predictably change plaintext by changing ciphertext, you have no integrity.
- Is there an explicit MAC (HMAC) or an AEAD tag (Poly1305, GHASH)?
- Is tag verification done **before** plaintext is released/processed?

## Red flags (stop-ship)
- Reusing an OTP key for multiple messages (“two-time pad”).
- Reusing a stream cipher nonce with the same key (same keystream twice).
- AES-CTR or ChaCha20 used without authentication for attacker-controlled ciphertexts.
- “Homegrown” PRNG for keystream generation (anything not `secrets`/OS RNG / vetted crypto library).
- Fixed or hardcoded IV/nonce, or IV derived only from timestamp.
- Encrypt-then-compress with shared keystream across messages (compression does not fix reuse).

## What to do instead (production defaults)
- If you need **confidentiality + integrity**: use an AEAD (ChaCha20-Poly1305 or AES-GCM).
- If you must use CTR/stream cipher primitives: enforce nonce uniqueness per key and add authentication (Encrypt-then-MAC or AEAD).
- If you truly need OTP (rare): treat key material like bulk one-time secrets; plan for distribution, storage, and strict non-reuse.

## Two-time pad failure in one line (for reviewers)
If `c1 = p1 XOR k` and `c2 = p2 XOR k` with the same `k`, then:
`c1 XOR c2 = p1 XOR p2`

That is enough to recover messages with known-plaintext guesses and structure (file headers, JSON keys, English text).

