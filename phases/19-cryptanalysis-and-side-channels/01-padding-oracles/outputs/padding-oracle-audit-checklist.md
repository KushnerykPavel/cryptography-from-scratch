---
name: Padding Oracle Audit Checklist
description: A copy-pastable checklist for reviewing CBC/PKCS#7 decryption endpoints for padding-oracle risk.
phase: 19-cryptanalysis-and-side-channels
lesson: 01-padding-oracles
---

# Padding Oracle Audit Checklist (CBC + PKCS#7)

Use this in PR review, threat modeling, or incident response when you see any legacy CBC decryption path.

## 1) Threat model (what the attacker can do)

- Can an attacker send chosen ciphertexts to a decryption endpoint (API, cookie parser, webhook verifier, file import)?
- Can they observe *any* signal correlated with “padding valid vs invalid”?
  - status code, error text, response length, different redirect path, different logging, different timing
- Can they repeat queries many times (rate limits, retries, distributed clients)?

## 2) Red flags in code

- `decrypt(...)` happens before authentication / integrity verification.
- Padding is checked first, then MAC is checked (or parsing is attempted).
- Different exception types/messages leak to the client.
- Different HTTP codes for padding failure vs “bad MAC” vs “bad JSON”.
- Early returns on padding failure that change runtime noticeably.

## 3) Required properties for a safe legacy CBC path

- Encrypt-then-authenticate: verify MAC/AEAD tag *before* attempting to decrypt or unpad.
- All failures are indistinguishable externally:
  - same HTTP status, same content type, same response length
  - similar timing profile (no obvious “fast fail” for padding)
- Decryption happens only after the integrity check passes.

## 4) Preferred fixes (in order)

- Replace CBC + PKCS#7 with an AEAD:
  - AES-GCM or ChaCha20-Poly1305
- If protocol forces CBC:
  - add a strong, separate MAC (HMAC-SHA256) over `IV || ciphertext`
  - verify MAC first, then decrypt
- Remove detailed error messages from decryption endpoints.

## 5) Verification steps

- Write a unit/integration test that:
  - sends a valid ciphertext and a tampered ciphertext
  - asserts responses are identical in status and length
- Run a differential timing check:
  - measure average response time for “bad padding” vs “bad MAC” vs “bad parse”
  - look for statistically significant differences

