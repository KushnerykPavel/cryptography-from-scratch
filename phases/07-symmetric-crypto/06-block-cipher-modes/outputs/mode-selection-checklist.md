---
name: "Block Cipher Mode Selection & Review Checklist"
description: "A paste-ready checklist for choosing ECB/CBC/CTR/CFB vs AEAD, and for reviewing nonce/IV/padding/integrity handling in PRs."
phase: "07-symmetric-crypto"
lesson: "06-block-cipher-modes"
---

# Block Cipher Mode Selection & Review Checklist

Use this as a decision guide + PR review checklist whenever you see “AES-*” or “mode of operation” in code or design docs.

## 1) Decision rule (pick the safe default)

- If you need **confidentiality + integrity** (almost always): use **AEAD** (AES-GCM, ChaCha20-Poly1305).
- If you only need **confidentiality** and integrity is provided elsewhere (rare, must be explicit): CBC/CTR/CFB can be acceptable with strict nonce/IV rules.
- If anyone proposes **ECB**: stop. ECB leaks structure and is almost never acceptable.

## 2) Questions to ask (design review)

- What is the attacker model? Passive observer only, or active network attacker?
- Where does the key come from, and how is it rotated (KMS, envelope encryption, versioned key IDs)?
- What exactly is encrypted (records, files, protocol messages)? What metadata remains plaintext?
- How are nonce/IV values generated, stored, and transmitted? Are they unique under a key?
- Where does integrity come from? (AEAD tag, MAC, signed envelope, authenticated transport)

## 3) Nonce/IV checklist (implementation review)

### CBC / CFB (IV)
- IV length matches block size (AES: 16 bytes).
- IV is **unique per message** under a key.
- IV is **unpredictable** unless you can prove you only need uniqueness.
- IV is transmitted/stored alongside ciphertext (IV is not a secret).
- Code does not reuse a constant IV (`iv = b\"\\x00\"*16`) or a predictable IV (`iv = timestamp`).

### CTR (nonce + counter)
- Nonce length matches the library API (commonly 12 or 16 bytes; or nonce+counter split).
- Nonce+counter sequence is **never reused under the same key**.
- Counter construction is unambiguous (endian, width) and cannot wrap within a message.
- Multi-process / multi-host uniqueness is addressed (random nonces, or a robust allocation scheme).

## 4) Padding checklist (CBC/ECB)

- PKCS#7 padding is used correctly (always add padding; validate bytes on unpad).
- Decryption failures do not leak padding validity via:
  - different error messages
  - different HTTP status codes
  - measurable timing differences
- If your system is remotely reachable, assume a padding oracle will be found unless AEAD is used.

## 5) Integrity checklist (the most missed part)

- If the mode is CBC/CTR/CFB/ECB:
  - Where is the MAC or signature?
  - Is it **encrypt-then-MAC** (preferred) rather than MAC-then-encrypt?
  - Is the tag verified **before** plaintext is parsed/used?
- If the mode is AEAD:
  - Is the tag verified on every decrypt?
  - Is the nonce unique?
  - Is associated data (AAD) used for headers/metadata that must be authenticated?

## 6) Red flags (block PRs on these)

- “AES-CBC” or “AES-CTR” with no mention of authentication/tag/MAC.
- Any constant or predictable IV/nonce.
- Reusing a nonce by “deriving it from user ID” or “hashing a timestamp”.
- Homegrown “checksum” or “CRC” used as integrity for ciphertext.
- Any branching on padding validity in an API response.
- Logging plaintext or keys “temporarily for debugging”.

## 7) Safe phrasing for tickets/design docs

Copy/paste:

- “Use AEAD (AES-GCM or ChaCha20-Poly1305). Nonce is random 96-bit per message. Store nonce + ciphertext + tag. Reject on tag failure.”
- “Keys are versioned. Ciphertext envelope includes `key_id`, `nonce`, `ciphertext`, `tag`.”
- “All decrypts authenticate before parsing. Decryption failures are indistinguishable to callers.”

## 8) If you must use a non-AEAD mode (rare)

Write these invariants into the doc/tests:

- “Nonce/IV uniqueness under a key is enforced by construction.”
- “Integrity is provided by <mechanism>, verified before use.”
- “Ciphertext is never decrypted unless the integrity check passes.”

