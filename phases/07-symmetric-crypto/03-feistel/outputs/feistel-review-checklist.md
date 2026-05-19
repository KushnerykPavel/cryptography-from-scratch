---
name: Feistel / Custom Block Transform Review Checklist
description: A practical checklist for reviewing Feistel-like “custom ciphers” and block transforms in production code.
phase: 07-symmetric-crypto
lesson: 03-feistel
---

# Feistel / Custom Block Transform Review Checklist

Use this when reviewing PRs that introduce a “custom cipher”, proprietary block transform, or Feistel-like construction.

## 0) Default decision
- If this is for production confidentiality: prefer a standard **AEAD** (AES-GCM, ChaCha20-Poly1305) from a vetted library.
- If this is for “obfuscation”: treat it as obfuscation, not cryptography, and document that explicitly.

## 1) What is the exact security goal?
- What is the threat model (passive eavesdropper, active attacker, chosen-plaintext, chosen-ciphertext)?
- Is integrity/authenticity required, or only confidentiality?
- Is this encrypting structured data where malleability is dangerous?

## 2) Construction sanity (Feistel basics)
- Block is split into equal halves; round wiring is exactly:
  - `L_{i+1} = R_i`
  - `R_{i+1} = L_i XOR F(K_i, R_i)`
- Decryption is implemented by applying round keys in reverse.
- `F` output is exactly half-block sized (no truncation bugs, no sign/endianness bugs).

## 3) Round function `F`
- Is `F` a PRF-like keyed function (non-linear, key-dependent, unpredictable)?
- Is `F` deterministic for a given `(K_i, R_i)`?
- Are there accidental linearities (e.g., `F(x)=x`, `F(x)=x XOR const`, small lookup tables)?

## 4) Number of rounds and diffusion
- How many rounds, and why that number?
- Is there an avalanche/diffusion test that flips one input bit and measures output bit flips?
- Are there known analyses for the chosen parameters (round count, block size, key schedule)?

## 5) Key schedule
- Are per-round keys derived from the master key with domain separation (round index included)?
- Are there repeated round keys, or related keys across different contexts (files/users/tenants)?
- Are keys rotated, versioned, and stored/handled safely?

## 6) Block size and modes
- What is the block size? (Small blocks leak patterns quickly.)
- If encrypting messages longer than one block: what mode is used (CTR/CBC/etc)?
- Are nonces/IVs unique where required (CTR, GCM, etc)?
- If using a mode: why not use an AEAD directly?

## 7) Side channels and implementation hazards
- Any data-dependent branches, table lookups, or variable-time operations on secrets?
- Is the code constant-time? If not, is it used in a setting where timing matters?
- Are there test vectors and cross-language compatibility tests?

## 8) “Red flags” that should block shipping
- “We invented this because AES is slow/complex.”
- No test vectors, no clear threat model, no formal review.
- Nonce/IV handling is unclear, randomized without collision planning, or reused.
- The cipher is homegrown but used as if it provided integrity (it doesn’t).

## 9) Suggested PR comment template
Paste this into a review to steer the discussion:

> This introduces a custom block transform. Can we use a standard AEAD (AES-GCM or ChaCha20-Poly1305) from a vetted library instead? If not, please document the security goal/threat model, add deterministic test vectors, specify block size + mode/nonce rules, and justify the round function + key schedule + round count with references.

