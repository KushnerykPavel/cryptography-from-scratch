---
name: AEAD Review Checklist (GCM/CCM/OCB)
description: A PR-ready checklist for nonce discipline, tag handling, AAD coverage, and safe payload framing when using AEADs.
phase: 07-symmetric-crypto
lesson: 07-aead-gcm-ccm-ocb
---

# AEAD Review Checklist (GCM/CCM/OCB)

Use this checklist in PR reviews whenever you see:
- `GCM`, `CCM`, `OCB`, `ChaCha20-Poly1305`
- “encrypt then send”, “decrypt then parse”
- any API that returns/accepts `(nonce, ciphertext, tag)` (or a packed blob)

## Decision Guide (what to choose)

| If you need... | Prefer | Notes |
|---|---|---|
| Broad ecosystem compatibility (TLS/IPsec tooling) | AES-GCM | Fast with hardware; strict nonce discipline required |
| Constrained devices / simple building blocks | AES-CCM | Uses CBC-MAC + CTR; commonly deployed in IoT protocols |
| One-pass efficiency on software-only paths | OCB (RFC 7253) | Check your platform/library support and policy constraints |
| Better misuse resistance (nonce reuse) | AES-GCM-SIV / AES-SIV | Different security tradeoffs; not “drop-in GCM” |

## Nonce Discipline (most important)

- [ ] **Uniqueness**: Prove (in code + docs) that `nonce` is never reused for the same `key`.
- [ ] **Construction**: Nonce source is either:
  - a monotonic counter (per key), or
  - random 96-bit (only if your system can tolerate collision risk and you rotate keys with strict limits), or
  - a spec-defined construction (protocol-level sequence numbers).
- [ ] **Persistence**: If a counter is used, it is persisted across crashes/reboots and cannot roll back.
- [ ] **Scope**: The nonce uniqueness scope is clearly documented: per-message, per-record, per-session, per-file, etc.

## Tag Handling

- [ ] **Always verify** the tag on decryption and reject on failure.
- [ ] **Verify before use**: the plaintext is not parsed, deserialized, logged, or acted upon before authentication succeeds.
- [ ] **Constant-time compare**: tag comparison uses a constant-time primitive.
- [ ] **Tag length**: tag length is documented and justified (16 bytes default unless you have a strong reason).

## AAD Coverage (authenticating the context)

AAD should include anything that changes how the ciphertext is interpreted:

- [ ] Message type / schema version
- [ ] Record id / user id / tenant id
- [ ] Protocol version / algorithm identifiers
- [ ] Key id (KID) and rotation epoch
- [ ] Any routing headers that must not be mutable by an attacker

Rule of thumb: if changing a field would make you accept or process the plaintext differently, it belongs in AAD.

## Payload Framing

If you pack into a single blob, define the exact layout and lengths:

- [ ] Fixed lengths are explicit (`nonce_len`, `tag_len`) and validated.
- [ ] Include a 1-byte or 2-byte **version** field (preferably authenticated as AAD).
- [ ] Avoid ambiguous parsing (“nonce is whatever is left”).
- [ ] Do not reuse the same packed blob format for different algorithms unless the algorithm id is authenticated.

## Common Failure Patterns (red flags)

- [ ] Nonce generated with `rand()` or “timestamp only” or “counter without persistence”.
- [ ] Tag is ignored, optional, logged-and-continued, or verified after parsing.
- [ ] AAD is empty even though there is meaningful metadata or headers.
- [ ] Errors differ between “bad tag” vs “bad padding/parse” (oracle risks).
- [ ] Decryption returns plaintext and error separately (easy to misuse).

## Review Template (paste into PR)

```
AEAD checklist:
- Mode:
- Nonce construction + uniqueness proof:
- AAD fields:
- Tag length:
- Decrypt flow verifies tag before use:
- Payload framing (nonce|ct|tag) spec:
```

