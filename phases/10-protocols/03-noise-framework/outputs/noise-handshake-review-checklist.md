---
name: noise-handshake-review-checklist
description: A practical checklist for reviewing Noise handshakes and Noise-like secure channel designs (pattern, authentication, transcript binding, key schedule, nonces).
version: 1.0.0
phase: 10
lesson: 03
tags: [noise, handshake, protocol, audit, wireguard, hkdf, aead]
---

Use this as a PR review template or paste it into an LLM to drive a structured audit of any Noise handshake (or “Noise-inspired” handshake).

If the design is not explicitly using an audited Noise implementation, treat it as high-risk.

## 1) Identify the handshake

- Pattern: `NN / NK / IK / XX / ...` (write it down explicitly)
- Primitives: DH (`25519` / `448` / ...), HASH (`SHA256` / `BLAKE2s` / ...), AEAD (`ChaCha20-Poly1305` / `AES-GCM` / ...)
- Prologue: is there a prologue? what bytes exactly?
- Payloads: what gets encrypted during handshake (certs, identities, tokens)?

## 2) Authentication and identity binding

- What entity is authenticated (server only, both, neither)?
- Where does the authenticated identity come from (pinned static key, certificate chain, TOFU, QR code, OOB channel)?
- Is authentication *cryptographically bound* to the handshake transcript (not just “checked later”)?
- Does the protocol have explicit key confirmation (each side is sure the peer derived the same keys)?

Red flag: using `NN` in any setting that needs to resist MitM.

## 3) Transcript binding

- Is every byte that goes on the wire included in the transcript hash (`mix_hash`) in the correct order?
- If handshake payloads are encrypted, is the ciphertext (including tag) hashed into the transcript?
- Are negotiable parameters (versions, cipher suite, pattern selection, PSK id) committed into the transcript?

Red flag: any “negotiation” that isn’t transcript-bound (downgrade risk).

## 4) Key schedule and domain separation

- Is the raw DH result fed through a KDF (Noise uses HKDF)?
- Are keys split into per-direction transport keys (`initiator_tx`, `initiator_rx`, ...), not reused bidirectionally?
- Are handshake keys distinct from transport keys (no “just keep using the same AEAD key”)?
- If PSKs are used, are they mixed in via the Noise functions (PSK tokens / mix_key / mix_hash), with a clear PSK identity story?

Red flag: reusing the same key for both directions or both handshake+transport.

## 5) Nonce and rekey rules (transport mode)

- Nonce strategy: counter-based? random? (Noise transport is typically counter-based)
- Are nonces monotonically increasing per key and per direction?
- What happens on reconnect, resume, or app restart — can a nonce counter reset under the same key?
- Rekey: is there a periodic rekey and does it reset nonces safely?

Red flag: any possibility of nonce reuse under the same AEAD key.

## 6) Message encoding and validation

- Are DH public keys validated on decode (length, range, subgroup if required)?
- Are message lengths bounded? (avoid DoS via huge payloads)
- Is parsing strict (no trailing garbage, no ambiguous encodings)?
- Are errors handled safely (no “decrypt then continue on failure”)?

## 7) Security properties (write the claims)

For each property, write “yes/no” and where it comes from:

- Confidentiality against passive attackers
- Resistance to active MitM
- Forward secrecy (and from which point)
- Post-compromise security (if using a ratchet)
- Identity hiding (if relevant)

## 8) Interop and test evidence

- Are there official test vectors (Noise, library vectors, or cross-impl tests)?
- Is there a transcript-level test that checks both sides compute the same handshake hash and split keys?
- Do tests include negative cases (tag mismatch, truncated messages, wrong key, replayed message)?

## 9) Operational concerns

- Logging: does it avoid secrets and avoid leaking identity before authentication completes?
- Timeouts / retries: could retries cause nonce reuse or state desync?
- Side channels: constant-time primitives are from audited libs (not handwritten)?

## Paste-into-LLM prompt (optional)

“Review this handshake implementation as a Noise handshake. Identify the pattern and primitives, then walk through transcript binding, authentication, key schedule, nonce discipline, decoding validation, and error handling. List concrete vulnerabilities and suggest minimal fixes. If the protocol is unauthenticated but used in an authenticated setting, call that out explicitly.”

