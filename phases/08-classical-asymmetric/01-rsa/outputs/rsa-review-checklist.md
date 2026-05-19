---
name: RSA Review Checklist (Encryption + Signatures)
description: A practical checklist for reviewing RSA usage in codebases, designs, and incident triage.
phase: 08-classical-asymmetric
lesson: 01-rsa
---

# RSA Review Checklist (Encryption + Signatures)

Use this checklist when a PR, design doc, or incident mentions “RSA”.

## 1) What is RSA being used for?

Pick exactly one primary use:

- **Public-key encryption / key transport** (wrap a random symmetric key) → should be **RSA-OAEP**.
- **Digital signatures** (authenticity) → should be **RSA-PSS**.
- **Legacy interoperability** (smart cards, old HSM APIs, old TLS stacks) → expect exceptions; document them explicitly.

If someone proposes “RSA encrypt a message directly”, ask: “Why not hybrid encryption?” (RSA wraps a symmetric key; AES-GCM/ChaCha20-Poly1305 encrypt the bulk data.)

## 2) Red flags (stop-the-line)

These are almost always a bug or vulnerability:

- “Textbook RSA” / `c = m^e mod n` on raw bytes without a standard padding scheme.
- “RSA signature” implemented as `sig = m^d mod n` on raw messages (no hashing / no encoding).
- **PKCS#1 v1.5 encryption** in new designs (historically fragile; OAEP is the modern baseline).
- Custom padding, custom encodings, or “roll our own OAEP”.
- RSA used for bulk encryption (large payloads) instead of hybrid encryption.

## 3) Parameters & key sizes

- **Key size**: 2048-bit minimum in most modern deployments; 3072-bit for longer-term assurance.
- **Public exponent `e`**: typically `65537`. Avoid unusual small exponents unless there is a justified reason and the encoding is safe.
- **Prime generation**: must come from an OS CSPRNG and an audited implementation. No predictable seeds.
- **Distinct primes**: verify `p != q` (libraries enforce this, but audits still check for weird key material sources).

## 4) Padding / encoding choices (what “correct” looks like)

Encryption:

- **RSA-OAEP** with a modern hash (often SHA-256) and MGF1.
- Ensure labels/associated data are set intentionally (or explicitly empty), not ad hoc.

Signatures:

- **RSA-PSS** with a modern hash and an appropriate salt length.

If the code uses “RSA/ECB/PKCS1Padding” style naming (common in Java), treat that as a high-risk area and confirm what it means in that stack.

## 5) API boundary sanity checks

- Keys should be loaded/parsed using a standard format (PEM/DER) and a vetted library.
- Ciphertext and signature verification must be strict: reject malformed inputs, check return codes, don’t ignore exceptions.
- Constant-time behavior matters: never compare secrets with `==` in hot paths; use hardened library code.

## 6) Operational considerations

- **Key rotation**: document how keys are rotated and how old ciphertexts/signatures remain verifiable.
- **Certificate validation**: for TLS, review the full chain validation rules, not just “we have a cert”.
- **Threat model**: clarify whether the attacker can choose ciphertexts/signatures (CCA/CMA), because that determines padding requirements.

## 7) Quick “what to ask in review” prompts

- “Is this OAEP (encryption) or PSS (signatures)? Where is it configured?”
- “What key sizes are accepted and enforced?”
- “Is this hybrid encryption (RSA wraps a symmetric key)?”
- “What happens on malformed ciphertext/signature inputs? Is the failure path safe?”
- “Where do keys come from? Who generates them? Is randomness audited?”

