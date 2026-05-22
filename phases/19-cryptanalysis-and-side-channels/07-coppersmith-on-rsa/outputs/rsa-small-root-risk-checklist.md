---
name: RSA Small-Root Risk Checklist
description: A checklist for spotting “known structure + small unknown” RSA risks that can enable Coppersmith-style attacks.
phase: 19-cryptanalysis-and-side-channels
lesson: 07-coppersmith-on-rsa
---

# RSA Small-Root Risk Checklist

Use this when reviewing any RSA usage that encrypts or signs structured data.

## Red flags

- Plaintext looks like `known_prefix || short_id` or `timestamp || counter`.
- Small public exponent `e` (especially `e=3`) combined with structured plaintext.
- No standard padding (no OAEP/PSS/KEM; custom formatting).
- Repeated messages with small differences under the same modulus.

## Questions to ask

- Is the plaintext distribution close to uniform, or is it predictable?
- Is there a “small unknown” (few bytes) that an attacker can model as x?
- Can an attacker build a polynomial f(x) with a small root modulo N?

## Mitigations

- Use standardized, randomized padding/KEM for encryption (OAEP/KEM/hybrid).
- Use randomized signature padding (PSS) and avoid deterministic raw-RSA signatures.
- Avoid `e=3` unless you have a strong reason and a vetted implementation.

