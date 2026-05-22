---
name: ECDSA Nonce Hygiene Checklist
description: A checklist to prevent key compromise from ECDSA nonce reuse, bias, or leakage.
phase: 19-cryptanalysis-and-side-channels
lesson: 08-hnp-on-ecdsa
---

# ECDSA Nonce Hygiene Checklist

Use this when reviewing any ECDSA/DSA signing code.

## 1) Nonce generation

- Never reuse k across signatures.
- Use deterministic nonces (RFC 6979) unless you have a vetted alternative.
- If using RNG:
  - ensure it is cryptographically secure
  - ensure per-device entropy is sufficient at boot

## 2) Side-channel considerations

- Treat k as secret key material.
- Avoid timing/cache/power leaks in:
  - scalar multiplication
  - modular inversion
  - conditional branches on secret bits

## 3) Operational signals of compromise

- Any nonce reuse or bias is a private key compromise event.
- If a device is physically exposed, assume k leakage is plausible unless hardened.

## 4) Safer alternatives

- Where possible, consider EdDSA implementations designed for constant-time behavior and deterministic nonce derivation (still requires correct implementation).

