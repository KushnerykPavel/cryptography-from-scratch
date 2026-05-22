---
name: RSA PKCS#1 v1.5 Oracle Checklist
description: A checklist for spotting Bleichenbacher-style padding-oracle risks in RSA decryption and key-transport code.
phase: 19-cryptanalysis-and-side-channels
lesson: 02-bleichenbacher
---

# RSA PKCS#1 v1.5 Padding-Oracle Checklist

Use this when you see any RSA decryption path that parses PKCS#1 v1.5 “block type 2” formatting.

## 1) Where the oracle comes from

- Does the decrypt path distinguish:
  - “bad padding/format” vs “bad key” vs “bad message”?
- Can the attacker observe differences via:
  - status code, error message, redirect location
  - response length, retry behavior
  - timing (early return during parse)
- Can the attacker submit many chosen ciphertexts (even if rate-limited)?

## 2) Code review red flags

- Any branch on PKCS#1 formatting that affects control flow or timing.
- Exceptions that bubble up with different messages/types.
- Logging that includes parse-stage details.
- Returning decrypted data (even partially) before authenticity checks.

## 3) Preferred mitigations

- Avoid RSAES-PKCS1-v1_5 for new systems.
- Prefer a modern KEM / hybrid key exchange with vetted implementations.
- If legacy support is mandatory:
  - uniform, constant-time-ish rejection handling
  - do not reveal whether formatting checks passed
  - follow standards guidance (e.g., implicit rejection patterns)

## 4) “Test like an attacker”

- Build an integration test that:
  - submits many mutated ciphertexts
  - confirms responses are indistinguishable in status and length
- Run a timing comparison:
  - compare rejection timings across different malformed ciphertext classes
  - look for statistically significant separation

