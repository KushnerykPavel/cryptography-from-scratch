---
name: Hash vs MAC Misuse Checklist
description: A checklist to prevent length-extension and other “hash-as-MAC” mistakes.
phase: 19-cryptanalysis-and-side-channels
lesson: 09-length-extension
---

# Hash vs MAC Misuse Checklist

Use this when reviewing request signing, webhook verification, or token integrity schemes.

## Red flags

- `mac = Hash(key || msg)` (secret-prefix hashing)
- `mac = Hash(msg || key)` (suffix hashing; has different issues)
- Using raw SHA-256/MD5/MD4 digests as “authentication tags”
- “Custom HMAC” code that does not match the HMAC construction

## Preferred designs

- HMAC: `HMAC(key, msg)` for message authentication
- AEADs (when you need encryption + authentication)
- Standard protocol mechanisms (JWT with correct signature verification, etc.)

## Review questions

- Is the construction vulnerable to length extension (Merkle–Damgård hashes)?
- Are key lengths predictable/guessable?
- Are errors indistinguishable (don’t leak verification stage)?

