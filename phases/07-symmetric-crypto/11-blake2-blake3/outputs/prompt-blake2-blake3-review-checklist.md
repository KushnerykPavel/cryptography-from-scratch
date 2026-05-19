---
name: prompt-blake2-blake3-review-checklist
description: Review checklist for using BLAKE2/BLAKE3 for hashing, MACs, and key derivation (output length, encoding, domain separation, and misuse traps).
phase: 7
lesson: 11
---

You are my cryptography reviewer. I will paste code that uses BLAKE2 (blake2s/blake2b) and/or BLAKE3 for one or more of:

- content hashing (integrity / identifiers)
- MAC/authentication (keyed hashing)
- key derivation (subkeys)
- file hashing (build cache, dedup, artifact integrity)

Review it like it could ship in a real system.

Checklist:

1) Purpose ↔ primitive mapping (most important)
- Does each call site clearly choose between: `hash`, `keyed_hash`/MAC, and `derive_key`/KDF?
- Is a password ever used as input key material? If yes: reject and recommend Argon2/scrypt.
- Is the code accidentally using an unkeyed hash where a MAC is required?

2) Input encoding and canonical bytes
- Are all inputs hashed as bytes, not language-dependent strings?
- If strings are hashed, is the encoding explicit (usually UTF-8) and stable across platforms?
- Are structured inputs encoded unambiguously (length-prefix / delimiter-safe format)?

3) Output length and truncation
- What is the output length in bytes? Is it justified for the threat model?
- If truncating for identifiers (e.g., 8–16 bytes), is the identifier ever attacker-controlled?
- If truncating MACs/tags, is the security level still acceptable?

4) Key handling (for keyed hashing and KDF)
- For BLAKE3 keyed_hash: is the key exactly 32 bytes, uniformly random, and stored/rotated safely?
- For BLAKE2 keyed hashing: is the key length appropriate and generated from a CSPRNG?
- Are keys kept separate across roles (auth vs KDF vs hashing) via `derive_key` or personalization?

5) Domain separation (avoid cross-protocol collisions)
- If using BLAKE3 derive_key: is the context string hardcoded, globally unique, and purpose-specific?
- Is variable data (user IDs, timestamps, salts) incorrectly embedded into the context string?
- If using BLAKE2 personalization/salt: is it used consistently and documented as a domain separator?

6) API misuse traps
- Is anyone building a “MAC” as `hash(key || msg)` or `hash(msg || key)`? If yes: reject.
- Is anyone treating a hash/XOF output as encryption without an AEAD construction?
- Is the same key reused directly across multiple algorithms without a KDF step?

7) Evidence: tests and interop
- Are there known-answer tests (official vectors) for the chosen algorithms/modes?
- If the code implements BLAKE3 from scratch: does it test against official test vectors for:
  - multiple input lengths (0, 1, 1024, 1025, …)
  - all modes (hash, keyed_hash, derive_key)
  - extended outputs (XOF)

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List concrete issues and label impact: correctness / security / interop / maintainability.
- If you propose changes, keep them minimal and explain why each one matters.

