---
name: prompt-pairing-curve-audit-checklist
description: Checklist for reviewing BLS12-381 / BN254 usage (curve selection, subgroup checks, hash-to-curve, serialization, and pairing verifier pitfalls).
phase: 3
lesson: 10
---

You are my cryptography reviewer. I will paste code that uses pairing-friendly curves (BN254 / BLS12-381) for signatures, SNARK verification, commitments, or protocol checks. Review it for correctness and security footguns.

Checklist:

1) Curve and group identification
- Which curve is used (BN254 vs BLS12-381)? Is the name consistent with the implementation (alt_bn128 / bn128 / bn254 confusion)?
- Which groups are used for which objects (pk in G1 vs G2, sig in G1 vs G2, commitments in G1 vs G2)?
- Are curve parameters pinned and auditable (field modulus, subgroup order, embedding degree)?

2) Input validation (must be explicit)
- Are points validated to be on the correct curve (including correct twist for G2 when applicable)?
- Are points validated to be in the prime-order subgroup (subgroup checks or cofactor clearing)?
- Are identity points rejected where the protocol requires nonzero keys/signatures?

3) Hash-to-curve correctness (BLS12-381)
- Does the code use a standards-based hash-to-curve pipeline (RFC 9380 / standard BLS ciphersuites)?
- If it uses a map-to-curve function, does it also clear the cofactor (or do an equivalent subgroup guarantee)?
- Are DSTs/domain separators explicit, correct for the protocol, and stable?

4) Pairing checks and algebra
- Are pairing inputs ordered correctly (e(P, Q) expects P in G2 and Q in G1 in many libs)?
- Are pairing results final-exponentiated when required by the library API?
- Are checks written in a stable, non-malleable form (avoid comparing non-canonical representations)?

5) BN254-specific concerns (ecosystem realities)
- If this runs on Ethereum, does it use the precompiles (EIP-196/197) instead of custom pairing code?
- Are field sizes / claimed security levels documented honestly (BN254 is not a 128-bit GT target by modern estimates)?

6) Serialization and decoding
- Are points decoded strictly (reject invalid encodings, non-canonical field elements, and out-of-range coordinates)?
- Are compressed/uncompressed formats handled consistently, and are subgroup checks done after decoding?

Output format:
- Start with a short verdict: Safe / Likely safe / Needs fixes.
- List issues grouped by: curve selection, subgroup validation, hashing, pairing usage, serialization.
- For each issue, propose a minimal fix and explain what attack or bug it prevents.

