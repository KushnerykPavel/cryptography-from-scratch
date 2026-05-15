---
name: prompt-x25519-review-checklist
description: Checklist for implementing or reviewing an X25519 (Curve25519) ladder, clamping, encoding, and all-zero handling.
phase: 3
lesson: 6
---

You are my cryptography reviewer. I will paste an implementation of X25519 (Curve25519) scalar multiplication, including:

- scalar clamping for 32-byte private keys
- u-coordinate decode/encode (little-endian)
- the Montgomery ladder using (X:Z) coordinates and `cswap`
- optional ECDH helpers (basepoint mult, shared secret derivation)

Review it like it could be used in a real protocol.

Checklist:

1) Encoding / decoding
- Does it treat inputs and outputs as 32-byte little-endian strings?
- Does it mask the most significant bit when decoding the u-coordinate (X25519 requirement)?
- Does it accept non-canonical u values by reducing mod p (rather than rejecting)?
- Does encoding always produce 32 bytes and ensure the top bit is zero?

2) Scalar handling (clamping)
- Does it implement clamping exactly: `k[0] &= 248`, `k[31] &= 127`, `k[31] |= 64`?
- Does it clamp the scalar bytes before converting to an integer?
- Does it avoid “helpful” changes that break interop (e.g., clamping the u-coordinate)?

3) Ladder correctness
- Does the loop process bits from MSB→LSB (RFC-style) with a conditional swap?
- Are the doubling and differential-addition formulas correct for Curve25519 and reduce mod p?
- Are projective updates performed without inversions inside the loop?
- Does it do the final conditional swap after the loop?

4) Constant-time goals (call out explicitly)
- Are there secret-dependent branches (scalar bits) or secret-dependent table lookups?
- If `cswap` is branchless in the target language, does it avoid leaking the swap bit?
- Does the code label itself educational-only if it is not constant-time end-to-end?

5) Protocol-level safety
- Does it perform (or document) the all-zero shared-secret check for small-order inputs?
- If it includes key exchange helpers, does it avoid reusing nonces/keys incorrectly?

6) Evidence (tests)
- Does it include RFC 7748 test vectors for:
  - the two X25519 scalar-multiplication vectors,
  - the Alice/Bob ECDH example,
  - at least one iteration-count vector?
- Does it test edge cases like all-zero inputs and non-canonical u values?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List concrete issues and their impact (correctness vs security vs interop).
- If you propose changes, keep them minimal and explain why each one matters.
