---
name: prompt-p256-pubkey-handling-and-trust-checklist
description: Checklist for implementing or reviewing NIST P-256 (secp256r1 / prime256v1) public key derivation + parsing/serialization, including validation, naming, and trust footguns.
phase: 3
lesson: 8
---

You are my cryptography reviewer. I will paste a P-256 implementation (curve params, point add/double, scalar multiplication, public key derivation, and pubkey parsing/serialization). Review it like it could be used in a TLS stack, JWT signer, WebAuthn implementation, or ECDH service.

Checklist:

1) Domain parameters (P-256 vs secp256k1 mixups)
- Does it use the correct P-256 parameters `(p, a=-3 mod p, b, G, n, h=1)` (NIST FIPS 186 / SEC 2)?
- Is `a` represented as `p-3` (or otherwise reduced mod `p`) rather than the negative integer `-3` leaking into code paths?
- Does it clearly distinguish names: `P-256` = `secp256r1` = `prime256v1`?

2) Scalar + private key handling
- Are private keys restricted to `[1, n-1]`?
- Is any reduction mod `n` explicit (and is `0` rejected)?
- Are negative scalars handled (or rejected) consistently?

3) Point validation + parsing
- For uncompressed keys: does it validate prefix/length, decode `x` and `y` as 32-byte big-endian, and reject values not in `[0, p-1]`?
- Does it reject points not on the curve (`y^2 == x^3 + a·x + b (mod p)`)?
- For compressed keys: does it compute `rhs = x^3 + a·x + b (mod p)` and correctly compute `sqrt(rhs) (mod p)` and pick the root based on y parity?
- Does it reject inputs where `rhs` is not a quadratic residue (no square root)?
- Does it avoid accepting “point at infinity” encodings (if any)?

4) Serialization
- Is uncompressed encoding `04 || x32 || y32`?
- Is compressed encoding `02/03 || x32` with prefix matching `y & 1`?
- Are x and y encoded as fixed 32-byte big-endian values (no variable-length encodings)?

5) Correctness
- Do point add/double formulas cover edge cases (identity, P + (−P), doubling when y=0)?
- Does it enforce “result is on curve” postconditions?
- Do tests include known-answer vectors for `k·G` and for parsing/serialization roundtrips?

6) Security + trust (call out explicitly)
- Is scalar multiplication constant-time? If not, is the code clearly labeled educational-only?
- Does the implementation validate peer public keys before any secret scalar multiplication (ECDH)?
- Does any documentation avoid implying P-256 implementations here are production-safe?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List issues grouped by correctness vs security vs ergonomics.
- For fixes, propose minimal changes and explain why each matters.

