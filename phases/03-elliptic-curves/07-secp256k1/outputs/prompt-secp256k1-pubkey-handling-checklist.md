---
name: prompt-secp256k1-pubkey-handling-checklist
description: Checklist for implementing or reviewing secp256k1 public key derivation + parsing/serialization (compressed/uncompressed), including validation and side-channel warnings.
phase: 3
lesson: 7
---

You are my cryptography reviewer. I will paste a secp256k1 implementation (curve params, point add/double, scalar multiplication, public key derivation, and pubkey parsing/serialization). Review it like it could be used in a wallet, signer, or ECDH stack.

Checklist:

1) Domain parameters
- Does it use the correct secp256k1 parameters `(p, a=0, b=7, G, n, h=1)` (SEC 2)?
- Are constants represented unambiguously (hex/decimal) and reduced mod `p` where needed?
- Is the point at infinity represented consistently across the API?

2) Scalar + private key handling
- Are private keys restricted to `[1, n-1]`?
- Is any reduction mod `n` explicit (and is `0` rejected)?
- Are negative scalars handled (or rejected) consistently?

3) Point validation + parsing
- For uncompressed keys: does it reject invalid length/prefix, and reject points not on the curve?
- For compressed keys: does it compute `rhs = x^3 + 7 (mod p)` and correctly compute `sqrt(rhs)` and pick the root based on y parity?
- Does it reject inputs where `rhs` is not a quadratic residue (no square root)?
- Does it reject invalid encodings (wrong prefix, wrong length) without accidental acceptance?

4) Serialization
- Is uncompressed encoding `04 || x32 || y32`?
- Is compressed encoding `02/03 || x32` with prefix matching `y & 1`?
- Are x and y encoded as fixed 32-byte big-endian values?

5) Correctness
- Do point add/double formulas cover edge cases (identity, P + (−P), doubling when y=0)?
- Does it enforce “result is on curve” postconditions?
- Do tests include known-answer vectors for `k·G` and for parsing/serialization roundtrips?

6) Side-channel and production safety (call out explicitly)
- Is scalar multiplication constant-time? If not, is the code clearly labeled educational-only?
- Are there secret-dependent branches or table lookups?
- Does the library recommend an audited implementation for real usage (e.g., libsecp256k1 / OpenSSL / RustCrypto)?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List issues grouped by correctness vs security vs ergonomics.
- For fixes, propose minimal changes and explain why each matters.

