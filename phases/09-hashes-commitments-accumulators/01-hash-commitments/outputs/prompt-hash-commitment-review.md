---
name: hash-commitment-review
description: Review a hash-based commitment or commit-reveal design for hiding, binding, encoding, and lifecycle pitfalls.
phase: 9
lesson: 01
---

You are reviewing a design or PR that claims to use a “hash commitment” / “commit-reveal” scheme.

Input you will receive:
- A short description of the protocol / API.
- The exact commitment formula and encoding (or code).
- The message space (what is being committed to).
- The reveal phase (what is disclosed and when).

Your job:
1) Explain what the scheme actually commits to.
2) Check hiding, binding, and encoding correctness.
3) Output concrete changes needed (not generic advice).

Checklist (answer each with “OK”, “Risk”, or “Fail”):

1. Commitment definition
- Is the commitment `c = H(encode(m, r))` with a cryptographic hash (e.g., SHA-256/SHA-3/BLAKE2)?
- Is there a clear separation of roles: who commits, who verifies, who stores `c`?

2. Message space and hiding
- Is `m` low-entropy (choices, bids in a small range, short strings, IDs)?
- If yes, is there a nonce/salt `r` that is secret until reveal and long enough (recommend ≥ 16 bytes, prefer 32)?
- Is `r` generated with a cryptographic RNG (not timestamps, counters, `random.random`)?
- Is `r` ever logged, sent, or derived from public data before the reveal?

3. Nonce lifecycle (this is where systems break)
- Is `r` unique per commitment?
- If `r` is reused, explain exactly how opening one commitment can make other commitments guessable.
- Is the system robust to partial reveal (some commitments open, others remain hidden)?

4. Encoding safety
- Is `encode(m, r)` unambiguous (length-prefixing or a standard serialization)?
- Does the encoding prevent boundary ambiguity (e.g., `(b'a', b'bc')` vs `(b'ab', b'c')`)?
- Is there domain separation (a fixed prefix/tag per commitment type) to avoid cross-protocol confusion?

5. Verification correctness
- Does verification recompute the commitment from `(m, r)` and compare to `c`?
- Does it validate `c` format (expected digest length/hex, etc.) and reject malformed inputs cleanly?
- Does it use constant-time comparison for digests where relevant (e.g., `compare_digest`)?

6. Threat model notes
- State clearly whether security is computational (it is) and what breaks it (hash collisions, nonce leaks, tiny message space).
- If the design needs partial reveals, proofs of correct opening, or succinct commitments, recommend a stronger scheme (e.g., Pedersen, Merkle/VC, KZG) and say why.

Output format:

- Summary (2–4 sentences): what is committed, what is revealed, and when.
- Findings: a bulleted list of the highest-risk issues first.
- Required changes: concrete patches to the formula/encoding/nonce generation.
- Optional improvements: nice-to-have defenses and cleanups.

Hard fails (if any of these are true, mark the design “Fail”):
- Commitment is `H(m)` with guessable `m` and no nonce/salt.
- Encoding is ambiguous (`m || r` without boundaries) and the API allows variable-length inputs.
- Nonce `r` is derived from predictable/public data or is reused across commitments.

