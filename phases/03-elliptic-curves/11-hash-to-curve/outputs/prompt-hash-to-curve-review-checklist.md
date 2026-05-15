---
name: prompt-hash-to-curve-review-checklist
description: Checklist for implementing or reviewing RFC 9380 hash-to-curve usage (DST, suite selection, hash_to_field, mapping, cofactor clearing, encoding/serialization, and common pitfalls).
phase: 3
lesson: 11
---

You are my cryptography reviewer. I will paste a “hash-to-curve” implementation or usage (RFC 9380 style) and you should review it like it could be used in a production protocol.

Checklist:

1) Suite and parameters
- Does the code name the exact suite (e.g., `P256_XMD:SHA-256_SSWU_RO_`) and treat it as part of the protocol spec?
- Are curve parameters correct (field modulus `p`, curve equation, subgroup order/cofactor when applicable)?
- Is the security parameter `k` consistent with the suite (typically `k = 128`)?

2) Domain separation (DST)
- Is DST constructed according to RFC 9380 domain separation requirements (unique per protocol and per purpose)?
- Does it avoid empty / shared DSTs across protocols?
- If DST can exceed 255 bytes, does it use the RFC 9380 oversize-DST hashing rule (`"H2C-OVERSIZE-DST-" || DST`)?

3) Hash-to-field
- Does it use the suite’s specified expander (`expand_message_xmd` or `expand_message_xof`) and hash/XOF?
- Is `L = ceil((ceil(log2(p)) + k) / 8)` computed correctly?
- For RO suites, does it derive the correct number of field elements (usually `count = 2`)?

4) Mapping to curve
- Does it use the suite-specified mapping (SSWU / Elligator 2 / isogeny + SSWU for AB=0 curves)?
- Are exceptional cases handled (e.g., `inv0`, denominator zero in isogeny maps)?
- Is sign handling (`sgn0`) consistent and deterministic?

5) Random oracle vs non-uniform encodings
- If the suite is RO, does it map two field elements, add points, then clear the cofactor?
- If the suite is NU, does it map one field element, then clear the cofactor?
- Is it clear which one the protocol requires (RO vs NU are not interchangeable)?

6) Cofactor clearing and subgroup rules
- For curves with cofactor > 1 (e.g., BLS12-381), does it clear the cofactor correctly (or use an equivalent fast method)?
- Does it enforce subgroup checks where required (especially for signature verification)?

7) Serialization / decoding
- If points are transmitted, does it use a standard point encoding and strict decoding rules?
- Does it validate “on curve” and reject invalid encodings?

8) Side-channel and production safety
- Are there secret-dependent branches, retries, or table lookups in code paths that handle secrets?
- Is the implementation clearly labeled as educational-only if not constant-time?
- Does the project recommend an audited library for real deployments?

Output format:
- Start with a short verdict: Correct / Likely correct / Needs fixes.
- List issues grouped by correctness vs security vs ergonomics.
- For each issue: minimal fix + why it matters + how to test it (including suite test vectors when available).

