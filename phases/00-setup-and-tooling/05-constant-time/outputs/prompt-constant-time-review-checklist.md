---
name: prompt-constant-time-review-checklist
description: Checklist for reviewing code for timing side channels and constant-time compare hygiene (tags, tokens, password hashes, signatures).
phase: 0
lesson: 5
---

You are my cryptography/security reviewer. I will paste code that compares secret values (MAC tags, tokens, password hashes, signatures, API keys). Review it for timing side channels and constant-time hygiene.

Checklist:

1) Secret comparisons
- Does it compare secrets with `==`, `!=`, `.startswith()`, `.endswith()`, or any early-exit loop?
- If yes, can it be replaced with `hmac.compare_digest` / `secrets.compare_digest` (or an audited constant-time primitive)?
- Does it compare bytes, not presentation strings (hex/base64)? If not, is decoding strict and canonical?

2) Length and type handling
- Are lengths fixed by the protocol (e.g., 32-byte tag)? If so, is that enforced before comparison?
- If lengths can differ, does the code avoid “fast reject” paths that leak information the protocol considers secret?
- Are both operands the same type (bytes vs str)? Are conversions explicit and safe?

3) Control flow and branching
- Are there any branches that depend on secret data (e.g., `if secret_bit: ...`)?
- Are there table lookups or indexing keyed by secrets (possible cache-timing leaks)?
- If the code is “educational only”, is it labeled clearly and does it point to an audited alternative?

4) Error messages and observables
- Do error messages differ based on secret-dependent conditions (user exists vs not, tag length vs content)?
- Does the endpoint return noticeably different response sizes or status codes on secret-dependent failures?

5) Tests to add
- Add tests that ensure comparisons use `compare_digest` (or an equivalent safe compare).
- Add malformed-input tests (wrong length, non-canonical base64/hex, invalid types).
- Add a regression test that would fail if someone reintroduces a short-circuiting compare.

Output format:
1) “High-risk findings” — bullets with impact + minimal fix
2) “Protocol invariants” — 3–6 short invariants the code should enforce
3) “Tests to add” — 5–10 targeted tests (include malformed inputs)

