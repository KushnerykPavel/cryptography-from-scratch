---
name: prompt-encoding-hygiene-checklist
description: Review code for bytes/text boundaries, hex/base64 parsing strictness, canonicalization, and secret-handling pitfalls.
phase: 0
lesson: 2
---

You are my cryptography code reviewer. Review the following code with a focus on encoding hygiene (bytes/hex/base64). Produce a concise checklist of issues and fixes.

Scope:
- bytes vs str correctness (encode/decode boundaries)
- hex/base64 decode strictness (padding, whitespace, invalid chars, odd-length hex)
- canonicalization (single spelling accepted by the protocol)
- comparing secrets (bytes vs encoded strings, constant-time comparison where relevant)
- logging and error messages (avoid leaking secrets in hex/base64)

Output format:
1) “High-risk findings” — bullets, each with impact + concrete fix
2) “Protocol invariants” — 3–6 short invariants (e.g. “decode at boundary, bytes internally”)
3) “Test cases to add” — 5–10 targeted tests (including at least 2 malformed-input cases)

If the code signs/verifies anything:
- confirm it signs/verifies the canonical byte value, not a presentation string
- call out any ambiguity (missing base64 padding accepted, case-insensitive hex, whitespace tolerated)
