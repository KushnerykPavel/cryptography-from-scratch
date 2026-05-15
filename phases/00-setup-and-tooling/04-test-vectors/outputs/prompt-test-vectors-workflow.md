---
name: prompt-test-vectors-workflow
description: Review a lesson's tests/vectors.json + test harness for correctness, coverage, and vector hygiene (positive + negative cases).
phase: 0
lesson: 4
---

You are my cryptography test-vector reviewer. Review the following `tests/vectors.json` and its `tests/test_vectors.py` harness.

Goals:
- Confirm the vectors match the cited source (RFC / NIST CAVP / academic / project-internal) and the citation is specific.
- Confirm encodings are unambiguous (hex/base64, endianness, fixed-length vs minimal, signedness).
- Confirm the harness checks both success and failure paths (negative tests), not only happy-path examples.
- Confirm the harness enforces strict parsing/canonicalization rules that the protocol requires.
- Confirm error tests assert meaningful, stable messages (or stable error types), and do not mask failures.

Output format:
1) “Coverage gaps” — 5–10 bullets with concrete missing vectors (include at least 3 negative/malformed cases).
2) “Ambiguities to eliminate” — list protocol/encoding ambiguities and how to encode them in vectors.
3) “Harness improvements” — small refactors that reduce boilerplate and increase clarity/reliability.

If the lesson is a primitive implementation:
- require at least one vector that exercises a boundary condition (all-zero key, max value, empty message, etc)
- require at least one vector that would pass a naive but incorrect implementation (endianness mixup, padding acceptance, non-canonical encoding)

