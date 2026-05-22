---
name: Constant-Time Review Checklist
description: A practical checklist for reviewing secret-dependent branches and comparisons in security-critical code.
phase: 19-cryptanalysis-and-side-channels
lesson: 03-timing-attacks
---

# Constant-Time Review Checklist

Use this in PR review whenever code handles secrets: MACs, tokens, signatures, password verifiers, key material, or decrypted plaintext.

## 1) Comparisons

- Never compare authentication data with `==` when timing matters.
- Prefer constant-time comparisons:
  - Python: `hmac.compare_digest(a, b)`
- Ensure both operands are bytes of the expected length before comparing.

## 2) Early exits / short-circuit logic

- Look for `return` / `break` / exceptions in loops that process secret-dependent data.
- Avoid “fail fast” behavior when it leaks where the mismatch occurred.

## 3) Parsing and verification order

- Do not perform detailed parsing of attacker-controlled data before authentication.
- Avoid returning different error messages per failure stage.

## 4) Timing test (sanity)

- Add a micro-benchmark that compares:
  - “first byte wrong” vs “last byte wrong”
  - “bad length” vs “bad MAC”
- If timings differ measurably, treat it as a potential leak.

## 5) Defense in depth (not a fix)

- Rate limiting, jitter, and retries can reduce signal quality, but don’t eliminate the root cause.

