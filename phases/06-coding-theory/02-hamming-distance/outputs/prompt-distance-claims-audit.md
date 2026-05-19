---
name: prompt-distance-claims-audit
description: Checklist + prompt for auditing distance-based ECC claims (Hamming distance, d_min, detect/correct guarantees, nearest-neighbor decoding)
phase: 6
lesson: 2
---

You are reviewing a spec or implementation that makes **distance-based claims** about an error-detecting/correcting code (ECC).

Your job is to prevent silent math bugs and unsafe “correction” behavior.

Ask the author for:
- The exact **alphabet and notion of distance**: bit-level vs byte-level vs symbol-level
- The code model: “a finite codebook” vs “a linear code described by G/H”
- The set of valid codewords (explicitly, or a way to generate them)
- The claimed minimum distance `d_min` (and how it was computed/verified)
- The decoder policy: correct, detect-only (reject), or “decode-or-reject”
- Deterministic test vectors and how they were generated

Then audit in this order.

## 1) Distance definition (hard fail if ambiguous)

Verify the implementation matches the written definition:
- Hamming distance requires **equal length** and counts **aligned positions that differ**
- If the objects are bytes, confirm whether “distance” means:
  - byte-level (count differing bytes), or
  - bit-level (XOR each byte and popcount bits)
- If “normalized distance” is used, confirm the unit (e.g., “bits per byte”) and ensure it’s not mixed with other units elsewhere.

## 2) Minimum distance `d_min` (the load-bearing number)

Confirm `d_min` is defined and computed correctly:
- `d_min(C) = min_{c1 != c2 in C} d(c1,c2)`
- Ensure the author did not accidentally compute:
  - min distance to the all-zero word only, or
  - average distance, or
  - min distance between *messages* instead of *codewords*

If the code is linear, verify they didn’t confuse:
- minimum distance of the code vs minimum weight of a specific generator row.

## 3) Claims derived from `d_min` (don’t let them overpromise)

Require every claim to be derived explicitly:
- “Detects up to t errors” must satisfy `t <= d_min - 1`
- “Uniquely corrects up to t errors” must satisfy `t <= floor((d_min - 1) / 2)`

If the author claims correction beyond this bound, demand a code-family-specific argument (e.g., RS/BCH decoding radius) and the exact decoder used.

## 4) Decoder ambiguity and safety policy (the failure mode)

Nearest-neighbor style decoding is unsafe unless it handles ambiguity:
- If there is a tie for closest codeword, the decoder must **refuse** (or return “ambiguous”), not silently pick one.
- If the system is adversarial, prefer “decode-or-reject” and treat silent miscorrection as a security bug.

Ask: “What happens on 2-bit errors?” If the answer is “we still correct”, treat it as suspicious unless proven.

## 5) Test plan (minimum bar)

Require:
- Deterministic vectors for distance on representative inputs (including edge cases)
- Vectors for `d_min` on a small codebook (hand-checkable)
- Exhaustive checks for tiny codes (if feasible): enumerate all codewords and verify computed `d_min`
- Decoder tests:
  - within the correction radius: decodes correctly
  - tie cases: rejects (does not guess)
  - wrong lengths / non-binary inputs: rejected clearly

## Output format

Produce:
- A bullet list of **incorrect or unproven claims** (quote the exact claim text and the parameter values)
- A bullet list of **missing invariants/tests**
- A “go / no-go” recommendation for:
  - toy demo (often OK)
  - production comms/storage (usually “use a vetted library/standard”)
  - adversarial context (assume “no” unless ambiguity and miscorrection are addressed)

