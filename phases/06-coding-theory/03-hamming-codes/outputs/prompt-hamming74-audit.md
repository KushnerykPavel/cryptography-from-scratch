---
name: prompt-hamming74-audit
description: Audit checklist + prompt for reviewing a Hamming(7,4) implementation (bit layout, syndrome, correction safety)
phase: 6
lesson: 3
---

You are reviewing a **Hamming(7,4)** encoder/decoder implementation. Your job is to catch silent correctness bugs and prevent unsafe “correction” behavior.

Ask the developer to state these **conventions up front** (hard fail if unclear):
- Codeword bit layout and indexing: which positions are parity vs data, and whether positions are 1-indexed (paper) or 0-indexed (arrays)
- Parity convention: **even** vs **odd**
- Syndrome bit order: is syndrome interpreted as `[1,2,4]` (LSB-first), `[4,2,1]`, or something else?
- What the decoder promises: detection-only, single-error correction (SEC), or SECDED (single-error correct / double-error detect)

Then audit in this order.

## 1) Layout & parity coverage (correctness)

If they claim classic Hamming(7,4) with parity at powers of two:
- Parity bits at positions `1,2,4`
- Data bits at positions `3,5,6,7`
- A typical layout is `[p1, p2, d1, p4, d2, d3, d4]` (positions 1..7)

Confirm their parity equations match the layout. For even parity, each parity check must XOR to 0.

## 2) Syndrome correctness (the “address” invariant)

The crucial invariant:
- For a valid codeword `c`, `syndrome(c) == 000`.
- For a single-bit error at position `i`, `syndrome(c with bit i flipped)` must equal the 3-bit binary representation of `i` (under the stated syndrome bit order).

Require an explicit test that checks **all 7** bit positions.

## 3) Correction behavior (safety)

SEC decoding typically does:
- compute `s = syndrome(r)`
- if `s != 0`, flip bit at index `pos = syndrome_to_position(s)`

Important safety note:
- Plain Hamming(7,4) **cannot reliably tell** “one bit flipped” from “two bits flipped”.
- If you apply SEC correction to a two-bit error, you can **miscorrect** into a different valid codeword and silently decode the wrong message.

If the system needs “correct 1, detect 2”, require **SECDED** (extended Hamming with an overall parity bit), and require tests for double-bit errors that assert “detected, not corrected”.

## 4) Minimum test plan (non-negotiable)

Require:
- Deterministic vectors for at least one known message → codeword and one known single-bit flip → syndrome
- Exhaustive roundtrip over all `2^4 = 16` messages
- Exhaustive single-bit flips: for each message and each of 7 positions:
  - flip bit
  - decode
  - assert original message recovered and the reported corrected position matches the flipped position
- Input validation tests:
  - wrong lengths rejected
  - non-binary bits rejected

## Output format

Produce:
- A bullet list of correctness risks (naming exact functions/modules)
- A bullet list of missing tests and the simplest way to add them
- A go/no-go recommendation for:
  - demo / educational use
  - production reliability (memory/storage/telemetry)
  - adversarial setting (assume “no” unless SECDED + authenticated framing exists)

