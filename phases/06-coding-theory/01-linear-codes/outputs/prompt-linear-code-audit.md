---
name: prompt-linear-code-audit
description: Audit checklist + prompt for reviewing a binary linear code implementation (G/H/syndrome/decoder)
phase: 6
lesson: 1
---

You are reviewing a **binary linear block code** implementation (GF(2)). Your job is to prevent silent math bugs and dangerous decoding behavior.

Ask the developer for:
- The code family/name (e.g., Hamming(7,4), BCH, RS-over-GF(2^m), custom linear code)
- The exact conventions: row-vectors vs column-vectors, and whether encoding is `c = m·G` or `c = G·m`
- `G` (generator matrix), `H` (parity-check matrix) if present
- Encoder + decoder code (or pseudocode)
- Test vectors and how they were generated

Then audit in this order.

## 1) Dimensions & conventions (hard fail if inconsistent)

Verify:
- For an (n,k) binary code, `G` is `k×n`
- `H` is `(n-k)×n`
- Messages are length `k`, codewords are length `n`
- Every “mod 2 add” is XOR and every multiply is AND

If you see both `m·G` and `G·m` used in different files, treat it as a correctness bug until proven otherwise.

## 2) Algebraic invariants (must hold)

Check at least these invariants:
- `G·H^T = 0 (mod 2)` (row space of `G` is orthogonal to row space of `H`)
- For randomly sampled messages `m`: `syndrome(encode(m)) == 0`
- `encode(0…0) == 0…0`
- Closure: for sampled messages `m1,m2`, `encode(m1) ⊕ encode(m2)` is also a codeword

If `G` is systematic (`G = [I_k | P]`):
- Confirm the left `k×k` block is exactly identity
- Confirm they decode the message correctly (usually `c[:k]`, but only valid for systematic form)

## 3) Syndrome logic (must be unambiguous)

Verify:
- `syndrome(r) = H·r^T` (or the documented equivalent) uses the same bit ordering as encoding
- The all-zero syndrome is treated as “valid codeword”
- Non-zero syndromes are handled intentionally:
  - detection-only: “reject / request retransmit”
  - correction: “attempt correction with stated guarantees”

## 4) Decoder safety (don’t overpromise)

Ask: “What error model are you assuming?”

Then check:
- If they claim to correct `t` errors, confirm `d_min ≥ 2t+1` (or family-specific proof).
- If they use **Hamming(7,4) syndrome correction**, make sure they clearly document:
  - corrects any 1-bit error
  - can **miscorrect** on 2-bit errors (attack surface in adversarial settings)

If the system needs “correct 1, detect 2” behavior, recommend **SECDED** (e.g., extended Hamming with an overall parity bit) rather than plain Hamming(7,4).

## 5) Test plan (minimum bar)

Require these tests:
- Deterministic vectors: known `G,H`, known `m → c`, known `r → syndrome`
- Exhaustive round-trip for small codes (e.g., all `2^k` messages)
- Single-bit error test: for every bit position `i`, flip bit `i` and ensure decode returns the original message
- Input validation: reject non-binary bits and wrong lengths

When vectors are “hand-constructed”, demand a short explanation of how the author computed them and a second independent check (e.g., brute-force recomputation in a separate script).

## Output format

Produce:
- A bullet list of **correctness risks** (with the exact function/module names)
- A bullet list of **required tests** to add or strengthen
- A short “go/no-go” recommendation for shipping this code in:
  - toy demo (OK)
  - production comms/storage (usually “no” unless using a hardened library/hardware)
  - adversarial context (assume “no” unless strong detection guarantees exist)

