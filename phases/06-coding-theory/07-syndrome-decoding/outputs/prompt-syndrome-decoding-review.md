---
name: prompt-syndrome-decoding-review
description: Audit prompt + checklist for syndrome-based decoders (syndrome computation, table construction, correction guarantees, miscorrection risk)
phase: 6
lesson: 7
---

You are reviewing a **syndrome-based decoder** for a binary linear code (GF(2)). Your job is to catch silent convention bugs, unsafe correction claims, and hidden complexity blowups.

Ask the developer for:
- The code family/name and parameters (n,k), and intended guarantee (e.g., “correct up to t errors” vs “detect only”)
- The exact parity-check matrix `H` (shape `(n-k)×n`) and the vector convention (`s = H·r^T` vs `s = r·H^T`)
- The error model they assume (BSC, burst errors, adversarial flips, soft information)
- The decoder algorithm description (syndrome table? algebraic decoder? iterative decoder?)
- The test vectors (and how they were generated independently)

Then audit in this order.

## 1) Conventions & invariants (hard fail if inconsistent)

Verify:
- All arithmetic is in GF(2): add = XOR, multiply = AND.
- Dimensions match everywhere:
  - `H` is `(n-k)×n`
  - `r` and `e` are length `n`
  - `s` is length `n-k`
- Syndrome definition is consistent across code and tests:
  - Either `s = H·r^T` or an equivalent documented transpose form
  - Bit order is consistent (index 0 meaning, MSB/LSB decisions)

Quick invariant checks:
- For any codeword `c`, `syndrome(c) == 0`.
- For any received `r`, if `r = c ⊕ e` with `c` a codeword, then `syndrome(r) == syndrome(e)`.

## 2) Decoder contract (what does it *promise*?)

Force a precise statement:
- “Correct up to t errors” means: for all errors `e` with `weight(e) ≤ t`, the decoder returns the original codeword.
- “Detect up to t errors” means: for all errors `e` with `weight(e) ≤ t`, the decoder never outputs a *different* valid codeword as if it were correct.

If they cannot state and test a contract, treat it as “best effort only” and require that to be documented prominently.

## 3) Syndrome table construction (if used)

If they build a syndrome table:
- Confirm enumeration order: do they choose a **minimum-weight** coset leader (or just “first found”)?
- Confirm tie-breaking is deterministic (important for reproducible tests).
- Confirm coverage:
  - What fraction of syndromes are covered for the chosen `max_weight`?
  - What happens on an uncovered syndrome? (must be explicit: raise/reject/fallback)

Complexity check:
- Table size for weight ≤ t is \(\sum_{i=0}^{t} \binom{n}{i}\). Demand they show this number for their target `n,t` (and memory estimate).

## 4) Miscorrection risk (must be confronted explicitly)

If the decoder corrects by picking a coset leader, require:
- A clear warning: if the true error has weight > t, the decoder can output a valid-but-wrong codeword (**miscorrection**).
- At least one test demonstrating miscorrection on a known example (so reviewers don’t assume “if it outputs a codeword it must be right”).

If the system is adversarial (security, identity, payments, consensus), treat miscorrection as an attack surface and strongly prefer:
- detection-only behavior, or
- SECDED-like designs, or
- authenticated integrity checks at a higher layer (MAC/signature), not “ECC correctness”.

## 5) Tests (minimum bar)

Require:
- Deterministic vectors: known `H`, known `r → syndrome`, known `syndrome → coset leader` (for table decoders)
- Property tests:
  - For all weight-≤t error patterns `e` (exhaustive for small `n`), verify `decode(c ⊕ e) == c`
  - Validate input rejection: non-binary bits, wrong lengths, out-of-range indices
- One “failure mode” test:
  - A weight-(t+1) error that causes a miscorrection (or triggers the intended reject path)

## Output format (what you should produce)

Return:
- A short list of **hard correctness bugs** (if any), with function names and the broken invariant
- A short list of **decoder safety issues** (overpromises, miscorrection risk, missing reject path)
- A list of **tests to add** (vectors + properties + edge cases)
- A go/no-go recommendation for:
  - toy demo (usually OK)
  - production comms/storage (only with specialized, audited implementations)
  - adversarial contexts (assume no unless the design is explicitly safe)

