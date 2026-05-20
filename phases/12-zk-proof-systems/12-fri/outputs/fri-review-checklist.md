---
name: FRI Review Checklist (Folding + Domain + Queries)
description: A practical checklist for reviewing FRI-based low-degree tests in STARK-ish systems (domains, folding, commitments, queries, and soundness pitfalls).
phase: 12-zk-proof-systems
lesson: 12-fri
---

# FRI Review Checklist (Practical)

Use this when a design or codebase says:
- “FRI”
- “STARK low-degree test”
- “commit to layers, then query openings”

It forces the team to be explicit about the parts that usually hide soundness bugs.

## 1) Write down the domain (don’t accept hand-waving)
Checklist:
- Field: which prime `p` (or extension field) and how elements are encoded
- Domain size `n` (power of two?) and why
- Domain definition: `D = {ω^0, ω^1, …, ω^(n-1)}` with `ω^n = 1`
- Pairing rule: which index corresponds to `-x` (typically `i ↔ i + n/2`)

PR prompt:
“Show me the exact code that maps an index to a domain point, and the exact code that computes the ‘paired index’.”

## 2) State the folding rule precisely
Write the exact formula used by the implementation, including scaling:
- Is it `g = (a + β·b)/2` or `g = a + β·b`?
- Are `a` and `b` the `x` and `-x` evaluations (or some other pairing)?
- Over which field is `β` sampled?

Red flags:
- Division by 2 implemented as integer division instead of field inverse
- “We fold by averaging” without field semantics

## 3) Challenges and transcript binding (Fiat–Shamir)
Checklist:
- Exactly what is hashed to derive each `β` challenge?
- Are challenges domain-separated (protocol version tags, round tags)?
- Are challenges derived *after* committing to the data they are meant to bind?

Attack intuition:
If the prover can influence `β` late, it can adapt answers to queries and hide inconsistency.

## 4) Commitments per layer (binding)
Checklist:
- What commitment is used (Merkle, vector commitment, etc.)?
- Are leaves encoded canonically (field element width, endianness, padding)?
- Are all layers committed (or only some)? If some are skipped, why is that sound?

PR prompt:
“If I flip one evaluation in layer 0, which commitment(s) must change, and where do tests assert that?”

## 5) Query schedule and checks (soundness-critical)
Checklist:
- How many queries per round (or total)?
- How are indices sampled (uniform, derived from transcript)?
- What exactly is checked when opening a query?
  - Correct leaf against Merkle path
  - Correct pairing (open both `i` and its mate)
  - Correct fold consistency (computed parent equals opened parent at next layer)

Red flags:
- Reusing indices across rounds incorrectly
- Off-by-one errors in “mate” computation
- Mixing “natural order” vs “bit-reversed order” indices without tests

## 6) End condition
Checklist:
- What is the final object the prover reveals (constant, small polynomial, etc.)?
- How does the verifier check it matches the last committed layer?
- Is there a degree bound (or max degree) explicitly stated and enforced?

## 7) Tests to demand (minimum bar)
Ask for CI tests that:
- Pass for an honest low-degree table.
- Fail when a single evaluation is flipped.
- Fail when the prover uses a wrong Merkle path.
- Fail when the prover opens the wrong mate index.
- Fail when transcript binding is broken (e.g., challenges not hashed from commitments).

## 8) Copy/paste PR review prompt

“Please document the FRI domain (`p`, `n`, `ω`), the exact folding rule, and the exact transcript inputs used to derive challenges per round. Also add (or link) tests that flip one evaluation, break a Merkle path, and open a wrong mate index — all of which must fail verification.”

