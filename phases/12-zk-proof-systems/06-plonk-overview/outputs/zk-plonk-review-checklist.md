---
name: PLONK Review Checklist (Gates + Permutation + Transcript)
description: A practical checklist for reviewing PLONK-ish SNARK designs and implementations (halo2/gnark/snarkjs-style).
phase: 12-zk-proof-systems
lesson: 06-plonk-overview
---

# PLONK Review Checklist (Overview-Level)

Use this in design reviews and PR reviews when a project says:
- “PLONK / PLONKish / halo2-style”
- “universal SRS”
- “permutation argument / copy constraints”
- “lookups / custom gates / selectors”

## 1) Name the arithmetization explicitly
Write down (don’t accept vague answers):
- Gate shape (e.g., 3-wire PLONK gate, custom gates, lookup-enabled PLONK)
- Column set (witness columns, selector columns, permutation columns, lookup columns)
- Public input handling (separate columns? fixed positions? dedicated gates?)

## 2) Gate constraints (soundness)
Require a concrete statement of the per-row constraint(s):
- What is the gate equation (selectors and wires)?
- Are selector degrees bounded and enforced?
- Are padding rows constrained (and consistent with permutation wiring)?
- Are there “enabled/disabled” rows, and can a prover abuse disabled rows to hide bad assignments?

PR prompts:
- “Show me the exact constraint polynomial(s) and their degrees.”
- “What stops the prover from using a different gate on some rows?”

## 3) Copy constraints / permutation argument (wiring)
For PLONK-style permutation checks:
- What is the permutation σ over wire positions?
- How are copy-constraint equivalence classes turned into cycles?
- What are the boundary conditions (e.g., `Z(1)=1`, end-of-domain consistency)?
- Are β, γ (and other challenges) transcript-derived and domain-separated?

PR prompts:
- “Where do we assert `Z(1)=1` and the end condition?”
- “What exactly is the set of positions that are permuted (which columns/rows)?”

## 4) Challenges and transcript binding (Fiat–Shamir)
Checklist:
- Transcript includes: protocol version / domain tag, circuit identifier, public inputs, commitments, and all prior challenges.
- Challenges are derived in the correct order (no “late binding”).
- Encodings are canonical and unambiguous (length-prefixing, fixed-length field encoding, etc.).

Red flags:
- “We hash the witness” (usually wrong and/or meaningless)
- Missing public input binding (statement substitution)

## 5) Polynomial commitment layer assumptions
Name the commitment scheme and what it gives you:
- KZG (pairings; trusted/universal setup; tiny proofs)
- IPA (no pairings; transparent-ish but larger proofs; curve assumptions)
- FRI/STARK-ish (transparent; different trade-offs; larger proofs)

PR prompts:
- “Where do we enforce degree bounds?”
- “What’s the exact setup model and how do we verify parameters?”

## 6) Zero-knowledge and leakage
Even if arithmetic checks are correct, ZK can fail via:
- Missing blinding terms (witness polynomials leaking through openings)
- Reusing randomness across proofs
- Side-channel leaks in field arithmetic / MSMs
- Logging or serialization that reveals witness components

## 7) Practical “sanity tests” to demand
Ask for these in CI / unit tests:
- A valid witness passes.
- Flipping one witness cell breaks a gate constraint.
- Breaking a copy constraint breaks the permutation check.
- Mutating public inputs breaks verification (transcript binding).
- Boundary-condition tampering fails (`Z(1)`, end condition).

## 8) Copy/paste review prompt
Paste this into a PR review:

“Please link the exact gate equations (selectors/wires), the definition of the permutation σ (what positions are permuted), and the transcript inputs used to derive challenges. Also point to tests that (1) break a gate constraint, (2) break a copy constraint, and (3) change a public input, all of which must fail verification.”

