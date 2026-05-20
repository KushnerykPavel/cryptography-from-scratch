---
name: "STARK AIR review checklist"
description: "A paste-ready prompt/checklist for reviewing a STARK trace + AIR design (boundary/transition constraints, commitments, Fiat–Shamir, and what FRI must enforce)."
phase: "12-zk-proof-systems"
lesson: "11-starks"
---

# STARK trace + AIR review checklist

Use this as a PR-review prompt when someone proposes a new STARK-style proving system component: a new trace layout, new AIR constraints, or a refactor of the commitment/query interface.

## 1) Statement and threat model

- What exactly is being proven? (inputs, outputs, and what “correct execution” means)
- What is the adversary? (malicious prover, network attacker, malicious verifier, DoS constraints)
- What assumptions are relied on? (hash collision resistance, soundness error target, Fiat–Shamir ROM-style assumption)

## 2) Trace table design

- List registers (columns) with meanings and units.
- Specify row semantics: what is a “step” (VM cycle, constraint layer, round, epoch)?
- Identify which registers are public inputs vs private witness vs derived.
- Show an example trace for a tiny instance (3–8 rows) and annotate each cell.

## 3) AIR constraints

### Boundary constraints

- Which rows are pinned (row 0, last row, periodic rows)?
- Are all initial-state and final-state conditions enforced?
- Are boundary values authenticated via openings (i.e., the verifier checks they match the committed trace)?

### Transition constraints

- Write transition equations explicitly (row i → row i+1).
- Check “no degrees of freedom” issues: can a prover pick arbitrary next states and still satisfy constraints?
- Confirm constraint coverage: which columns participate; are any columns unconstrained or weakly constrained?

### Constraint hygiene

- Are constraints purely algebraic over the field (no hidden branching)?
- Are conditional constraints handled with selectors/masks correctly?
- Are there any constraints that accidentally become trivial on parts of the domain?

## 4) Commitment and openings

- What is committed: full trace, columns, or derived polynomials/evaluations?
- Commitment type: Merkle over rows, Merkle over columns, polynomial commitment (and which one)?
- Is the encoding unambiguous? (stable serialization; domain separation between leaf/node hashes)
- What exactly is opened per query? (rows, columns, neighbor rows, composition values)

## 5) Fiat–Shamir transcript

- What data is hashed to derive challenges? (must bind to commitments)
- Is the transcript encoding canonical (no ambiguity, no multiple equivalent encodings)?
- Is there clear domain separation between different challenge types?
- Are query positions sampled without bias and without accidental duplicates?

## 6) Low-degree enforcement (FRI / folding)

Even if the AIR is correct, a prover can commit to an arbitrary table that passes a few local checks unless the protocol enforces polynomial structure.

- What object is claimed to be low-degree? (trace polynomials, constraint quotient, composition polynomial)
- What is the domain? (size, subgroup/coset, blowup factor)
- What is the target maximum degree? How is it derived from the AIR?
- Where is the low-degree test performed, and what is the soundness error budget?

## 7) Soundness sanity checks

- If you remove the low-degree test, can you sketch a cheating prover strategy?
- If you remove boundary checks, can the prover “start from a different state” and still pass?
- If you remove domain separation in hashing, can you create structural collisions in toy settings?

## 8) Practicalities

- Proof size: what is sent (roots, openings, paths, number of queries)?
- Verifier time: asymptotic and concrete for expected trace sizes.
- Prover time and memory: do commitments force full materialization, or can it stream?
- Failure modes: what is rejected early vs late (DoS considerations)?

## Deliverable for the PR

Ask the author to add (or link) a one-page “design note” containing:

- Trace layout table (columns + meaning)
- Boundary constraints list
- Transition constraints list
- Commitment/opening format (exact bytes/fields)
- Transcript derivation (what’s hashed, in what order)
- Low-degree enforcement plan (FRI parameters + degree bound rationale)

