---
name: "Arkworks Circuit Review Checklist"
description: "A backend-agnostic checklist for reviewing arkworks R1CS circuits: inputs, witness, constraints, and proving-system swaps."
phase: "13-zk-engineering"
lesson: "04-arkworks"
---

# Arkworks Circuit Review Checklist (Backend-Agnostic)

Use this in PR review for any Rust circuit that claims it can be proven with different backends (Groth16/Marlin/Plonk/etc.) in the arkworks ecosystem.

## 1) Statement contract (public inputs)

- List the public inputs in order, with types and semantics (e.g., `root`, `nullifier`, `value`, `chain_id`).
- Confirm the verifier and prover use the exact same order (including “output wires” that some toolchains treat as public).
- Confirm what is *bound* to the proof: every value that must be checked by the verifier must be a public input, not a witness.
- Confirm domain separation: any context (chain id, app id, version) that prevents replay lives in public inputs or inside the constrained computation.

## 2) Witness contract (private inputs + intermediates)

- Enumerate which fields are witness: secrets, preimages, randomness, intermediate wires.
- Confirm witnesses are not “implicitly trusted”: every witness used in security-critical logic must be constrained to the statement.
- Look for “free witnesses” (allocated but never constrained, or constrained only via an unconstrained constant).

## 3) Constants and parameters

- Constants should appear as coefficients in linear combinations or as `FpVar::constant`, not as unconstrained witness variables.
- For hash/curve parameters (Poseidon, Pedersen, etc.), confirm they are:
  - fixed for the circuit (not provided as witness),
  - consistent with the library implementation used outside the circuit,
  - versioned or domain-separated if there are multiple parameter sets.

## 4) Native vs constraint alignment

When there is both:

- a native function (off-circuit computation), and
- a gadget (in-circuit constraints),

verify they implement the same spec:

- same field modulus / curve,
- same endianness (byte ↔ field conversions),
- same hash personalization / domain tag,
- same range / bit-length assumptions.

If you can’t point at a single spec document or test vector, the circuit will drift.

## 5) Constraint hygiene and debuggability

- Ensure the circuit has an easy way to surface the “first failing constraint”:
  - a unit test that calls `cs.is_satisfied()` and prints/debugs offending constraints, or
  - structured logging around key gadget boundaries.
- Prefer smaller named subcircuits/gadgets so failures localize.

## 6) Backend portability checks

When switching proving systems, your circuit should not change; only the proving wrapper should.

- Circuit uses `ark-relations` + `ark-r1cs-std` primitives, not backend-specific APIs.
- No backend-specific assumptions leak into the circuit:
  - “trusted setup is already present”,
  - hard-coded SRS size,
  - proof recursion features that exist only in one backend.
- If the backend requires a specific arithmetization (e.g., R1CS vs custom gates), confirm the circuit’s representation matches.

## 7) Performance red flags (security-relevant)

Performance problems become security problems when they force you to weaken constraints.

- Range checks implemented naively (bit-decomposition everywhere).
- Hash gadgets used on large inputs without chunking strategy.
- Repeated conversions between bits/bytes/fields.
- Unnecessary allocations of intermediate variables (especially around multiplications).

Ask for:

- a constraints count before/after the change,
- a benchmark harness (even a simple wall-clock run) for prover time.

## 8) Minimum test suite to demand in PR

- Deterministic test vectors:
  - known witness + expected public output(s),
  - at least one failing vector (public output altered, or a key witness bit flipped).
- Property tests:
  - small randomized cases (seeded RNG),
  - edge cases (0, 1, modulus-1, max ranges),
  - rejection tests (invalid encodings, out-of-range values).

## Reviewer decision guide

Block the PR if any of these are true:

- public input order is undocumented or inconsistent across components,
- any constant/parameter that affects correctness is unconstrained,
- native code and gadget logic have no shared spec/tests,
- “it proves” is tested but “it rejects bad witnesses” is not tested.

