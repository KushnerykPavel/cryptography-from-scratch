---
name: Bulletproofs IPA integration review checklist
description: A paste-ready prompt + checklist for reviewing Bulletproofs inner-product proofs (and range proofs that embed them).
phase: 11-zero-knowledge-foundations
lesson: 08-bulletproofs
---

# Bulletproofs / IPA Integration Review Checklist (Paste-Ready)

Use this when reviewing a PR that:
- “adds Bulletproofs range proofs”
- “verifies Bulletproofs proofs”
- “implements an inner product proof (IPA/IPP)”

Goal: catch transcript-binding bugs, shape/parameter bugs, and serialization gotchas before they become consensus failures or security issues.

## Paste This Prompt Into Your Reviewer AI

You are a cryptography-focused reviewer. Review the diff for a Bulletproofs integration and answer:

1) **Statement binding:** What *exact statement* is being proved/verified? List the public inputs that must be transcript-bound (commitments, generators, sizes, protocol versions).
2) **Transcript:** Identify the transcript implementation (Merlin or equivalent). Confirm:
   - Domain separation is used (protocol name + version).
   - Vector length (`n`) / aggregation parameters are committed.
   - All prover messages that influence challenges are appended *before* hashing.
   - The *statement* (e.g. commitment `V`, `P'`, `Q`, generators) is appended before any challenges.
3) **Shape invariants:** Confirm the verifier rejects:
   - non-power-of-two vector lengths (or verifies deterministic padding rules),
   - mismatched generator lengths,
   - identity points where forbidden,
   - non-canonical scalars / invalid encodings.
4) **Serialization:** Confirm the transcript byte encoding is unambiguous:
   - length-prefix or fixed-width encodings,
   - consistent endianness,
   - no string concatenation ambiguities.
5) **Soundness hazards:** Look for:
   - challenges derived before transcript items are appended,
   - reused blinding/nonces across proofs,
   - mixing generators across proofs without domain separation,
   - accepting proofs with missing components (wrong `k`, missing L/R).
6) **Side-channels:** Flag any non-constant-time scalar inversion, branching on secrets, or variable-time multiscalar multiplication when secrets are involved.
7) **Failure behavior:** Verify failures are handled safely:
   - verification returns a boolean/error without panics in consensus-critical code,
   - errors are not swallowed,
   - test coverage includes tampering cases.

Deliverables:
- A bullet list of **must-fix** issues (security/correctness).
- A bullet list of **should-fix** issues (hardening/clarity).
- A short section: “What test should be added to prevent regression?”

## Quick Checklist (Human)

### Statement + Parameters
- [ ] Proof statement is explicitly documented (what is proven about what commitment).
- [ ] Generator derivation is fixed and domain-separated (no adversary-controlled generators).
- [ ] Vector length handling is explicit (power-of-two requirement or deterministic padding).

### Transcript Binding (Fiat–Shamir)
- [ ] Domain separator includes protocol + version (and rangeproof/ipp variants).
- [ ] Transcript commits to: sizes, generators (or their derivation label), commitments, and all prover messages.
- [ ] Challenges are derived only after appending the relevant messages.

### IPA / IPP Verification Equation
- [ ] Verifier recomputes challenges from transcript (doesn’t accept them as input).
- [ ] Correct round count `k = log2(n)` is enforced.
- [ ] Verifier checks the single multiscalar equation (or its equivalent) and rejects on mismatch.

### Test Coverage (Minimum)
- [ ] Happy-path proof verifies.
- [ ] Tamper 1 bit/byte in `L` or `R` => reject.
- [ ] Tamper final scalars => reject.
- [ ] Tamper statement commitment `P'`/`V` => reject.
- [ ] Wrong `n` / padding mismatch => reject.

## Red Flags (Stop-Ship)
- Challenges derived without committing to the statement.
- No domain separation (or same transcript labels reused across protocols).
- Accepting variable-length proofs without enforcing `k`.
- Ambiguous serialization (string concat, missing lengths).

