---
name: "ZK Knowledge Soundness — Extractor Checklist"
description: "A practical audit checklist (and LLM prompt) to evaluate 'proof of knowledge' claims: what witness is being proven, what extractor exists, and what assumptions it relies on."
phase: "11-zero-knowledge-foundations"
lesson: "10-extractors"
---

# ZK Knowledge Soundness — Extractor Checklist

Use this checklist to review a protocol, paper, PR, or vendor claim that says:
“this proof shows knowledge of a witness” / “this is an argument of knowledge”.

If you paste this into an LLM, also paste the protocol description and the
security claim verbatim.

## 1) What is being proven?
- **Statement (public input):** What is the verifier given?
- **Witness (secret input):** What must the prover actually know?
- **Relation R(x, w):** Write the exact predicate that must hold.
- **What does 'success' enable?** (spend, authenticate, mint, decrypt, sign, …)

## 2) Soundness vs knowledge soundness
- Does the document distinguish:
  - **Soundness:** false statements are rejected (except with small probability)
  - **Knowledge soundness:** acceptance implies existence of an extractor that outputs a witness
- If it only proves soundness, where is the argument-of-knowledge upgrade justified?

## 3) Extractor model (this is the core)
Identify what the proof assumes the extractor can do:
- **Black-box rewinding extractor:** Can restart the prover from an internal checkpoint.
- **Forking / Random Oracle model extractor:** Can re-run the prover while changing oracle outputs (Fiat–Shamir style).
- **Straight-line extractor:** No rewinding; extracts from one forward run (stronger, rarer).
- **Simulation extractability / simulation knowledge soundness:** Extraction must work even when proofs are simulated.

Write down the exact model and where it is stated.

## 4) Where does extraction come from?
For sigma-protocol-style components, confirm the exact extraction route:
- **Special soundness claim:** From two accepting transcripts with the same commitment and different challenges, compute the witness.
- **How do we get two transcripts?**
  - Interactive: rewinding after the commitment.
  - Fiat–Shamir: a forking lemma / ROM argument that yields two challenges for the same commitment.
- **What is the knowledge error / soundness error?**
  - What is the challenge size?
  - How is repetition / batching handled?

If the protocol uses OR/AND composition:
- For **OR**: ensure the proof explains how “two global challenges” implies “two challenges in one branch” (and which witness is extracted).
- For **AND**: ensure extraction outputs all required witnesses (or the intended combined witness).

## 5) Fiat–Shamir specifics (if non-interactive)
- What hash function / transcript format is specified?
- Is there explicit domain separation (protocol id, statement, commitment, context)?
- Are there binding-to-statement checks (no replay across statements)?
- Does the security proof explicitly say **Random Oracle Model** (or an alternative)?
- Is there a multi-proof setting? (batch verification, aggregation, recursion) If so, does extraction still apply?

## 6) Implementation “gotchas” that break extractor arguments
Look for concrete failures that invalidate the proof assumptions:
- **Nonce reuse** (same commitment twice) leaks witnesses in Schnorr-like protocols.
- **Wrong modulus** (scalar field vs group modulus) silently breaks verification/extraction.
- **Bad group checks** (points not in the right subgroup / wrong order) invalidate soundness and extractor logic.
- **Challenge malleability** (missing transcript binding / ambiguous encoding) weakens Fiat–Shamir.
- **Stateful provers** that reuse randomness across sessions (accidentally enabling extraction by attackers).

## 7) Deliverable: one-paragraph extraction story
Write a short paragraph answering:
“If an attacker makes the verifier accept with non-negligible probability, how does the extractor obtain a witness, under what exact assumptions, and with what success bound?”

If you cannot write this paragraph unambiguously, the “proof of knowledge” claim is not review-ready.

