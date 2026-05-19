---
name: "Vector Commitment (Merkle VC) Audit Prompt"
description: "A paste-ready checklist + review prompt for Merkle-based vector commitments (commit/open/verify) and Merkle-proof APIs."
phase: "09-hashes-commitments-accumulators"
lesson: "03-vector-commitments"
---

# Vector Commitment (Merkle VC) Audit Prompt

Use this when reviewing a PR/spec that introduces “Merkle proofs”, “state roots”, “commitment roots”, or any `commit/open/verify` API for lists.

## 60-second checklist (red flags)

- The leaf encoding is ambiguous (e.g., string concatenation) or lacks length-prefixing.
- Leaves do not bind the **index/position** (proving “x exists” is not the same as “x at index i”).
- The commitment does not bind the **vector length n** (padding/truncation can change meaning).
- The hash input format is reused across contexts (no domain separation for leaf/node/root).
- Proof format is under-specified (endianness, ordering, left/right bits, padding rules).

## Design questions to ask (commit/open/verify)

1. What exactly is the committed object?
   - ordered list? set? key/value map? sparse map?
   - what is `n` and where is it specified?
2. What security property is required?
   - binding only? or also hiding? (Merkle VCs are usually not hiding)
3. What is the canonical encoding for leaves?
   - include index? include length? include type tags? (bytes vs utf-8 vs ints)
4. What is the canonical encoding for internal nodes?
   - left/right order fixed? domain-separated from leaves?
5. What are the padding rules?
   - odd node counts: duplicate last? hash-with-empty? power-of-two padding?
   - are these rules committed to (directly or via `n`)?
6. What is the proof format?
   - list of sibling hashes + side bits?
   - is the side bit derived from index, or explicitly provided?
7. What does verification require the verifier to know?
   - `n`? the tree height? the leaf encoding rules? the hash function id?

## Common pitfalls (what to look for in code)

- “Hash the concatenation” without a structured encoding (`i || len(v) || v`).
- Using `hex()`/`str()` serialization inside hashing (locale/format ambiguity).
- Implicitly switching between bytes/utf-8 without a canonical rule.
- Accepting multiple encodings of the same logical value (malleability).
- Forgetting to pin the hash function and domain separation tags in the protocol spec.
- Treating Merkle VCs as hiding (values are often guessable and brute-forceable).

## Paste-ready review prompt (Claude/ChatGPT)

Paste the following into your model of choice along with the relevant code/spec:

> You are reviewing an implementation/spec of a Merkle-based vector commitment (commit/open/verify) used for membership proofs in an ordered list.  
> Check for: (1) unambiguous leaf encoding (length-prefixing), (2) index binding, (3) length binding (`n` committed), (4) domain separation between leaf/node/root hashes, (5) proof format completeness (left/right bits, ordering, endianness, padding rules), and (6) misuse of Merkle VC as hiding.  
> For each issue you find, explain the concrete failure mode (how it could be exploited or cause a consensus/audit failure) and propose a specific fix (API change, encoding change, or verification rule).  
> If the design is sound, list the assumptions it relies on (hash collision resistance, canonical encoding, fixed padding), and suggest 2–3 hardening improvements (type tags, explicit hash id, strict input validation, test vectors).

