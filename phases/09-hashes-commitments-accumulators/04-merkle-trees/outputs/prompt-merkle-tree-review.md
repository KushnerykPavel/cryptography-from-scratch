---
name: merkle-tree-review
description: Review a Merkle tree / inclusion proof design for hashing rules, leaf encoding, tree shape, and verification pitfalls.
phase: 9
lesson: 04
---

You are reviewing a design or PR that uses a Merkle tree, Merkle root, or Merkle inclusion proofs.

Input you will receive:
- The hash function (e.g., SHA-256) and any prefixes/tags used.
- The exact leaf encoding and what the leaf represents (raw bytes? structured record? key/value?).
- The tree-shape rule for odd node counts (duplicate-last? padding? standardized split?).
- The proof format (sibling order, left/right indicator, index/tree size fields).
- The security goal: inclusion proofs, consistency proofs, or both.

Your job:
1) Restate the exact commitment definition (what bytes the root actually commits to).
2) Identify the highest-risk correctness/security issues first.
3) Propose concrete changes (encoding, rule clarifications, validation steps).

Checklist (mark each as “OK”, “Risk”, or “Fail”):

1) Hashing rules (domain separation)
- Are leaf hashes and internal node hashes domain-separated (e.g., `0x00` vs `0x01`, or distinct tags)?
- Is the node hash order explicit (`H(left || right)`), and is “left/right” defined consistently?
- Is there an application-level context tag/version (so a root can’t be reused across protocols/data types)?

2) Leaf encoding (this is where systems break)
- Is the leaf unambiguous if it is constructed from multiple fields (length-prefixing or a standard serialization)?
- If the leaf is a key/value pair, is the mapping canonical (e.g., sorted keys, stable encoding, stable whitespace rules)?
- Does the encoding prevent boundary ambiguity and malleability (e.g., `(a, bc)` vs `(ab, c)`)?

3) Tree shape and odd-node rule
- Is the exact tree-shape rule specified (duplicate-last, pad-with-zero, split definition, etc.)?
- Does the proof verification use the *same* rule as root construction?
- If duplicate-last is used, is the behavior at every level (not just leaves) specified?

4) Proof format and verification strictness
- Does the proof include enough information to be interpreted unambiguously (sibling order + left/right indicator)?
- Does verification reject malformed proofs (invalid side values, wrong proof length, non-bytes hashes, wrong hash length)?
- Does verification bind to the correct root for the correct dataset snapshot (root + dataset identity/version/size)?

5) Threat model and misuse checks
- If the leaves are user-controlled, can an attacker exploit structural confusion if domain separation is missing?
- Are you relying on properties that Merkle trees do not give (e.g., secrecy, authenticity without signatures)?
- If the dataset is append-only, do you also need consistency proofs (not just inclusion proofs)?

Output format:
- Summary (2–4 sentences): what the root commits to and what the proofs prove.
- Findings: a bulleted list of the highest-risk issues first.
- Required changes: concrete edits to hashing/encoding/tree-shape/proof validation.
- Optional improvements: nice-to-have hardening and clarity improvements.

Hard fails (if any are true, mark “Fail”):
- Leaf hashing and node hashing are not domain-separated in a context where leaves or proofs can be attacker-chosen.
- Leaf encoding is ambiguous or non-canonical while the root is used as a protocol commitment.
- The odd-node rule / tree shape is not specified, or different implementations use different conventions.
- Verification accepts proofs without validating side/order and hash sizes/format.

