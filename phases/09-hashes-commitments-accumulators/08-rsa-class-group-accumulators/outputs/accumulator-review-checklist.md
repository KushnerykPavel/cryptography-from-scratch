---
name: "Accumulator Design & Audit Checklist"
description: "A copy-pastable checklist for reviewing RSA/class-group accumulator designs and deciding between accumulators, Merkle trees, and KZG."
phase: "09-hashes-commitments-accumulators"
lesson: "08-rsa-class-group-accumulators"
---

# Accumulator Design & Audit Checklist

Use this when reviewing a PR, writing a design doc, or choosing a membership-proof primitive.

## 1) What problem are you solving?
- Do you need **membership proofs**, **non-membership proofs**, or both?
- Do you need **dynamic updates** (add/remove), or is the set append-only / epoch-based?
- How many verifications happen per update? (One update might invalidate many witnesses.)
- What is the acceptable client proof size and server storage size?

## 2) Pick the primitive (decision guide)

### If you need membership only
- Prefer **Merkle trees** when you want simplicity, standard tooling, and clear update mechanics.
- Consider **accumulators** when you want constant-size proofs and are willing to accept more complex update logic and assumptions.

### If you need succinct proofs inside pairing-friendly protocols
- Consider **KZG** (vector commitments) if you already accept its setup/trust model and want efficient proofs.

### If you need non-membership
- RSA accumulators support classic non-membership proofs, but check the exact scheme and its conditions.
- Many accumulator deployments avoid non-membership by using “deny lists” or epoch snapshots; ensure the product requirement truly needs it.

## 3) Threat model and setup assumptions
- Who generates public parameters?
  - RSA accumulators: who generates `N=p*q` and who can learn `(p,q)`?
  - Class groups: how is the discriminant chosen and validated?
- Are you assuming an “unknown-order group”? If yes, state what makes the order unknown.
- What breaks if the order trapdoor is known?
  - Can an attacker forge witnesses?
  - Can they produce non-membership proofs for members?

## 4) Element encoding (this is where bugs hide)
- Is every element mapped to a **unique representative**?
  - If using hash-to-prime: domain separation, bit length, collision handling, determinism.
  - If using “direct primes”: how do you prevent duplicates / adversarial choice?
- Are elements normalized (case-folding, whitespace, canonical byte encoding)?
- Is the encoding fixed in the protocol spec (not “implementation-defined”)?

## 5) Update semantics and witness management
- Append-only:
  - Can clients update their witness with one exponentiation per new element?
  - Do clients need to stay online to process updates, or can they “catch up”?
- Deletions:
  - What exact algorithm supports deletion (if any)?
  - Who is trusted to publish update info, and what does a client need to store?
- What is the “source of truth” for the set? Is there an authenticated log of updates?

## 6) Verification API (make it explicit)
Write down these exact interfaces in the design doc:
- `Commit(S) -> A`
- `ProveMember(S, x) -> w`
- `VerifyMember(A, x, w) -> bool`
- If needed: `ProveNonMember(S, x) -> proof`, `VerifyNonMember(A, x, proof) -> bool`

If you can’t write these cleanly, the design probably isn’t stable yet.

## 7) Practical checks (implementation review)
- Constant-time: are any branches or operations leaking secrets? (If secrets exist at all.)
- Input validation: reject `x <= 1`, reject non-coprime group elements, reject malformed encodings.
- Parameter sizes: do you meet the security level? (Toy sizes are for demos only.)
- Determinism: can two parties independently map the same element to the same representative?
- Test vectors: do you have deterministic vectors for core operations and edge cases?

## 8) “Red team” questions to ask in review
- Can an attacker choose elements that collide under the encoding?
- Can they cause `gcd(s, x) != 1` and break non-membership proofs or trigger weird behavior?
- If someone knows the trapdoor (e.g., factors of `N`), what can they forge?
- What happens if a client has an old witness and missed updates?

