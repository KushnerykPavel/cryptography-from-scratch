---
name: "BLS signatures integration & review checklist"
description: "A practical checklist for safely using BLS signatures and aggregation (distinct-message aggregates vs same-message multi-signatures)."
phase: "08-classical-asymmetric"
lesson: "11-bls-signatures"
---

# BLS signatures integration & review checklist

Use this as a PR review checklist (or paste into an AI reviewer) whenever you see BLS signatures, aggregation, or validator/public-key registration.

## 1) What exactly is being verified?

- Is this verifying **one signature**, an **aggregate signature** (distinct messages), or a **multi-signature** (same message)?
- Is the verification equation documented (what pairing checks are performed)?
- Is the threat model clear (who chooses public keys, who aggregates, who verifies)?

## 2) Which BLS scheme variant is used?

BLS is not “one thing”. Common variants:

- **Basic / aggregate signatures over distinct messages**: safe if AggregateVerify enforces message distinctness.
- **Message augmentation**: sign over `H(pk || message)` (or an equivalent construction with domain separation) so messages are distinct per key.
- **Proof of possession (PoP)**: require each public key to come with a PoP at registration time; enables fast same-message aggregation checks.

Checklist:

- Is the variant explicitly named in code and config?
- If using **basic aggregation**, is message distinctness enforced *at verification time*?
- If using **fast same-message aggregation**, is PoP enforced for every public key?

## 3) Hash-to-curve and domain separation

- Is hash-to-curve implemented via a **standard ciphersuite** (RFC 9380-style), not ad-hoc hashing?
- Are **domain separation tags** (DSTs) fixed, versioned, and protocol-specific?
- Are different purposes separated (e.g., message signatures vs PoP vs other statements)?

Red flags:

- “Hash to point” implemented as `SHA256(m) mod q` or “try-and-increment” without a spec.
- DSTs are missing, not constant, or user-controlled.

## 4) Message encoding (most production bugs live here)

- What are the **exact bytes** being signed (canonical encoding, version prefix, length prefixes)?
- Is the message unambiguous across languages (JSON canonicalization vs protobuf deterministic vs raw bytes)?
- Is the message domain-separated so it can’t be replayed in another subsystem?

## 5) Key registration and rogue-key defenses

- Who is allowed to register keys? Is there an authenticated registry / allowlist?
- If the system verifies same-message aggregates, does registration require **PoP**?
- Are PoPs verified once at registration and stored with the key, or verified on every aggregate check?

Red flags:

- Fast same-message aggregate verification with no PoP or no key registry rules.
- “Any key the client sends” is accepted as an aggregator member.

## 6) Deserialization, subgroup checks, and point validation

For real BLS12-381 libraries:

- Are public keys and signatures **deserialized with validation** (correct format, correct subgroup)?
- Is **cofactor clearing** handled correctly (usually by the library; verify you’re calling the right API)?
- Are points at infinity rejected where required by the scheme?

Red flags:

- Using “unchecked” / “unvalidated” deserialize APIs on untrusted bytes.
- Accepting points that are not in the prime-order subgroup.

## 7) Aggregation logic and edge cases

- Does aggregation deduplicate inputs or accidentally allow duplicates?
- For aggregate signatures: does AggregateVerify reject duplicate messages (or enforce augmentation/PoP rules instead)?
- Are empty aggregates rejected (no “vacuous true” acceptance)?
- Are mismatched list lengths rejected (`len(pks) != len(messages)` or missing PoPs)?

## 8) Operational concerns

- Is verification failure observable (metrics) without leaking sensitive data?
- Are there rate limits / DoS controls (pairings are not free)?
- Is there algorithm confusion protection (explicit scheme id / ciphersuite id bound to protocol context)?

## 9) Minimal “good” reference patterns (high-level)

- Bind context into signed bytes: `b"proto=v1\\nkind=vote\\n..."`.
- Choose one BLS scheme variant, document it, and enforce its rules in verification.
- Use audited libraries and validated deserialization APIs.

