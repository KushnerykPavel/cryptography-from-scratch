---
name: Fiat–Shamir Transcript Review Checklist
description: A practical checklist for reviewing Fiat–Shamir transcripts (binding, encoding, domain separation, and grinding risks) in ZK proofs and Schnorr-style signatures.
phase: 11-zero-knowledge-foundations
lesson: 04-fiat-shamir
---

# Fiat–Shamir Transcript Review Checklist

Use this in PR reviews and protocol design docs whenever you see “Fiat–Shamir”, “transcript”, “hash-to-challenge”, “non-interactive proof”, or “Schnorr-style signature”.

## 1) What is the statement being proved?

- Write it down as a function of public inputs:
  - Examples: “I know `x` such that `y = g^x`”, “I know openings to these commitments”, “This ciphertext decrypts to a value in range”.
- List the exact public inputs that define the statement:
  - group/curve id, `p/q` or curve parameters
  - generators (`g`, `G`, `H`, …)
  - public keys, commitments, ciphertexts, public witnesses
- Confirm both prover and verifier agree on those inputs and bind them consistently.

## 2) What exactly goes into the hash?

Default safe rule: hash *everything the verifier would have seen before choosing the challenge* plus the intended context.

- Domain separator:
  - protocol name + version
  - challenge label / round id (if multiple challenges)
  - network / application context if relevant (chain id, app id)
- Statement inputs:
  - all public inputs that define the statement (including parameters)
- Transcript so far:
  - prover commitments (and any prior challenges if multi-round)
- Message / context binding:
  - for signatures: bind the message bytes
  - for proofs in protocols: bind the session id / nonce / context string

Red flag: “We hash only the prover commitment” or “we hash only the message”.

## 3) Encoding and canonicalization

Most Fiat–Shamir bugs are encoding bugs.

- Are group elements serialized canonically?
  - unique encoding (no multiple byte encodings for the same point/field element)
  - reject non-canonical / invalid encodings
- Are variable-length fields unambiguous?
  - fixed-length encoding per field, or length prefixes for each field
  - no raw concatenation of strings/bytes without boundaries
- Is endianness fixed and documented?
- Are integers reduced modulo the correct modulus before encoding?

Red flag: concatenation like `H(str(a) + str(b))` or `H(a_bytes || b_bytes)` without lengths.

## 4) Challenge size and grinding

Fiat–Shamir proofs are vulnerable to “try many nonces until the hash looks good”.

- How large is the challenge space?
  - target: ≥ 128 bits of effective challenge entropy (often more)
  - small challenges that are “fine interactively” may be broken non-interactively
- Can the prover cheaply vary the transcript?
  - changing nonce, re-randomizing commitments, permuting inputs
- Are there extra constraints to limit grinding?
  - deterministic nonces (signatures)
  - binding transcript to a session nonce provided by verifier / protocol
  - rate-limiting / cost mechanisms (system-level, not crypto-level)

Red flag: challenge is 32–64 bits and prover can retry offline.

## 5) Multi-challenge transcripts (real proof systems)

If a protocol derives multiple challenges:

- Is each challenge derived from the transcript up to that point?
- Is each challenge labeled (e.g., `challenge("alpha")`, `challenge("beta")`)?
- Is the previous challenge included in the transcript state (common pattern)?

Red flag: “We hash the same values for every challenge”.

## 6) Security model assumptions

Be explicit about what is assumed.

- Is Fiat–Shamir security argued in the Random Oracle Model (ROM)?
- Does the design claim quantum security? If yes, are you relying on QROM results?
- If the protocol is deployed with a concrete hash (Poseidon/Keccak/SHA-256), is that choice justified for the environment and threat model?

Red flag: “It’s secure because SHA-256 is secure” with no statement of the actual model.

## 7) Test strategy

Add tests that fail when the common mistakes are introduced.

- Message binding tests:
  - same proof must not verify for a different message/context
- Domain separation tests:
  - proofs from different protocol labels must not cross-verify
- Encoding tests:
  - reject non-canonical encodings (if applicable)
- Negative tests:
  - tweak one transcript component and ensure verification fails

## 8) Quick “stop the review” questions

If “yes” to any, pause and investigate:

- “We didn’t include the message/context in the transcript.”
- “We didn’t include the statement/public inputs in the transcript.”
- “We serialize points/ints with `str()` or ad-hoc concatenation.”
- “The challenge is small and the prover can retry cheaply.”
- “We reuse transcript formats across protocols without explicit labels.”

