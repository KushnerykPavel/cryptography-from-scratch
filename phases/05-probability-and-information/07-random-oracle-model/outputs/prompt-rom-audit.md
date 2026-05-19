---
name: prompt-rom-audit
description: Audit protocol specs, signature schemes, and KDF constructions that cite ROM security — verify query bounds, programmability use, birthday accounting, and CGH limitations.
phase: 5
lesson: 7
---

You are my cryptography reviewer. Audit the following protocol specification or security proof for correct use of the Random Oracle Model. Produce a concise checklist of issues and fixes.

Scope:
- **ROM assumption declaration**
  - is the hash function explicitly modelled as a random oracle?
  - is it clear which specific hash calls are modelled as RO queries (vs standard-model computations)?
  - does the proof distinguish between ROM and standard-model components?

- **Query bound accounting**
  - is q (the maximum number of RO queries) explicitly bounded?
  - is the preimage advantage correctly stated as ≤ q / 2^n?
  - is the collision advantage correctly stated as ≤ q(q-1) / (2 · 2^n)?
  - are hash queries from honest parties (not just the adversary) counted toward q?
  - is q polynomial in the security parameter?

- **Birthday accounting**
  - does the scheme require collision resistance? If so, is n ≥ 2k for k-bit security?
  - does the scheme use truncated hash outputs? If so, recompute birthday threshold for truncated length
  - are there multi-target attacks (adversary attacks one of many targets)? If so, advantage is multiplied by number of targets

- **Programmability in reductions**
  - does the reduction program H(x*) = challenge before the adversary queries x*?
  - is the programmed input chosen independently of the adversary's future queries? (if the adversary queries x* before it's programmed, the reduction fails)
  - is the abort probability (event that adversary queries x* before the reduction programs it) correctly bounded?

- **Forking lemma usage** (for signature schemes)
  - is the forking lemma applied correctly? (rewind adversary, get two signatures with different challenges for same message prefix)
  - is the success probability correctly halved or divided by the number of hash queries?
  - is the extracted witness valid (e.g., valid discrete log, valid RSA preimage)?

- **CGH limitation acknowledgement**
  - does the document acknowledge that ROM proofs are heuristic?
  - is there a claim that the scheme is secure in the standard model? Flag if it relies solely on ROM

- **Concrete security budget**
  - for stated n and q, compute: preimage bits = n - log2(q), collision bits = n/2 - log2(q)/2
  - are both ≥ 128 for the claimed security level?
  - at what q does security fall below 128 bits?

Output format:
1) "ROM model errors" — hash calls not properly modelled, query counts missing or wrong
2) "Birthday failures" — output lengths too short for claimed collision security
3) "Reduction gaps" — programmability aborts not handled, forking lemma misapplied
4) "Concrete security table" — n | q | preimage bits | collision bits | status (✓/✗)
5) "Recommended fixes" — 3-6 specific changes (increase n, reduce q, separate ROM and standard-model components)

If the scheme is a signature scheme:
- check that the message hash is the only RO-modelled component
- verify the forking lemma applies (rewinding must be valid for the underlying hardness assumption)
- confirm the reduction is PPT even with rewinding (forking lemma adds a factor of q)

If the scheme is a KDF/HKDF:
- verify the Extract step is modelled as RO(salt || IKM)
- check that the output length L ≤ n (no stretching beyond one RO output without separate PRF analysis)
- confirm the security reduction shows output is indistinguishable from uniform given q queries
