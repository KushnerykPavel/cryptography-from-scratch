---
name: "Threshold HE / Distributed Decryption Review Checklist"
description: "A practical checklist for designing, reviewing, and operating threshold decryption (and threshold FHE) systems."
phase: "17-fhe-and-mpc"
lesson: "11-threshold-fhe"
---

# Threshold HE / Distributed Decryption Review Checklist

Use this checklist when you review a design doc, PR, or runbook for a system that supports:
- homomorphic computation on ciphertexts (BFV/BGV/CKKS/TFHE/etc), and
- decryption that requires a quorum (`t-of-n`) of key-holders.

## 1) Threat model and goals
- What are you protecting: inputs, outputs, both, metadata (who queried what), and/or timing?
- Who is trusted: honest majority, honest-but-curious, or actively malicious?
- What’s the adversary: external attacker, insider, colluding subset of key-holders, or compute provider?
- What does “threshold” mean operationally: `t` signatures to authorize, or `t` shares required to decrypt, or both?
- What is the liveness requirement: can you tolerate missing parties, churn, or network partitions?

## 2) Key generation and custody
- Is there a trusted dealer? If yes, what prevents dealer key exfiltration?
- If no dealer, is there a DKG? Which protocol, how many rounds, and what’s the failure/retry policy?
- Are key shares bound to identities (hardware keys, certs, or an allowlist) and rotated on membership changes?
- Where are shares stored: HSM/TEE, disk, encrypted at rest, backed up, and how is compromise detected?
- Are shares ever reconstructed (even “temporarily”) in RAM on a single machine? If yes, that’s a red flag.

## 3) Decryption protocol
- Does decryption require `t` parties to produce partial decryptions (preferred), or does a combiner reconstruct a key (avoid)?
- Are partial decryptions authenticated and replay-protected (session id, ciphertext id, epoch)?
- Is there verifiability: proofs / consistency checks that a partial decryption is well-formed?
- Can a single malicious party block progress? If yes, do you have a threshold of *responses* (e.g., `t` out of `n`) and a timeout policy?
- Are partial decryptions and proofs kept as an audit log with stable identifiers?

## 4) Evaluation keys and auxiliary material
- Which evaluation keys exist (relinearization, rotation, key switching, bootstrapping)?
- Who can generate them and when (offline ceremony vs runtime)?
- Do evaluation keys leak anything if exfiltrated (beyond what the scheme assumes)?
- Are evaluation keys versioned and bound to the correct secret-share epoch?

## 5) API/UX shape (how this fails in practice)
- Is decryption an explicit action (approve + decrypt) rather than an implicit side-effect?
- Are you rate-limiting and monitoring decryption requests (a decryption oracle is dangerous)?
- Do you return plaintext only after policy checks (authorization, purpose limitation, threshold approval)?
- Do you support “decrypt only aggregates” rather than arbitrary ciphertexts when possible?

## 6) Abuse cases to explicitly test
- Malicious partial decryptions: one party returns random garbage.
- Replay: reusing old partial decryptions in a new session.
- Mismatched epochs: mixing shares from different key rotations.
- Collusion: `t` parties collude (that’s the assumed break); confirm what damage that causes in your system.
- Decryption-oracle exposure: can an attacker submit chosen ciphertexts and learn anything from errors or timing?

## 7) Operational runbooks
- Key ceremony: who attends, what artifacts are produced, and how do you verify correctness?
- Decryption ceremony: who approves, how do you prove approvals happened, and how do you handle emergencies?
- Rotation: planned and emergency rotation procedures (and how ciphertexts are handled across epochs).
- Incident response: what happens if a key-holder device is compromised or a party goes offline?

## 8) “Green flags” in a serious threshold HE system
- DKG (no single party ever knows the full secret).
- Partial decryption with verifiable proofs or robust consistency checks.
- Clear liveness policy: decrypt succeeds with any `t` correct parties, not “the same fixed `t`”.
- Explicit policy boundary: evaluation is public-ish; decryption is gated and audited.
- Strong identity and secure enclaves/HSMs for key share custody.

