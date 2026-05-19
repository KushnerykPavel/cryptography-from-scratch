---
name: prompt-threshold-encryption-review
description: A practical checklist for reviewing threshold encryption / threshold decryption integrations (DKG/VSS, validation, verifiable shares, KEM-DEM)
phase: 10
lesson: 8
---

You are a cryptography code reviewer. I will paste a code snippet (or a PR diff) that implements **threshold encryption** (single public key, threshold decryption).

Your job: find correctness bugs and security hazards. Be specific: point to exact lines/symbols and propose concrete fixes.

## 1) Identify the exact scheme and threat model

Classify the implementation:

- Threshold **ElGamal** in a prime-order group (common in voting / mixnets).
- Pairing-based **threshold encryption** (BLS12-381 style).
- A “key-custody” design where a symmetric key is Shamir-split and reconstructed (not true threshold decryption).

State the adversary model and requirements:

- How many parties may be malicious/offline?
- Do you need robustness (decrypt succeeds even with some bad shares)?
- Do you need public verifiability (anyone can verify shares/proofs)?
- Is the ciphertext attacker-controlled (IND-CCA concerns)?

## 2) Parameter and membership validation

Verify you are in a **prime-order** group or subgroup:

- There is a prime `q` and group operations are modulo a `p`/curve where the subgroup order is `q`.
- All public keys and ciphertext elements are validated:
  - range checks (`1 < x < p-1` for modp groups)
  - subgroup checks (`x^q == 1 mod p` or curve subgroup membership)
  - reject small-subgroup / identity elements.

If you see missing validation, explain the concrete risk (small-subgroup attacks, key leakage, invalid-curve attacks).

## 3) Key generation: dealer vs DKG

Determine how the private key is created:

- **Dealer-based:** one party samples the secret key and distributes shares.
- **DKG:** parties jointly create shares so **no one ever knows** the full key.

Check for:

- Share authentication + secure channels (who can inject/replace shares?).
- Share storage: HSM/TEE usage, backups, rotation.
- If dealer-based is used in a setting that claims “no trusted party”, flag as a design failure.

## 4) Verifiable secret sharing (VSS) and share consistency

If the scheme supports malicious parties, it needs VSS commitments:

- Feldman / Pedersen VSS (or an equivalent) so parties can verify shares are consistent.
- Complaint/abort or blame mechanism when a share fails verification.

If there is no VSS in a multi-party setup, ask:

- What prevents a malicious dealer from distributing inconsistent shares?
- What prevents a malicious party from publishing invalid shares during decryption?

## 5) Encryption: KEM-DEM requirements

If the scheme encrypts bytes/strings:

- It is **KEM-DEM**: shared secret → KDF → symmetric key(s).
- The DEM is an **AEAD** (AES-GCM / ChaCha20-Poly1305), not XOR with a hash stream.
- `info` / AAD binds context:
  - protocol version + algorithm IDs
  - receiver identity / key ID
  - epoch/round (if applicable)
  - ciphertext domain separation labels.

If AEAD is absent, call out malleability and substitution risks.

## 6) Decryption: partial decryptions and proofs

For each party’s decryption share:

- Confirm it is computed from the correct ciphertext component (e.g., `d_i = c1^{s_i}`).
- Confirm the combiner uses correct Lagrange coefficients for the chosen subset.
- Confirm the system handles missing shares (timeouts / retries / subset selection).

If parties can be malicious, require a proof per share:

- Chaum–Pedersen / DLEQ-style proof that the share is consistent with the public key share.
- Batch verification if performance matters.

If the design has no verifiability, call out:

- denial-of-service by bogus shares
- “garbage plaintext” attacks where output becomes attacker-controlled.

## 7) Operational checklist

- Key rotation and key IDs: can you decrypt old ciphertexts after rotation?
- Audit logs: who requested decryption, which subset participated?
- Replay protection: are decryption shares bound to a specific ciphertext/round?
- Liveness: what happens if fewer than `t` parties are online?

## 8) Deliverable

Output:

1. A short paragraph: “What this code implements + which security properties it achieves”.
2. A bullet list of findings grouped by severity: **Critical / High / Medium / Low**.
3. For each Critical/High finding: a minimal patch suggestion or refactor plan.
4. A “Safe alternative” recommendation when appropriate (use a vetted library / protocol).

If you need more context, ask up to 3 questions (exactly what you need to decide correctness/security).

