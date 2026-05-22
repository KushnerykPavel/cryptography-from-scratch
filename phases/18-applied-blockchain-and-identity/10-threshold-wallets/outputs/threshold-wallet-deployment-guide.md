# Threshold Wallet Deployment Guide

## Phase 1: DKG Ceremony Setup

- [ ] Agree on parameters: threshold t, total parties n, prime field, curve (secp256k1 / Ed25519)
- [ ] Each party independently generates a random secret polynomial of degree t−1
- [ ] Each party produces a commitment to every polynomial coefficient: `C_ij = G^{a_ij}`
- [ ] Each party proves knowledge of the secret scalar `a_i0` via a Schnorr proof-of-possession (defends against rogue-key attacks)
- [ ] Commitments and proofs are broadcast to all parties over an authenticated channel
- [ ] Each party verifies all incoming proofs before proceeding

## Phase 2: Share Distribution

- [ ] Each party i sends share `f_i(j)` to party j over an encrypted, authenticated channel
- [ ] Each receiving party j verifies the share against the committed coefficients: `G^{f_i(j)} == Π_k C_{ik}^{j^k}`
- [ ] Any party that receives an invalid share broadcasts a complaint; the offending party must either reveal the correct share or be disqualified
- [ ] Each party computes its final secret share: `sk_j = Σ_i f_i(j) mod ORDER`
- [ ] The group public key is computed and cross-verified by all parties: `PK = Π_i C_{i0}`

## Phase 3: Key Verification

- [ ] All parties independently compute the group public key and confirm it matches
- [ ] A test signature is produced by a t-subset and verified against the group public key
- [ ] The group public key is published to the blockchain / distributed ledger
- [ ] Each party stores only its own secret share — the full secret key is never assembled

## Phase 4: Signing Quorum

- [ ] Define the signing policy: which t-of-n parties must approve each operation
- [ ] Establish a secure communication channel for signature rounds (authenticated broadcast)
- [ ] Round 1: each participating signer generates a fresh nonce and broadcasts its commitment
- [ ] Aggregate nonce is computed from all signers' commitments
- [ ] Round 2: each signer computes and broadcasts its partial signature
- [ ] Partial signatures are aggregated and the final signature is verified before broadcast

## Phase 5: Key Refresh (Proactive Security)

- [ ] Schedule periodic key refresh (e.g., every 30 days) to limit the window of share compromise
- [ ] Key refresh re-randomises all shares without changing the group public key
- [ ] Old shares are securely deleted after refresh completes and is verified
- [ ] At least t honest parties must participate in the refresh

## Phase 6: Operational Security

- [ ] Secret shares are stored in hardware security modules (HSMs) or secure enclaves
- [ ] Share backups are encrypted with a separate key held by a trusted recovery contact
- [ ] Audit logs record every signing request, participant set, and outcome
- [ ] Any party that fails to respond within timeout is flagged; signing continues with remaining quorum if ≥ t
- [ ] Signing quorum decisions require out-of-band confirmation (e.g., approval app, phone call)

## References

- FROST spec: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.txt
- ZcashFoundation/frost (Rust): https://github.com/ZcashFoundation/frost
- tss-lib (Go, GG20 ECDSA): https://github.com/bnb-chain/tss-lib
- Silence Laboratories DKLs23: https://github.com/silence-laboratories/silent-shard-dkls23
