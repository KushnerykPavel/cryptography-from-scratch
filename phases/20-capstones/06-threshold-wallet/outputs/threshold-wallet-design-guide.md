---
phase: 20
lesson: 06
title: Threshold Wallet Architecture — Design Guide
---

# Threshold Wallet Architecture — Design Guide

A reusable reference for teams evaluating or building threshold (MPC) wallet systems.

---

## 1. Choosing Your (t, n) Parameters

| Configuration | Availability | Security | Typical Use Case |
|---------------|-------------|----------|-----------------|
| 1-of-n | Any single party suffices | No threshold protection | Hot wallet convenience key |
| 2-of-3 | 2 parties needed; 1 can be offline | Tolerates 1 compromise | Personal MPC wallet, small team |
| 3-of-5 | 3 parties needed; 2 can be offline | Tolerates 2 compromises | Exchange hot wallet, DAO treasury |
| m-of-2m-1 | Majority required | Tolerates up to m-1 compromises | Validator committee, HSM cluster |
| n-of-n | All parties must sign | No fault tolerance | Atomic swap finalization |

**Key tradeoffs:**
- Higher t means stronger security but more liveness risk (more parties must be reachable to sign).
- Lower t means easier signing but a smaller attack surface for an adversary to cross.
- For custody, a common production choice is 3-of-5 with geographic distribution of the 5 parties.

---

## 2. DKG Protocol Selection

### When to use Pedersen DKG (simplified, this lesson)
- Learning / prototyping.
- Synchronous network with authenticated broadcast.
- All parties are trusted (no malicious adversary assumed).

### When to use Pedersen DKG with VSS (Verifiable Secret Sharing)
- Semi-honest adversary model.
- Parties may make mistakes; each share should be verifiable against the dealer's commitment.
- Implementation: publish Feldman commitments `C_{ik} = g^(a_{ik})` alongside shares. Recipients verify `g^(f_i(j)) == product(C_{ik}^(j^k))`.

### When to use Secure DKG (e.g., GJKR / Canetti-Gennaro)
- Malicious adversary model.
- Any party may submit inconsistent shares or biased secrets.
- Adds zero-knowledge proofs of knowledge for each commitment.
- Higher round complexity (3+ rounds vs. 2).

### Rushing attack note
In the naive Pedersen DKG, a malicious last party can abort after seeing all others' commitments `X_i` and retry until the aggregate key has some desired property. Mitigate with a commit-then-reveal structure: all parties first broadcast a hash of their commitment, then reveal; a party that does not reveal is excluded.

---

## 3. Threshold Signing Protocol Selection

### Threshold Schnorr

| Protocol | Rounds | Security Model | Notes |
|----------|--------|---------------|-------|
| Simplified (this lesson) | 1 | Semi-honest | Vulnerable to nonce reuse, rushing |
| FROST (Komlo & Goldberg 2020) | 2 | Malicious, ROM | Production standard for ed25519/secp256k1 Schnorr |
| MuSig2 (Nick et al. 2021) | 2 | Malicious, AOMDL | t=n only; simpler than FROST |

**FROST round summary:**
- Round 1 (pre-processing): each signer generates nonce pairs `(d_i, e_i)` and broadcasts commitments `(D_i, E_i) = (g^d_i, g^e_i)`.
- Round 2 (signing): after the message is known, each signer computes a binding factor `rho_i = H(i, msg, {D_j, E_j})`, nonce `R_i = D_i * E_i^rho_i`, aggregate `R`, challenge `e`, partial response `z_i = d_i + e_i*rho_i - lambda_i * x_i * e`.

### Threshold ECDSA

| Protocol | Notes |
|----------|-------|
| GG18 / GG20 | First practical threshold ECDSA; used by Binance TSS, many exchanges |
| CGGMP21 | Improved GG20; stronger proofs, used in newer MPC wallets |
| Doerner-Shelat (2-of-2) | Efficient 2-party ECDSA using OT extension |

ECDSA threshold is significantly more complex because `s = k^{-1}(z + rx)` involves a product of secret values. Protocols use multiplicative-to-additive (MtA) share conversion via oblivious transfer or Paillier encryption.

---

## 4. Key Refresh and Share Rotation

A threshold wallet should support periodic key refresh: re-randomize all shares without changing the aggregate public key. This limits the damage from a slow share compromise and is part of proactive security.

**Approach:**
1. Each party generates a new random additive mask `delta_i` with `sum(delta_i) = 0 mod q`.
2. Shamir-share each `delta_i` among all parties.
3. Each party adds the received delta shares to its current share.
4. The aggregate key is unchanged because `sum(delta_i) = 0`.

Frequency: rotate on a schedule (e.g., weekly) or after any suspected compromise event.

---

## 5. Security Considerations Checklist

- [ ] **Nonce uniqueness**: never reuse `k` across signing sessions. Use CSPRNG or deterministic derivation per session.
- [ ] **Authenticated channels**: all inter-party messages must be authenticated (e.g., signatures or MACs under long-term keys) to prevent man-in-the-middle attacks during signing rounds.
- [ ] **Share storage**: shares must be stored with the same security level as a private key — encrypted at rest, access-controlled, and ideally in an HSM or secure enclave.
- [ ] **Threshold for key operations**: both signing and DKG should require the same threshold `t`; do not use a lower threshold for "convenience" operations.
- [ ] **Abort handling**: define what happens when a party goes offline mid-protocol. FROST and most production protocols are identifiable abort — they produce a proof of which party misbehaved.
- [ ] **Commitment scheme**: in DKG, use commit-then-reveal for public key broadcasts to prevent rushing attacks.
- [ ] **VSS verification**: after DKG, every party should verify its received shares against the dealer's public polynomial commitments before accepting them.
- [ ] **Key refresh cadence**: rotate shares at least annually or after any security incident.
- [ ] **Audit log**: record which parties participated in each signing session (not the nonces or partial sigs — just the participant set and timestamp).

---

## 6. Production Library Reference

| Language | Library | Protocol | Notes |
|----------|---------|---------|-------|
| Rust | `frost-dalek`, `frost-core` (ZF) | FROST | Reference FROST implementation by Zcash Foundation |
| Go | `tss-lib` (bnb-chain) | GG20 | Used by Binance; supports ECDSA and EdDSA |
| Rust | `multi-party-ecdsa` (ZenGo) | GG20 / CGGMP21 | Powers ZenGo MPC wallet |
| TypeScript | `@tkey/core` (Torus) | Shamir + 2-of-n | Web-focused; integrates with OAuth recovery |
| Python | none production-grade | — | Use Rust/Go libs via FFI or subprocess for production |

---

## 7. Comparison: On-chain Multi-sig vs. MPC Threshold

| Property | On-chain Multi-sig (e.g., Bitcoin P2SH, Ethereum Gnosis Safe) | MPC Threshold Wallet |
|----------|--------------------------------------------------------------|---------------------|
| Signature count on chain | n separate signatures stored | Single aggregate signature |
| Privacy | Observer can see t-of-n policy | Policy is invisible; looks like a normal key |
| Gas cost (EVM) | Linear in n | Constant — one signature |
| Key generation | Each party generates own key independently | Requires DKG round |
| Key recovery | Each party's key is standard and recoverable | Share recovery requires protocol support |
| Trust model | Smart contract enforces policy | Cryptographic protocol enforces policy |
| Complexity | Low (well-understood) | High (requires correct MPC implementation) |

For most teams: use on-chain multi-sig for simplicity unless privacy or gas cost is a hard requirement, in which case invest in a well-audited MPC library.
