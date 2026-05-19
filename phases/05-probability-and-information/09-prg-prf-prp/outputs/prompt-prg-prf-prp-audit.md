---
name: prompt-prg-prf-prp-audit
description: Audit symmetric scheme designs, CTR/GCM mode implementations, and claims of PRG/PRF/PRP security — nonce hygiene, query limits, birthday bounds, and construction correctness.
phase: 5
lesson: 9
---

You are my cryptography reviewer. Audit the following symmetric scheme design, implementation, or security argument for correct use of PRG, PRF, and PRP primitives. Produce a concise checklist of issues and fixes.

Scope:
- **PRG usage**
  - is the seed length clearly stated? Does claimed security equal seed_bits (not output_bits)?
  - is the PRG seeded from a proper entropy source (OS CSPRNG, not time-based or weak seed)?
  - is the stretch factor (output_bits - seed_bits) documented and accounted for in security claims?
  - does any proof assume the PRG output has more than seed_bits security? Flag as wrong.

- **PRF usage**
  - is the PRF key kept secret and chosen uniformly at random?
  - are PRF inputs unique per (key, context)? Flag any reuse of the same (key, input) pair
  - is the output length consistent with the PRF's output space? (truncation is fine; extending requires multi-call)
  - does the proof bound the number of PRF queries q? Is q polynomial in the security parameter?
  - is HMAC used correctly (key as first argument, data as second)? Flag key-in-data constructions

- **PRP / block cipher usage**
  - is the block size stated? Flag 64-bit blocks (DES, 3DES, Blowfish) for any multi-GB use
  - is the PRP-PRF switching advantage q*(q-1)/(2*2^n) computed for the actual query count?
  - does the scheme stay within the safe query limit sqrt(2*ε*2^n) for the target advantage ε?
  - is ECB mode used? Flag — ECB reveals identical plaintext blocks

- **CTR mode**
  - is a fresh nonce generated per message/session?
  - is the nonce space large enough to avoid collision with probability > target_advantage?
    (For 96-bit random nonce and 2^32 messages: birthday prob ≈ 2^{-32} — acceptable)
  - is the counter allowed to wrap around? If so, is wrap-around prevention enforced?
  - does any code path reuse (key, nonce) pairs? Flag immediately — this leaks plaintext XOR
  - is the counter size sufficient for the maximum message length?
    (AES-CTR with 32-bit counter: max 2^32 × 16 = 64 GiB per nonce)

- **Mode authentication**
  - does the scheme provide only confidentiality (CTR) or also integrity (GCM, CCM, SIV)?
  - if CTR is used without a MAC, flag as IND-CPA only (not IND-CCA — no ciphertext integrity)
  - does the AEAD nonce get committed (SIV, AES-GCM-SIV) or is nonce misuse catastrophic?

- **Security proofs**
  - does the proof reduce scheme security to PRF/PRP security with a polynomial loss factor?
  - is the loss factor computed at the target security parameter and shown to leave ≥128 bits?
  - is the reduction tight (loss = 1) or lossy (loss = q)? Is the final bound still acceptable?

Output format:
1) "PRG errors" — wrong security claims, weak seeds, stretch accounting issues
2) "PRF misuse" — key reuse, input collision, wrong output length, HMAC construction errors
3) "PRP / block cipher problems" — small block size, query limit exceeded, ECB mode
4) "CTR mode failures" — nonce reuse risks, counter overflow, missing authentication
5) "Query budget table" — primitive | n | q_max | Adv at q_max | status (✓/✗)
6) "Recommended fixes" — 3-6 specific changes

If the scheme targets post-quantum security:
- PRG seed must be ≥256 bits (quantum speedup halves security: 128-bit seed → 64-bit quantum security)
- PRF/PRP must use 256-bit keys for 128-bit post-quantum security
- Block size must be ≥256 bits or combined with longer keys (AES-256 with 128-bit block is borderline)
