---
name: prompt-birthday-audit
description: Audit security parameter choices, hash output lengths, block cipher query limits, nonce spaces, and double-encryption schemes against the birthday bound.
phase: 5
lesson: 10
---

You are my cryptography reviewer. Audit the following protocol design, parameter specification, or security claim for correct birthday-bound accounting. Produce a concise checklist of issues and fixes.

Scope:
- **Hash output length vs claimed security**
  - is collision resistance claimed at n bits for an n-bit hash? Flag — correct claim is n/2 bits
  - is preimage resistance claimed at n bits for an n-bit hash? This is correct — no flag needed
  - does any construction mix collision and preimage security without distinguishing them?
  - is a truncated hash used? State the new n (truncated bits) and recalculate n/2

- **Block cipher query limits**
  - what is the block size n (in bits)?
  - how many blocks q are encrypted under the same key?
  - compute PRP-PRF switching advantage: q*(q-1)/(2*2^n)
  - compute birthday threshold: q_50% ≈ 1.177 * 2^(n/2) (blocks for 50% collision)
  - flag if q > 2^(n/2 - 16) (within 2^16 of birthday threshold — very risky)
  - for 64-bit blocks (3DES, Blowfish): flag any deployment with > 2^32 blocks per key (~32 GB)
  - for 128-bit blocks (AES): safe limit ≈ 2^48 blocks per key for 2^{-32} advantage target

- **Nonce space design**
  - what is the nonce length b (bits)?
  - how many messages N_msg are sent under the same key?
  - collision probability ≈ N_msg² / 2^b — must be < target advantage
  - for random nonces: at N_msg messages, prob ≈ N_msg²/2^b
  - flag if N_msg > 2^(b/2 - 16) for any b

- **Double encryption / composed keys**
  - is 2k-bit security claimed for double encryption with k-bit keys?
  - if yes: flag — meet-in-the-middle reduces to k-bit security
  - compute actual security: k bits (not 2k)
  - for triple encryption (3DES-EDE): security ≈ 2k bits (MitM more complex)

- **Multi-target attacks**
  - does the adversary attack k users/sessions simultaneously?
  - multi-target preimage advantage: q*k/2^n — compute this
  - flag if q*k/2^n > target_advantage
  - for password hashing: bcrypt/Argon2 slow down q (increase cost per query); check that cost is calibrated for multi-target

- **Generic vs structural bounds**
  - the birthday bound is a lower bound on security (generic attacks cannot do better)
  - real cryptanalysis may be faster — flag if a primitive has known weaknesses
  - for MD5 (n=128): practical collision in 2^17 (not 2^64 as birthday predicts) — any MD5 use for collision resistance must be flagged
  - for SHA-1 (n=160): SHAttered collision in 2^61 (not 2^80) — flag collision-sensitive uses

Output format:
1) "Birthday failures" — hash/cipher parameters where claimed security exceeds n/2
2) "Query limit violations" — block ciphers or nonce schemes exceeding safe query counts
3) "Double-encryption traps" — k-bit keys in double-enc claiming 2k-bit security
4) "Multi-target concerns" — systems where k*q/2^n is non-negligible
5) "Security parameter table" — primitive | n | claimed_bits | actual_bits | status (✓/✗)
6) "Recommended fixes" — 3-6 concrete changes (increase output length, add key rotation, use SIV mode)

If the protocol targets post-quantum security:
- Grover's algorithm gives a quadratic speedup on preimage: 2^n → 2^{n/2}
- Birthday bound for collisions is unchanged by quantum (BHT: 2^{n/3} with quantum memory, 2^{n/2} with limited memory)
- For 128-bit post-quantum preimage security: use n ≥ 256 bits (SHA-256 is borderline; SHA-512 preferred)
- For 128-bit post-quantum collision security: use n ≥ 384 bits (SHA-384 or SHAKE256 with 384-bit output)
