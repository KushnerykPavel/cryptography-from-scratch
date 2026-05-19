# Birthday Bound & Generic Attacks

> Any n-bit hash or cipher is broken in 2^{n/2} work by the birthday attack — not 2^n.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 05 · 01 (Probability Basics) · 04 (Computational Indistinguishability) · 09 (PRG/PRF/PRP)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- State the birthday bound: collision probability ≈ q²/(2·2^n) after q draws from a 2^n space.
- Compute collision and preimage expected query counts: 2^{n/2} and 2^n respectively.
- Explain why n-bit hash output gives only n/2-bit collision security.
- Apply meet-in-the-middle to show double encryption has k-bit security, not 2k-bit.
- Calculate multi-target advantage q·k/2^n and apply it to password-database scenarios.

## The Problem

MD5 was designed with 128-bit output — you might expect 128-bit collision resistance. But MD5 collisions were found in 2004 using only 2^17 operations. SHA-1 was 160 bits; SHAttered (2017) found a collision in 2^61 operations. 3DES uses 168-bit keys but is only 112-bit secure against key recovery.

The culprit is the birthday bound: every n-bit collision-resistant primitive breaks in 2^{n/2} generic queries, not 2^n. Without this, you will routinely overestimate the security of hash functions, block cipher modes, nonce schemes, and double encryption. Every practical security parameter choice depends on the birthday bound.

## The Concept

### The birthday problem

In a room of k people, what is the probability that two share a birthday?

```
P(collision | k people, N = 365 days) = 1 - (365/365) · (364/365) · ... · (365-k+1)/365)
```

At k = 23 people: P ≈ 0.507 — over 50%. With only 23 people drawn from 365 slots.

### Birthday bound for cryptography

Generalise: q random draws from a space of size N = 2^n.

**Exact formula:**
```
P(collision) = 1 - ∏_{k=1}^{q-1} (1 - k/2^n)
```

**Upper bound (union bound):**
```
P(collision) ≤ q(q-1) / (2 · 2^n)
```

**Exponential approximation (Poisson model):**
```
P(collision) ≈ 1 - exp(-q(q-1) / (2 · 2^n))
```

**50% collision threshold:**
```
q_50% ≈ sqrt(2 · ln(2) · 2^n) ≈ 1.177 · 2^(n/2)
```

So a collision is expected after roughly `2^(n/2)` queries — halving the security exponent.

### Generic attacks

| Attack | Target | Expected queries | Space |
|--------|--------|-----------------|-------|
| Preimage | Find x with H(x) = y | 2^n | O(1) |
| Second preimage | Find x' ≠ x with H(x') = H(x) | 2^n | O(1) |
| Collision | Find any x ≠ y with H(x) = H(y) | 2^{n/2} | 2^{n/2} |

These bounds are **generic** — they apply to any hash function, PRF, or permutation that behaves like a random function. No assumption about structure is required.

### Multi-target attacks

If the adversary can attack any of k targets simultaneously:

```
Adv(q queries, k targets) ≤ q · k / 2^n
```

With k = 2^20 targets and q = 2^60 queries against SHA-256 (n=256):
```
Adv ≤ 2^60 · 2^20 / 2^256 = 2^{-176}   (still negligible)
```

Multi-target matters for password databases (k = number of accounts), multi-user security proofs (k = number of users), and BREACH/BEAST-style attacks.

### Meet-in-the-middle: double encryption is not 2k-bit secure

Double encryption: `C = E_{k2}(E_{k1}(P))` with k1, k2 each `b` bits.

Naive hope: 2b bits of security. Reality: `b` bits via meet-in-the-middle:

```
1. Build table: for all k1, compute E_{k1}(P) → store (value, k1).   [2^b entries]
2. For all k2, compute D_{k2}(C) → look up match in table.
3. Any matching pair (k1, k2) is a candidate key.
```

Time: `2 · 2^b`.  Space: `2^b`.  Effective security: `b`, not `2b`.

This is why 2-DES (using two 56-bit DES keys) is only 56-bit secure — the nominal 112 bits collapse.

### The n_bits / 2 rule

| Primitive | Output/block bits | Collision security | Preimage security |
|-----------|-------------------|-------------------|-------------------|
| MD5 | 128 | 64 (theoretical) → 17 (practical) | 128 |
| SHA-1 | 160 | 80 → 61 (SHAttered) | 160 |
| SHA-256 | 256 | 128 | 256 |
| SHA-512 | 512 | 256 | 512 |
| AES-128 (block) | 128 | 64 (Sweet32 for 64-bit) | N/A |
| 3DES (block 64) | 64 | 32 | N/A |

The practical attacks beat the theoretical bound because real hash functions have structure. The birthday bound is the **floor** — a generic adversary cannot do better; a cryptanalyst may do worse.

## Build It

### Step 1: exact and approximate birthday probability

```python
def birthday_collision_prob_exact(q, space_size):
    if q <= 1: return 0.0
    log_p = sum(math.log1p(-k / space_size) for k in range(1, q))
    return 1.0 - math.exp(log_p)

def birthday_collision_prob_approx(q, n_bits):
    return q * (q - 1) / (2.0 * 2.0 ** n_bits)   # upper bound
```

### Step 2: query thresholds

```python
def collision_threshold(n_bits, *, target_prob=0.5):
    return math.sqrt(-2.0 * (2.0 ** n_bits) * math.log1p(-target_prob))

def preimage_expected_queries(n_bits):
    return 2.0 ** n_bits          # each query hits with prob 2^{-n}

def collision_expected_queries(n_bits):
    return math.sqrt(math.pi / 2.0 * 2.0 ** n_bits)   # ≈ 1.253 · 2^{n/2}

def security_bits_after_birthday(n_bits):
    return n_bits / 2.0
```

### Step 3: multi-target and meet-in-the-middle

```python
def multi_target_advantage(q, k_targets, n_bits):
    return q * k_targets / (2.0 ** n_bits)   # union bound over k targets

def meet_in_the_middle_cost(key_bits_per_half):
    return {
        "nominal_key_bits":      2 * key_bits_per_half,
        "effective_security_bits": key_bits_per_half,
        "time_complexity":       2.0 ** key_bits_per_half,
    }
```

Double encryption has `k`-bit security, not `2k`-bit. Build a table of `E_{k1}(P)` for all `k1`; look up `D_{k2}(C)` for all `k2`.

### Step 4: simulated birthday attack

```python
def simulate_birthday_attack(hash_fn, n_bits, max_queries, *, rng=None):
    seen = {}
    for _ in range(max_queries):
        x = rng.getrandbits(64)
        h = hash_fn(x) & ((1 << n_bits) - 1)
        if h in seen and seen[h] != x:
            return (seen[h], x)
        seen[h] = x
    return None
```

Run it:

```
python3 code/main.py
```

## Use It

The birthday bound determines:

- **Hash output length**: SHA-256 gives 128-bit collision resistance (n/2 = 128). SHA-512 gives 256-bit.
- **Block cipher query limits**: AES-128 in CTR mode — limit queries to 2^48 blocks per key for a birthday-safe 2^{-32} advantage bound (PRP-PRF switching lemma).
- **Nonce space**: AES-GCM with 96-bit random nonce — after 2^32 messages, collision probability ≈ 2^{-33} (acceptable). After 2^48: ≈ 2^{-1} (catastrophic).
- **Password hashing**: bcrypt outputs 184 bits but security is bounded by the password entropy, not the output length.
- **Key agreement**: Diffie-Hellman 2048-bit (≈112-bit security via GNFS, not birthday) — no birthday issue because the output is a key, not random-looking hash output.

## Attack It

**Sweet32 (2016)**: Both 3DES (64-bit block) and Blowfish (64-bit block) break after 2^32 blocks (~32 GB) of data with the same key, because:

```
collision_threshold(64 bits, 0.5) ≈ 2^32 blocks
```

An attacker who can observe 32 GB of ciphertext encrypted under the same key can find two blocks with the same ciphertext — revealing the XOR of two plaintexts, which (with HTTP header knowledge) leaks session cookies. The attack was demonstrated live against HTTPS with 3DES.

Fix: use AES (128-bit block) and retire 3DES. Per NIST SP 800-131Ar2, 3DES is deprecated.

## Ship It

This lesson ships a reusable birthday-bound calculator prompt:

- `outputs/prompt-birthday-audit.md`

Use it when evaluating hash output lengths, block cipher query limits, nonce space design, or any claimed security parameter.

## Exercises

1. Easy: how many queries does an adversary need to find a collision in a 32-bit hash with 50% probability? With 99% probability? Use `collision_threshold`.

2. Medium: a protocol sends 2^40 AES-128-GCM packets under the same key with random 96-bit nonces. Compute the probability of a nonce collision. Is it acceptable at a 2^{-32} advantage target?

3. Hard: implement the meet-in-the-middle attack on a toy "double cipher" `C = E_{k2}(E_{k1}(P))` where `E_k(x) = (x + k) mod 2^16`. Show it recovers (k1, k2) in `O(2^8)` time and space instead of `O(2^{16})`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| birthday bound | "square-root attack" | collision after ~2^{n/2} queries; halves exponent |
| collision | "hash clash" | two distinct inputs with the same output |
| preimage | "inversion" | find any x with H(x) = y; costs 2^n |
| second preimage | "targeted collision" | given x, find x'≠x with H(x')=H(x); costs 2^n |
| multi-target | "attack many at once" | k targets multiply advantage: q*k/2^n |
| meet-in-the-middle | "time-space tradeoff" | double-enc security = k bits, not 2k bits |
| Sweet32 | "block collision" | 64-bit block → 2^32 block limit per key |
| generic attack | "no structure needed" | preimage/collision bounds apply to any random-like function |

## Test Vectors

Source: exact birthday formula (log-sum), approximation q*(q-1)/(2*2^n), Poisson exponential, collision_threshold from sqrt formula, preimage/collision expected values, multi-target union bound.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Flajolet & Odlyzko, "Random Mapping Statistics" (1990)](https://link.springer.com/chapter/10.1007/3-540-46885-4_34) — exact birthday problem analysis
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*, §7.1](https://toc.cryptobook.us/) — collision and preimage bounds, multi-target
- [Katz & Lindell, *Introduction to Modern Cryptography*, §4.1](https://www.cs.umd.edu/~jkatz/imc.html) — generic attacks on hash functions
- [Sweet32 paper (Bhargavan & Leurent, 2016)](https://sweet32.info/) — birthday attack on 64-bit block ciphers in TLS
- [NIST SP 800-107r1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf) — security considerations for hash functions
