# Pseudorandomness — PRG, PRF, PRP

> A pseudorandom generator stretches a seed; a pseudorandom function fakes a random table; a pseudorandom permutation fakes a random bijection — and each is the building block for the next.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 05 · 04 (Computational Indistinguishability) · 06 (Negligible Functions & Reductions) · 07 (Random Oracle Model)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Distinguish PRG, PRF, and PRP by their security games and structural properties.
- Explain why PRG security equals seed security regardless of output length.
- Compute the PRP-PRF switching advantage q(q-1)/(2·2^n) and derive the safe query limit.
- Implement CTR mode from a PRF and demonstrate that nonce reuse leaks plaintext XOR.
- Place the hierarchy OWF → PRG → PRF → PRP and name the construction at each step.

## The Problem

Every symmetric cryptographic scheme — stream ciphers, block ciphers, MACs, AEAD — reduces to one of three primitives: PRG, PRF, or PRP. Security proofs for AES-GCM, ChaCha20-Poly1305, and HMAC all say "assuming the underlying PRF/PRP is secure". Without knowing what PRG, PRF, and PRP mean precisely, you cannot:

- Verify security claims for any symmetric scheme.
- Understand why nonce reuse breaks CTR mode.
- Know why a 64-bit block cipher (DES) cannot be used securely with more than 2^32 messages.
- Understand the PRP-PRF switching lemma that governs birthday bounds for block ciphers.

This lesson builds toy implementations of all three and gives you the formulas to compute their concrete security bounds.

## The Concept

### Pseudorandom Generator (PRG)

```
G : {0,1}^n  →  {0,1}^{n+l}        (l > 0: the stretch)
```

A PRG stretches a short **seed** to a longer **output**. Security: no PPT distinguisher can tell `G(k)` from a truly uniform string of the same length.

Key fact: **stretching does not add security**. A 128-bit seed gives 128-bit security no matter how many bytes you produce. The output is long but not more secret.

Construction: feed the seed into a hash function in counter mode:
```
G(seed) = H(seed || 0) || H(seed || 1) || …
```

### Pseudorandom Function (PRF)

```
F : {0,1}^λ × {0,1}^n  →  {0,1}^m    (key × input → output)
```

For each key `k`, `F(k, ·)` is computationally indistinguishable from a truly random function `f : {0,1}^n → {0,1}^m`.

Security game:
```
Challenger has either F(k, ·) for random k, or a random function f.
Distinguisher makes q adaptive queries.
Advantage = |Pr[D=1 | F(k,·)] - Pr[D=1 | f]| ≤ negl(λ)
```

Practical PRFs: HMAC-SHA256 (key-then-data), AES in a keyed mode, BLAKE3.

### Pseudorandom Permutation (PRP)

```
E : {0,1}^λ × {0,1}^n  →  {0,1}^n    (bijective in second argument)
```

For each key `k`, `E(k, ·)` is a permutation (bijection) that is computationally indistinguishable from a uniformly random permutation. The inverse `E^{-1}(k, ·)` also exists and is efficiently computable.

Practical PRPs: AES-128 (n=128), AES-256 (n=128 block, 256-bit key), ChaCha20 (stream cipher, but PRP-like in CTR blocks).

### PRP-PRF switching lemma

A PRP is "almost" a PRF. After `q` queries, the advantage of distinguishing them is:

```
Adv_switch(q, n) ≤ q(q-1) / (2 · 2^n) ≈ q² / 2^(n+1)
```

This is the birthday bound again. Consequences:
- AES-128 (n=128): stay below 2^64 encryptions for birthday-safe PRP-PRF interchangeability.
- AES-GCM with 128-bit counter: ~2^32 block limit per nonce for a concrete 2^{-32} advantage bound.
- DES (n=64): safe query limit is 2^{32} — reached quickly in practice (deprecated for this reason).

### The hierarchy

```
OWF ──► PRG ──► PRF ──► PRP
```

- PRG from PRF: counter mode `G(k) = F(k, 0) || F(k, 1) || …`
- PRF from PRG: GGM tree construction (not shown here)
- PRP from PRF: 3-round Feistel (Luby-Rackoff theorem)
- Practical: AES is directly assumed to be a PRP; HMAC is directly assumed PRF.

### CTR mode: PRF → stream cipher

```
Enc(k, nonce, m) = m XOR (F(k, nonce||0) || F(k, nonce||1) || …)
```

Security: if F is a PRF, CTR mode achieves IND-CPA (indistinguishability under chosen-plaintext attack). The PRF outputs are the keystream; XOR-ing with plaintext destroys any structure an adversary could exploit.

**Nonce reuse breaks everything**: if two messages are encrypted with the same `(key, nonce)`, their keystreams are identical, and XOR-ing the two ciphertexts reveals the XOR of the plaintexts.

## Build It

### Step 1: toy PRG (counter-mode SHA-256)

```python
def toy_prg(seed: bytes, output_bytes: int) -> bytes:
    blocks, counter = [], 0
    while len(b"".join(blocks)) < output_bytes:
        blocks.append(hashlib.sha256(seed + struct.pack(">Q", counter)).digest())
        counter += 1
    return b"".join(blocks)[:output_bytes]
```

Security = seed bits regardless of `output_bytes`. Stretch does not add entropy.

### Step 2: toy PRF (HMAC-SHA-256)

```python
def toy_prf(key: bytes, x: bytes) -> bytes:
    return hmac.new(key, x, hashlib.sha256).digest()
```

Keyed by `key`; looks random for each input `x` to anyone who does not know `key`.

### Step 3: toy PRP (4-round balanced Feistel)

```python
def toy_prp_encrypt(key: bytes, plaintext: bytes, n_rounds: int = 4) -> bytes:
    h = len(plaintext) // 2
    L, R = bytearray(plaintext[:h]), bytearray(plaintext[h:])
    for i in range(n_rounds):
        f = hashlib.sha256(key + struct.pack(">I", i) + bytes(R)).digest()[:h]
        L, R = R, bytearray(a ^ b for a, b in zip(L, f))
    return bytes(L) + bytes(R)
```

Bijective for any fixed key. Luby-Rackoff: 3 rounds suffice for PRP security.

### Step 4: CTR mode

```python
def ctr_mode_encrypt(key, nonce, plaintext, prf_fn=toy_prf):
    result = bytearray()
    for i, chunk in enumerate(chunks(plaintext, 32)):
        ks = prf_fn(key, struct.pack(">QQ", nonce, i))
        result.extend(a ^ b for a, b in zip(chunk, ks))
    return bytes(result)
```

### Step 5: PRP-PRF switching advantage

```python
def prp_prf_switching_advantage(q, block_bits):
    return q * (q - 1) / (2.0 * 2.0 ** block_bits)

def safe_query_limit(block_bits, target_advantage=2**-32):
    return int(math.sqrt(2.0 * target_advantage * 2.0 ** block_bits))
```

Run it:

```
python3 code/main.py
```

## Use It

| This lesson | Production equivalent |
|-------------|----------------------|
| `toy_prg(seed, n)` | `os.urandom(n)` (OS CSPRNG) or ChaCha20 in CTR |
| `toy_prf(key, x)` | `hmac.new(key, x, sha256).digest()` (this IS the standard) |
| `toy_prp_encrypt(key, block)` | `Cipher(AES(key), ECB).encrypt(block)` |
| `ctr_mode_encrypt(...)` | `Cipher(AES(key), CTR(nonce)).encrypt(msg)` |

`toy_prf` is actually production-grade HMAC-SHA256 — the "toy" label refers to the simplicity of use, not the underlying primitive. The Feistel PRP is educational; use AES for real block cipher needs.

## Attack It

**Nonce reuse in CTR mode:**

```python
key = b"shared-key-32b!!"
nonce = 0  # reused for both messages
ct1 = ctr_mode_encrypt(key, nonce, b"Attack at dawn!!")
ct2 = ctr_mode_encrypt(key, nonce, b"Attack at dusk!!")
xor_ct = xor(ct1, ct2)  # = plaintext1 XOR plaintext2 — leaks both
```

Given `ct1 XOR ct2 = m1 XOR m2`, an adversary with any knowledge of `m1`
can recover `m2` entirely. This is why:
- TLS generates a fresh nonce per record.
- AES-GCM counters must never repeat.
- ChaCha20-Poly1305 uses a 96-bit random nonce (collision probability ~2^{-32} for 2^32 messages).

**Birthday attack on a 64-bit PRP (DES):**

After `q = 2^32` DES encryptions with the same key, the PRP-PRF switching advantage exceeds 0.5. An adversary observing `q` (ciphertext, plaintext) pairs can distinguish DES from a random permutation — and extract information about the key. This is the Sweet32 attack on 3DES and Blowfish.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-prg-prf-prp-audit.md`

Use it when reviewing symmetric scheme designs, CTR/GCM mode implementations, or any claim that "uses a PRF/PRP securely".

## Exercises

1. Easy: compute the PRP-PRF switching advantage for AES-128 after 2^32, 2^48, and 2^64 queries. At what query count does the advantage exceed 2^{-32}?

2. Medium: implement `prf_to_prg` (counter-mode PRG from a PRF). Show that its output passes the same distinguishing tests as `toy_prg`. Compare the first 32 bytes when the PRF key = SHA-256(seed).

3. Hard: implement the `toy_prp_decrypt` inverse and verify that it is the exact inverse of `toy_prp_encrypt` for all 2^16 possible 2-byte plaintexts with a fixed key. Then implement a chosen-plaintext attack against a 1-round Feistel — show it does not satisfy PRP security.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| PRG | "stream cipher" | stretches n-bit seed to longer output; indistinguishable from uniform |
| PRF | "keyed hash" | `F(k, ·)` indistinguishable from random function for unknown k |
| PRP | "block cipher" | bijective PRF; indistinguishable from random permutation |
| stretch | "expansion" | l = output_bits - seed_bits; does not add security |
| PRP-PRF switching | "birthday loss" | Adv_switch ≤ q²/2^(n+1); dominant for block cipher modes |
| CTR mode | "stream from block" | XOR plaintext with PRF(k, nonce||i) per block; IND-CPA secure |
| nonce reuse | "catastrophic" | same (k, nonce) pair → same keystream → plaintext XOR leaks |
| safe query limit | "block cipher lifespan" | q ≤ sqrt(2·ε·2^n) for birthday advantage ≤ ε |

## Test Vectors

Source: SHA-256 (toy_prg), HMAC-SHA256 (toy_prf, toy_prf_n), 4-round Feistel (toy_prp), HMAC-based CTR mode. All with zero-byte keys/seeds.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Goldreich, *Foundations of Cryptography, Vol. 1*, §3.3–3.6](https://www.wisdom.weizmann.ac.il/~oded/foc-vol1.html) — PRG, PRF, PRP hierarchy
- [Boneh & Shoup, *A Graduate Course in Applied Cryptography*, Ch. 4–5](https://toc.cryptobook.us/) — PRF/PRP security, CTR mode, GCM
- [Katz & Lindell, *Introduction to Modern Cryptography*, Ch. 6–7](https://www.cs.umd.edu/~jkatz/imc.html) — stream ciphers, block ciphers, PRF/PRP
- [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) — CTR, CBC, and other block cipher modes
- [Sweet32 attack paper](https://sweet32.info/) — birthday attack on 64-bit block ciphers
