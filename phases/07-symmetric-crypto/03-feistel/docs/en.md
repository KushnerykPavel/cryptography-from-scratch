# Block Ciphers — Feistel Networks
> Swap halves and XOR with a keyed function — invertible by construction.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 07 · 01 (One-Time Pad), Phase 07 · 02 (Stream Ciphers)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why a Feistel round is invertible even if `F` is not
- **Compute** one Feistel round by hand on a small block
- **Implement** Feistel encrypt/decrypt for fixed-size blocks in Python
- **Distinguish** Feistel networks from SPNs (e.g., AES) at a design level
- **Apply** a practical checklist to avoid “toy cipher” mistakes (too few rounds, weak `F`, bad key schedule)

## The Problem
You want a **block cipher-like primitive**: a keyed permutation over fixed-size blocks (e.g., 64-bit or 128-bit) so you can later build modes of operation (CBC/CTR/GCM), format-preserving transforms, or deterministic encrypt-then-MAC constructions.

The hard part isn’t writing code — it’s designing something that is both **invertible** (so decryption exists) and **diffusive** (so every output bit depends on many input bits) without accidentally making it trivially breakable. If you try to “just hash and XOR some bytes”, you typically end up with something that isn’t a permutation or is easy to distinguish from random.

Feistel networks are one of the two classic blueprints (the other is the substitution–permutation network, SPN) that turn a simple mixing rule into an invertible permutation. DES is a Feistel cipher. Learning Feistel gives you a mental model for why “rounds + diffusion” is the core idea behind practical block ciphers.

## The Concept
A Feistel network operates on a block split into two halves `(L, R)`.

One round takes:

```
L_{i+1} = R_i
R_{i+1} = L_i XOR F(K_i, R_i)
```

Key idea: **decryption uses the same round function** — you just apply the round keys in reverse order. You never need to invert `F`.

### Why it’s invertible (the trick)
Given `(L_{i+1}, R_{i+1})`, you can recover:

```
R_i = L_{i+1}
L_i = R_{i+1} XOR F(K_i, R_i)
```

So as long as XOR works and you can compute `F`, the round is reversible.

### Rounds and diffusion
One or two rounds do not “mix enough”. With more rounds, a single-bit change in the plaintext should flip roughly half the ciphertext bits (the **avalanche effect**). That doesn’t prove security, but it’s a minimum bar for “not obviously broken”.

## Build It

### Step 1: Split and join a block
Implement helpers that treat a `block_bits`-wide integer as two `half_bits` halves.

```python
class FeistelError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FeistelError(message)


def int_to_bytes(x: int, length: int) -> bytes:
    _require(x >= 0, "x must be non-negative")
    _require(length >= 0, "length must be non-negative")
    return x.to_bytes(length, byteorder="big", signed=False)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def split_block(block: int, block_bits: int) -> tuple[int, int]:
    _require(block_bits > 0, "block_bits must be positive")
    _require(block_bits % 2 == 0, "block_bits must be even")
    _require(0 <= block < (1 << block_bits), "block out of range for block_bits")
    half_bits = block_bits // 2
    right = block & ((1 << half_bits) - 1)
    left = block >> half_bits
    return left, right


def join_block(left: int, right: int, block_bits: int) -> int:
    _require(block_bits > 0, "block_bits must be positive")
    _require(block_bits % 2 == 0, "block_bits must be even")
    half_bits = block_bits // 2
    _require(0 <= left < (1 << half_bits), "left out of range for half_bits")
    _require(0 <= right < (1 << half_bits), "right out of range for half_bits")
    return (left << half_bits) | right
```

This makes the rest of the lesson easier: encryption/decryption will be defined over `(L, R)` halves rather than raw bytes.

### Step 2: A round function F
Use HMAC-SHA256 as a “PRF-ish” building block, then truncate to `half_bits`.

```python
def derive_round_keys(master_key: bytes, rounds: int) -> list[bytes]:
    _require(isinstance(master_key, (bytes, bytearray)), "master_key must be bytes-like")
    _require(rounds > 0, "rounds must be positive")
    mk = bytes(master_key)
    out: list[bytes] = []
    for r in range(1, rounds + 1):
        msg = b"feistel-round-key" + r.to_bytes(4, "big")
        out.append(hmac.new(mk, msg, hashlib.sha256).digest())
    return out


def round_function(round_key: bytes, round_index: int, right: int, half_bits: int) -> int:
    _require(half_bits > 0, "half_bits must be positive")
    _require(0 <= right < (1 << half_bits), "right out of range for half_bits")
    _require(round_index >= 1, "round_index must be >= 1")

    out_len = (half_bits + 7) // 8
    msg = b"feistel-f" + round_index.to_bytes(4, "big") + int_to_bytes(right, out_len)
    digest = hmac.new(round_key, msg, hashlib.sha256).digest()
    x = bytes_to_int(digest[:out_len])
    return x & ((1 << half_bits) - 1)
```

This is not “a real cipher round function”, but it’s good enough to demonstrate how Feistel structure works: you only need a deterministic keyed function that outputs `half_bits` bits.

### Step 3: Encrypt and decrypt
Implement the Feistel round update, then reverse the process for decryption by iterating keys backwards.

```python
def feistel_encrypt_block(block: int, block_bits: int, round_keys: list[bytes]) -> int:
    _require(len(round_keys) > 0, "need at least one round key")
    left, right = split_block(block, block_bits)
    half_bits = block_bits // 2
    for i, rk in enumerate(round_keys, start=1):
        f = round_function(rk, i, right, half_bits)
        left, right = right, left ^ f
    return join_block(left, right, block_bits)


def feistel_decrypt_block(block: int, block_bits: int, round_keys: list[bytes]) -> int:
    _require(len(round_keys) > 0, "need at least one round key")
    left, right = split_block(block, block_bits)
    half_bits = block_bits // 2
    for i, rk in enumerate(reversed(round_keys), start=1):
        round_index = len(round_keys) - i + 1
        f = round_function(rk, round_index, left, half_bits)
        left, right = right ^ f, left
    return join_block(left, right, block_bits)
```

Notice the symmetry: encryption always applies `F` to the “right” half, and decryption applies `F` to the “left” half while walking keys in reverse.

### Step 4: Diffusion vs number of rounds
Measure the avalanche effect by flipping one plaintext bit and counting how many ciphertext bits change.

```python
def hamming_distance_bits(a: int, b: int, bits: int) -> int:
    _require(bits >= 0, "bits must be non-negative")
    _require(0 <= a < (1 << bits), "a out of range for bits")
    _require(0 <= b < (1 << bits), "b out of range for bits")
    return (a ^ b).bit_count()
```

You should see the Hamming distance increase as rounds increase. If it stays tiny after many rounds, your `F` or your wiring is wrong.

Run it:
python3 code/main.py

## Use It
You almost never implement a block cipher from scratch in production. You choose a standard cipher (AES) and use a vetted library.

- **Python:** `cryptography` (AES-GCM, AES-CTR, ChaCha20-Poly1305)
- **libsodium:** high-level APIs for modern symmetric crypto
- **Go:** `crypto/aes` + `cipher` modes (but prefer AEADs)

Feistel shows up mostly as a *design concept* (DES, Blowfish, Twofish-like structures), not as an API you call directly.

## Pitfalls
- **Too few rounds:** 1–4 rounds are typically distinguishable and have poor diffusion; real designs use many more.
- **Weak `F`:** linear or predictable `F` (e.g., `F(x)=x`) makes the whole cipher structurally weak.
- **Bad key schedule:** repeating round keys or related keys can create slide/related-key issues.
- **Tiny block sizes:** small blocks leak patterns quickly (birthday bound); standards use 64-bit historically, 128-bit today.
- **Confusing “avalanche” with “security”:** good diffusion is necessary, not sufficient — security requires careful cryptanalysis.

## Ship It
Save the reusable checklist in `outputs/feistel-review-checklist.md`. Use it when:
- reviewing a PR that introduces a “custom cipher” or proprietary block transform
- deciding whether a Feistel-like construction is appropriate (usually: no, use AES/ChaCha20-Poly1305)
- sanity-checking number of rounds, block size, round function, and key schedule assumptions

## Exercises
1. Easy: run `python3 code/main.py`. Observe how Hamming distance changes as rounds increase.
2. Medium: change `block_bits` to 64 and `rounds` to 16 in `main.py`. Observe whether diffusion improves or worsens for the same bit flip.
3. Hard: replace the round function with a deliberately weak one (e.g., return `right`) and explain (in a short note) what breaks and why.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Feistel network | “DES-like structure” | A way to build an invertible permutation from XOR + a keyed function `F`. |
| Round | “one iteration” | One application of the Feistel update rule that swaps halves and XORs in `F`. |
| Round function (`F`) | “the magic” | A keyed function applied to one half; doesn’t need to be invertible. |
| Key schedule | “deriving subkeys” | How you turn a master key into per-round keys; mistakes here can kill security. |
| Avalanche effect | “flip one bit, everything changes” | Empirical diffusion metric: small input changes cause many output bit flips. |

## Further Reading
- Horst Feistel, *Cryptography and Computer Privacy* (1973) — classic early exposition of the Feistel idea.
- Bruce Schneier, *Applied Cryptography* (1996) — historical ciphers and design intuition (read with modern caution).
- Ferguson, Schneier, Kohno, *Cryptography Engineering* (2010) — why you should not design your own cipher; good practice guidance.
