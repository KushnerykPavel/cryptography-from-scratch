from __future__ import annotations

import hashlib
import hmac as _hmac
import math
import struct
from collections.abc import Callable


# ---------------------------------------------------------------------------
# Toy PRG — SHA-256 counter mode.  Seed security = seed_bits.  Not production.
# ---------------------------------------------------------------------------

def toy_prg(seed: bytes, output_bytes: int) -> bytes:
    """Stretch seed to output_bytes using SHA-256(seed || counter) blocks.

    Security inherits from seed length, not output length.
    A 16-byte seed gives 128-bit security regardless of how many bytes we emit.
    """
    if not seed:
        raise ValueError("seed must be non-empty")
    if output_bytes < 0:
        raise ValueError("output_bytes must be non-negative")
    blocks = []
    counter = 0
    total = 0
    while total < output_bytes:
        ctr_bytes = struct.pack(">Q", counter)
        blocks.append(hashlib.sha256(seed + ctr_bytes).digest())
        total += 32
        counter += 1
    return b"".join(blocks)[:output_bytes]


def prg_stretch(seed_bits: int, output_bits: int) -> int:
    """Stretch factor: how many extra bits the PRG produces."""
    return output_bits - seed_bits


def prg_security_bits(seed_bits: int) -> int:
    """PRG output security = seed security. Stretching does not add entropy."""
    return seed_bits


# ---------------------------------------------------------------------------
# Toy PRF — HMAC-SHA-256(key, x).  Not production.
# ---------------------------------------------------------------------------

def toy_prf(key: bytes, x: bytes) -> bytes:
    """Keyed pseudorandom function: HMAC-SHA256(key, x).

    For each fixed key, x -> toy_prf(key, x) behaves like a random function.
    32-byte output.  Truncate as needed.
    """
    if not key:
        raise ValueError("key must be non-empty")
    return _hmac.new(key, x, hashlib.sha256).digest()


def toy_prf_n(key: bytes, x: bytes, output_bits: int) -> int:
    """PRF with output_bits-bit integer output (truncated HMAC-SHA256)."""
    if output_bits <= 0 or output_bits > 256:
        raise ValueError("output_bits must be in (0, 256]")
    n_bytes = (output_bits + 7) // 8
    raw = toy_prf(key, x)[:n_bytes]
    return int.from_bytes(raw, "big") >> (n_bytes * 8 - output_bits)


def prf_to_prg(key: bytes, output_bytes: int) -> bytes:
    """Build a PRG from a PRF in counter mode: G(k) = PRF(k,0) || PRF(k,1) || ...

    Security: if PRF is secure, this PRG is secure.
    """
    blocks = []
    counter = 0
    total = 0
    while total < output_bytes:
        ctr_bytes = struct.pack(">Q", counter)
        blocks.append(toy_prf(key, ctr_bytes))
        total += 32
        counter += 1
    return b"".join(blocks)[:output_bytes]


# ---------------------------------------------------------------------------
# Toy PRP — balanced Feistel network over a 2n-bit block.  Not production.
# ---------------------------------------------------------------------------

def _feistel_round_fn(key: bytes, round_num: int, half: bytes) -> bytes:
    """Feistel round function: SHA-256(key || round || half), truncated to |half|."""
    data = key + struct.pack(">I", round_num) + half
    return hashlib.sha256(data).digest()[: len(half)]


def toy_prp_encrypt(key: bytes, plaintext: bytes, n_rounds: int = 4) -> bytes:
    """Toy Feistel permutation (encryption). Block = len(plaintext) bytes (even).

    4-round balanced Feistel: bijective for any fixed key.
    """
    if len(plaintext) == 0 or len(plaintext) % 2 != 0:
        raise ValueError("plaintext length must be positive and even")
    if n_rounds < 1:
        raise ValueError("n_rounds must be >= 1")
    h = len(plaintext) // 2
    L, R = bytearray(plaintext[:h]), bytearray(plaintext[h:])
    for i in range(n_rounds):
        f = _feistel_round_fn(key, i, bytes(R))
        L, R = R, bytearray(a ^ b for a, b in zip(L, f))
    return bytes(L) + bytes(R)


def toy_prp_decrypt(key: bytes, ciphertext: bytes, n_rounds: int = 4) -> bytes:
    """Toy Feistel permutation (decryption). Inverse of toy_prp_encrypt."""
    if len(ciphertext) == 0 or len(ciphertext) % 2 != 0:
        raise ValueError("ciphertext length must be positive and even")
    if n_rounds < 1:
        raise ValueError("n_rounds must be >= 1")
    h = len(ciphertext) // 2
    L, R = bytearray(ciphertext[:h]), bytearray(ciphertext[h:])
    for i in reversed(range(n_rounds)):
        f = _feistel_round_fn(key, i, bytes(L))
        L, R = bytearray(a ^ b for a, b in zip(R, f)), L
    return bytes(L) + bytes(R)


def ctr_mode_encrypt(
    key: bytes,
    nonce: int,
    plaintext: bytes,
    prf_fn: Callable[[bytes, bytes], bytes] = toy_prf,
) -> bytes:
    """CTR mode encryption: XOR plaintext with PRF(key, nonce || counter) per block.

    Converts any PRF into a stream cipher.  Requires fresh nonce per message.
    """
    result = bytearray()
    block_size = 32  # SHA-256 output
    for i in range(0, len(plaintext), block_size):
        ctr_block = struct.pack(">QQ", nonce, i // block_size)
        keystream = prf_fn(key, ctr_block)
        chunk = plaintext[i : i + block_size]
        result.extend(a ^ b for a, b in zip(chunk, keystream))
    return bytes(result)


def ctr_mode_decrypt(
    key: bytes,
    nonce: int,
    ciphertext: bytes,
    prf_fn: Callable[[bytes, bytes], bytes] = toy_prf,
) -> bytes:
    """CTR mode decryption (identical to encryption — XOR is self-inverse)."""
    return ctr_mode_encrypt(key, nonce, ciphertext, prf_fn)


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

def prp_prf_switching_advantage(q: int, block_bits: int) -> float:
    """Advantage of distinguishing a PRP from a PRF after q queries.

    PRP-PRF switching lemma: Adv <= q*(q-1) / (2 * 2^block_bits).
    Same formula as the birthday bound.
    """
    if q < 0:
        raise ValueError("q must be non-negative")
    if block_bits <= 0:
        raise ValueError("block_bits must be positive")
    return q * (q - 1) / (2.0 * (2.0 ** block_bits))


def prf_collision_probability(q: int, output_bits: int) -> float:
    """Probability of output collision across q PRF queries (birthday bound).

    Pr[∃ i≠j: PRF(k,x_i) = PRF(k,x_j) for distinct x_i] ≈ q^2 / 2^(output_bits+1).
    """
    if q < 0:
        raise ValueError("q must be non-negative")
    if output_bits <= 0:
        raise ValueError("output_bits must be positive")
    return q * (q - 1) / (2.0 * (2.0 ** output_bits))


def safe_query_limit(block_bits: int, target_advantage: float = 2 ** -32) -> int:
    """Max queries before distinguishing advantage exceeds target_advantage.

    From: q*(q-1)/(2*2^n) <= epsilon => q <= sqrt(2*epsilon*2^n).
    """
    if not (0 < target_advantage < 1):
        raise ValueError("target_advantage must be in (0, 1)")
    if block_bits <= 0:
        raise ValueError("block_bits must be positive")
    return int(math.sqrt(2.0 * target_advantage * (2.0 ** block_bits)))


def prg_from_prf_stretch(prf_output_bits: int, n_blocks: int) -> int:
    """Total bits produced by PRG-from-PRF in counter mode for n_blocks PRF calls."""
    return prf_output_bits * n_blocks


def main():
    print("=" * 60)
    print("PRG, PRF, PRP — PSEUDORANDOMNESS HIERARCHY")
    print("=" * 60)

    key = b"demo-key-32bytes-padded-to-32byt"
    seed = b"seed-16-bytes!!!"

    # --- PRG ---
    print("\n--- PRG: stretching a seed ---")
    for out_bytes in (16, 32, 64, 128):
        out = toy_prg(seed, out_bytes)
        print(f"  seed={len(seed)}B → {out_bytes}B  first8: {out[:8].hex()}")
    print(f"  Security = seed bits = {len(seed)*8} bits (stretch doesn't add security)")
    print(f"  PRG stretch: {prg_stretch(len(seed)*8, 64*8)} extra bits for 64-byte output")

    # --- PRF ---
    print("\n--- PRF: keyed pseudorandom function ---")
    for x in (b"\x00" * 4, b"\x01" * 4, b"test"):
        h = toy_prf(key, x)
        print(f"  PRF(key, {x!r}) = {h[:8].hex()}...")
    print("  Same key, different inputs → independent-looking outputs")
    print("  toy_prf_n(key, b'x', 64) =", toy_prf_n(key, b"x", 64))

    # --- PRF → PRG ---
    print("\n--- PRG from PRF (counter mode) ---")
    prg_out = prf_to_prg(key, 64)
    prg_seed_mode = toy_prg(seed, 64)
    print(f"  PRF-based PRG (64B): {prg_out[:8].hex()}...")
    print(f"  SHA-256 PRG    (64B): {prg_seed_mode[:8].hex()}...")

    # --- PRP: Feistel ---
    print("\n--- PRP: toy Feistel permutation ---")
    block = b"hello-world-16!!"  # 16 bytes (8L + 8R)
    ct = toy_prp_encrypt(key, block)
    pt = toy_prp_decrypt(key, ct)
    print(f"  Plaintext:  {block.hex()}")
    print(f"  Encrypted:  {ct.hex()}")
    print(f"  Decrypted:  {pt.hex()}")
    print(f"  Roundtrip:  {pt == block}")
    print("  Bijection: different plaintexts → different ciphertexts (no collisions)")
    ct2 = toy_prp_encrypt(key, b"hello-world-17!!")
    print(f"  PT+1:       {ct2.hex()} (differs from above)")

    # --- CTR mode ---
    print("\n--- CTR mode: PRF → stream cipher ---")
    msg = b"Attack at dawn!!"
    nonce = 0x12345678
    enc = ctr_mode_encrypt(key, nonce, msg)
    dec = ctr_mode_decrypt(key, nonce, enc)
    print(f"  Message:   {msg}")
    print(f"  Encrypted: {enc.hex()}")
    print(f"  Decrypted: {dec}")
    print(f"  Correct:   {dec == msg}")
    print("  Nonce reuse with same key → SAME keystream → XOR reveals plaintext")
    enc2 = ctr_mode_encrypt(key, nonce, b"Attack at dusk!!")
    xored = bytes(a ^ b for a, b in zip(enc, enc2))
    print(f"  XOR of two ciphertexts (same nonce): {xored.hex()} (leaks plaintext XOR)")

    # --- Security bounds ---
    print("\n--- PRP-PRF switching lemma ---")
    print(f"  {'block_bits':>10}  {'q=2^20':>12}  {'q=2^32':>12}  {'q=2^64':>12}")
    for bits in (64, 128, 256):
        adv20 = prp_prf_switching_advantage(2**20, bits)
        adv32 = prp_prf_switching_advantage(2**32, bits)
        adv64 = prp_prf_switching_advantage(2**64, bits)
        print(f"  {bits:>10}  {adv20:>12.2e}  {adv32:>12.2e}  {adv64:>12.2e}")

    print("\n--- Safe query limits ---")
    print(f"  {'block_bits':>10}  {'limit (Adv<2^-32)':>20}  {'log2(limit)':>12}")
    for bits in (64, 128, 256):
        q = safe_query_limit(bits, 2 ** -32)
        print(f"  {bits:>10}  {q:>20}  {math.log2(q+1):>12.1f}")

    print("\n--- Hierarchy summary ---")
    print("  OWF  →  PRG  →  PRF  →  PRP")
    print("  (one-way functions imply pseudorandomness at each level)")
    print("  PRG: stretch seed (no inversion possible)")
    print("  PRF: keyed random function (no distinguishing possible)")
    print("  PRP: bijective PRF (block cipher model)")
    print("  PRP ≈ PRF up to birthday advantage q^2/2^n")


if __name__ == "__main__":
    main()
