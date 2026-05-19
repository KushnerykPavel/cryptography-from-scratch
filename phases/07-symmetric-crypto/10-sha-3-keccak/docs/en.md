# SHA-3 / Keccak from Scratch
> Hash with a permutation: absorb, permute, squeeze.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `07-symmetric-crypto/09-sha-256` (hash basics + padding), comfort with bytes + bitwise ops  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** the sponge construction (absorb/permute/squeeze) and how it differs from Merkle–Damgård
- **Compute** rate/capacity parameters for SHA3-256 and SHAKE128
- **Implement** Keccak-f[1600] (θ, ρ+π, χ, ι) and use it as a black-box permutation
- **Distinguish** SHA-3 vs SHAKE vs “raw Keccak” (domain separation + padding differences)
- **Apply** SHAKE to produce variable-length output safely (and know when you should use KMAC/HKDF instead)

## The Problem
You can’t avoid hashing in real systems: you hash passwords (with a password-hash), you hash transcripts in protocols, you hash commits and blocks, you hash messages for signatures, you hash keys for key derivation, and you hash large files for integrity. If you treat “a hash” as a single interchangeable box, you eventually ship subtle bugs: mixing up SHA-3 with Keccak, truncating an XOF incorrectly, using a hash where you needed a keyed function, or accidentally relying on properties that don’t hold.

SHA-3 is especially relevant because it’s not “another SHA-2.” It’s built from a permutation (Keccak-f) via a sponge construction, which changes how padding, internal state, and some classic pitfalls (like length-extension on Merkle–Damgård hashes) behave. SHAKE (an XOF) is also a workhorse in modern crypto engineering: you often want “as many bytes as needed” from one primitive for KDF-like tasks or protocol transcripts.

## The Concept
Keccak-f[1600] is a fixed 1600-bit permutation. SHA-3 doesn’t build a compression function out of it; instead it uses a **sponge**:

- Split the 1600-bit state into:
  - **rate** `r`: the part that touches the message/output
  - **capacity** `c`: the hidden part that provides security margin
  - Always: `r + c = 1600`
- **Absorb:** XOR `r` bits of message into the first `r` bits of the state, then apply Keccak-f.
- **Squeeze:** Read `r` bits out. If you need more, apply Keccak-f again and keep reading.

For SHA3-256:
- `c = 512` bits, so `r = 1600 - 512 = 1088` bits = `136` bytes
- output length is fixed: `32` bytes

For SHAKE128:
- `c = 256` bits, so `r = 1344` bits = `168` bytes
- output length is variable (you choose it)

Two details matter a lot in real systems:
1. **Padding (pad10*1):** ensures the padded message is unambiguous and ends on a rate boundary.
2. **Domain separation:** SHA-3 and SHAKE append different suffix bits before the padding (byte-aligned forms often show up as `0x06` for SHA-3 and `0x1F` for SHAKE). This prevents cross-function confusion.

## Build It

### Step 1: State & Lanes
```python
MASK64 = (1 << 64) - 1


def rol64(x: int, shift: int) -> int:
    shift &= 63
    x &= MASK64
    if shift == 0:
        return x
    return ((x << shift) | (x >> (64 - shift))) & MASK64
```
Keccak’s 1600-bit state is a 5×5 grid of 64-bit **lanes**. We’ll represent it as 25 Python integers masked to 64 bits, and we need a correct rotate-left primitive because ρ uses rotations heavily.

### Step 2: Keccak-f[1600] Permutation
```python
KECCAKF_ROUNDS = 24

KECCAKF_ROTC = [
    1,
    3,
    6,
    10,
    15,
    21,
    28,
    36,
    45,
    55,
    2,
    14,
    27,
    41,
    56,
    8,
    25,
    43,
    62,
    18,
    39,
    61,
    20,
    44,
]

KECCAKF_PILN = [
    10,
    7,
    11,
    17,
    18,
    3,
    5,
    16,
    8,
    21,
    24,
    4,
    15,
    23,
    19,
    13,
    12,
    2,
    20,
    14,
    22,
    9,
    6,
    1,
]

KECCAKF_RNDC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]


def keccak_f1600(lanes: list[int]) -> list[int]:
    if len(lanes) != 25:
        raise ValueError("state must have 25 lanes")

    a = [x & MASK64 for x in lanes]

    for round_index in range(KECCAKF_ROUNDS):
        c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
        c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
        c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
        c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
        c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]

        d0 = c4 ^ rol64(c1, 1)
        d1 = c0 ^ rol64(c2, 1)
        d2 = c1 ^ rol64(c3, 1)
        d3 = c2 ^ rol64(c4, 1)
        d4 = c3 ^ rol64(c0, 1)

        a[0] ^= d0
        a[5] ^= d0
        a[10] ^= d0
        a[15] ^= d0
        a[20] ^= d0

        a[1] ^= d1
        a[6] ^= d1
        a[11] ^= d1
        a[16] ^= d1
        a[21] ^= d1

        a[2] ^= d2
        a[7] ^= d2
        a[12] ^= d2
        a[17] ^= d2
        a[22] ^= d2

        a[3] ^= d3
        a[8] ^= d3
        a[13] ^= d3
        a[18] ^= d3
        a[23] ^= d3

        a[4] ^= d4
        a[9] ^= d4
        a[14] ^= d4
        a[19] ^= d4
        a[24] ^= d4

        t = a[1]
        for i in range(24):
            j = KECCAKF_PILN[i]
            a[j], t = rol64(t, KECCAKF_ROTC[i]), a[j]

        for y in range(5):
            row0 = a[y * 5 + 0]
            row1 = a[y * 5 + 1]
            row2 = a[y * 5 + 2]
            row3 = a[y * 5 + 3]
            row4 = a[y * 5 + 4]
            a[y * 5 + 0] ^= (~row1 & MASK64) & row2
            a[y * 5 + 1] ^= (~row2 & MASK64) & row3
            a[y * 5 + 2] ^= (~row3 & MASK64) & row4
            a[y * 5 + 3] ^= (~row4 & MASK64) & row0
            a[y * 5 + 4] ^= (~row0 & MASK64) & row1

        a[0] ^= KECCAKF_RNDC[round_index]

    return [x & MASK64 for x in a]
```
This is the heart of SHA-3: a 24-round permutation on a 1600-bit state. Each round applies linear diffusion (θ), bit rotations + shuffling (ρ+π), a nonlinear step (χ), and a round constant injection (ι). We’ll treat it like a secure “mixing function” and build a hash out of it.

### Step 3: Sponge + Padding
```python
def keccak_multirate_pad(rate_bytes: int, message: bytes, delimited_suffix: int) -> bytes:
    if rate_bytes <= 0:
        raise ValueError("rate_bytes must be positive")
    if not (0 <= delimited_suffix <= 0xFF):
        raise ValueError("delimited_suffix must be a byte")

    padded = bytearray(message)
    pad_len = rate_bytes - (len(padded) % rate_bytes)
    padded.extend(b"\x00" * pad_len)
    padded[len(message)] ^= delimited_suffix
    padded[-1] ^= 0x80
    return bytes(padded)


def keccak_sponge(
    *,
    rate_bytes: int,
    message: bytes,
    delimited_suffix: int,
    output_len: int,
) -> bytes:
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    if rate_bytes % 8 != 0:
        raise ValueError("this educational implementation requires rate_bytes % 8 == 0")

    lanes_in_rate = rate_bytes // 8
    state = [0] * 25

    padded = keccak_multirate_pad(rate_bytes, message, delimited_suffix)
    for offset in range(0, len(padded), rate_bytes):
        block = padded[offset : offset + rate_bytes]
        for i in range(lanes_in_rate):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        state = keccak_f1600(state)

    out = bytearray()
    while len(out) < output_len:
        chunk = b"".join(state[i].to_bytes(8, "little") for i in range(lanes_in_rate))
        out.extend(chunk[: min(rate_bytes, output_len - len(out))])
        if len(out) < output_len:
            state = keccak_f1600(state)
    return bytes(out)
```
This builds the sponge: pad the message, XOR blocks into the first `rate_bytes` of the state (lane-wise, little-endian), permute after each block, then squeeze output bytes. SHA-3 and SHAKE differ mostly by `(rate, capacity)` and the `delimited_suffix` used for domain separation.

### Step 4: SHA3-256 / SHA3-512
```python
def sha3_256(message: bytes) -> bytes:
    return keccak_sponge(rate_bytes=136, message=message, delimited_suffix=0x06, output_len=32)


def sha3_512(message: bytes) -> bytes:
    return keccak_sponge(rate_bytes=72, message=message, delimited_suffix=0x06, output_len=64)
```
These two fixed-output hashes use the same permutation, but different rate/capacity splits (and output lengths). The capacity determines the security strength; the rate determines throughput.

### Step 5: SHAKE (XOF)
```python
def shake128(message: bytes, output_len: int) -> bytes:
    return keccak_sponge(rate_bytes=168, message=message, delimited_suffix=0x1F, output_len=output_len)


def shake256(message: bytes, output_len: int) -> bytes:
    return keccak_sponge(rate_bytes=136, message=message, delimited_suffix=0x1F, output_len=output_len)
```
SHAKE functions are XOFs: after absorbing the message, you can squeeze as many bytes as you want. That’s incredibly useful for “hash-to-many-bytes” use cases — but only if you treat the output length as part of the protocol and keep domain separation straight.

Run it:
`python3 code/main.py`

## Use It
Production code should use audited libraries:

| Environment | What to use | Notes |
|---|---|---|
| Python | `hashlib.sha3_256`, `hashlib.sha3_512`, `hashlib.shake_128`, `hashlib.shake_256` | Built-in, easy to use correctly |
| OpenSSL | `EVP_sha3_256`, `EVP_shake128`, etc. | Widely deployed; check FIPS/provider requirements |
| Rust | `sha3` crate (RustCrypto) | Provides SHA-3 + SHAKE; also cSHAKE/KMAC via related crates |
| PyCryptodome | `Crypto.Hash.SHA3_256`, `Crypto.Hash.keccak` | Exposes SHA-3 and raw Keccak variants (easy to mix up) |

## Pitfalls
1. **Confusing SHA-3 with Keccak-256.** Ethereum uses Keccak-256 (different padding/domain separation than SHA3-256). The names look interchangeable; they are not.
2. **Forgetting domain separation.** If your protocol uses “SHAKE output” and “SHA3 digest” in different places, you must keep those domains disjoint (suffix bits, context strings, or different functions).
3. **Treating SHAKE output length as “just truncation.”** The requested output length is part of the construction; specify it explicitly and consistently in the protocol.
4. **Using SHAKE as a MAC/KDF without a standard wrapper.** Prefer KMAC (SP 800-185) for keyed hashing, and HKDF for key derivation unless you have a good reason.
5. **Hashing strings without canonicalization.** Ambiguous encodings (UTF-8 vs UTF-16, JSON whitespace, floating-point formatting) create “same semantic value, different hash” failures.

## Ship It
Save the reusable checklist in `outputs/sha3-keccak-review-checklist.md`. Use it as:
- a PR review checklist when someone introduces SHA-3/SHAKE/Keccak into a codebase
- a protocol design reminder (domain separation, output lengths, and “Keccak vs SHA-3” gotchas)

## Exercises
1. Easy: Run `python3 code/main.py`. Observe that our outputs exactly match `hashlib` for the same inputs.
2. Medium: Add `sha3_384(message: bytes) -> bytes` (rate `104` bytes, output `48` bytes) and test it against `hashlib.sha3_384`.
3. Hard: Pick one real-world “Keccak vs SHA-3” context (e.g., Ethereum preimages) and write a short note explaining exactly what breaks if someone swaps SHA3-256 for Keccak-256 in that context.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Sponge | “Absorb/squeeze hash” | A construction that turns a permutation into a hash/XOF by XORing input into a rate portion and squeezing output after permutations |
| Rate (`r`) | “Block size” | How many bits per permutation call are used for absorbing/squeezing |
| Capacity (`c`) | “Security margin” | The hidden part of the state; larger `c` generally means higher security strength |
| Keccak-f[1600] | “The SHA-3 core” | The 24-round 1600-bit permutation used by standard SHA-3 instances |
| Domain separation | “Different flavors” | Extra bits (suffix/customization) that ensure different functions/uses don’t collide |
| XOF | “Variable-length hash” | A function like SHAKE that can output any number of bytes on demand |

## Further Reading
- NIST, *FIPS 202: SHA-3 Standard* (2015) — the canonical SHA-3 / SHAKE specification
- Bertoni, Daemen, Peeters, Van Assche, *The Keccak Sponge Function Family* (2011) — sponge intuition and design notes
- Keccak team, *Keccak specification summaries* — parameter tables and implementation notes (especially domain separation and instances)
