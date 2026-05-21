# BIKE & HQC — Code-Based KEMs (QC Syndrome Decoding)

> The “ciphertext” is a syndrome; the hard part is finding a low-weight error that explains it.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 2 — Binary Polynomial Math; Polynomial Rings
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what “QC syndrome decoding” means in BIKE/HQC
- **Compute** syndromes in `GF(2)[x]/(x^r - 1)` using cyclic convolution
- **Implement** a toy QC-MDPC bit-flipping decoder and observe when it works/fails
- **Distinguish** BIKE’s “decode a QC-MDPC syndrome” from HQC’s “decode a noisy codeword”
- **Apply** a concrete review checklist to spot real-world implementation pitfalls (DFR, timing, bit order)

## The Problem

Post-quantum key exchange isn’t “just pick a lattice KEM”. Real deployments often want a backup family with different assumptions. That’s where **code-based** KEMs like **BIKE** and **HQC** show up: they’re designed so that even if lattice assumptions fail, you still have an alternative.

But code-based schemes are famously easy to get *subtly wrong*: bit/byte order, polynomial rotation direction, and “mod `x^n-1` vs `x^n+1`” mistakes can silently break interoperability. Even worse, the **decoder** can fail sometimes, and any visible difference between “decode success” and “decode failure” (timing, errors, retries) can become a **reaction/timing attack surface**.

This lesson gives you a runnable mental model: how QC polynomials become bitsets, how a “ciphertext as syndrome” works, and what a bit-flipping decoder is actually doing.

## The Concept

### The shared core: QC arithmetic over GF(2)

Both BIKE and HQC do a lot of work in a ring like:

`R = GF(2)[x] / (x^n - 1)`

Represent a binary polynomial as a length-`n` bit-vector:

- coefficient of `x^i` is bit `i` (0 or 1)
- addition is XOR
- multiplication is **cyclic convolution** (wrap exponents mod `n`)

### BIKE’s “ciphertext is a syndrome”

BIKE uses a QC parity-check matrix with two circulant blocks, often written as a pair of sparse polynomials `(h0, h1)`.

If the plaintext is a low-weight error vector `(e0, e1)`, the syndrome is:

`s(x) = e0(x) * h0(x) + e1(x) * h1(x)`  in `R`

Decapsulation = “given `s`, find the low-weight `(e0, e1)` that explains it” (syndrome decoding).

### HQC’s “decode a noisy codeword”

HQC also does QC math, but then uses a **public** decodable code `C` (a concatenated code in the real scheme). A useful simplification is:

1) compute a noisy “codeword-ish” thing
2) run `C.Decode(...)` to recover the message

So BIKE is “recover the error”, HQC is “recover the message from a noisy codeword”.

## Build It

### Step 1: Bit-Polynomials in `GF(2)[x]/(x^r - 1)`

We represent an `r`-bit polynomial as a Python `int` where bit `i` is the coefficient of `x^i`.
That gives us:

- masking to `r` bits
- Hamming weight via `int.bit_count()`
- rotate-left for cyclic shifts (the key operation behind cyclic convolution)

```python
from __future__ import annotations

def mask_r(r: int) -> int:
    if r <= 0:
        raise ValueError("r must be positive")
    return (1 << r) - 1


def popcount(x: int) -> int:
    return int(x).bit_count()


def rotl(x: int, r: int, k: int) -> int:
    k %= r
    m = mask_r(r)
    x &= m
    if k == 0:
        return x
    return ((x << k) | (x >> (r - k))) & m


def poly_from_positions(r: int, positions: list[int]) -> int:
    m = mask_r(r)
    acc = 0
    for p in positions:
        if not (0 <= p < r):
            raise ValueError("position out of range")
        acc ^= 1 << p
    return acc & m


def poly_positions(x: int, r: int) -> list[int]:
    x &= mask_r(r)
    out: list[int] = []
    while x:
        lsb = x & -x
        out.append(lsb.bit_length() - 1)
        x ^= lsb
    return out


def poly_str(x: int, r: int) -> str:
    bits = [(x >> i) & 1 for i in range(r)]
    return "".join(str(b) for b in reversed(bits))
```

### Step 2: Cyclic Multiplication and QC Syndromes

In `R = GF(2)[x]/(x^r - 1)`, multiplication is cyclic convolution. A clean educational trick:

If `a(x)` has a `1` at position `i`, then `a(x) * b(x)` includes `x^i * b(x)` which is just a rotate-left by `i`.

Then we can build BIKE-like syndromes from `(h0, h1)`:

```python
def poly_mul_mod_xr1(a: int, b: int, r: int) -> int:
    """
    Multiply in R = GF(2)[x]/(x^r - 1) using cyclic convolution.

    Representation: bit i of an int is the coefficient of x^i.
    """
    a &= mask_r(r)
    b &= mask_r(r)
    out = 0
    aa = a
    while aa:
        lsb = aa & -aa
        i = lsb.bit_length() - 1
        out ^= rotl(b, r, i)
        aa ^= lsb
    return out & mask_r(r)


def syndrome_bike_like(h0: int, h1: int, e0: int, e1: int, r: int) -> int:
    return poly_mul_mod_xr1(e0, h0, r) ^ poly_mul_mod_xr1(e1, h1, r)


def columns_from_parity_polys(h0: int, h1: int, r: int) -> list[int]:
    """
    Expand H = [H0 | H1] columns in polynomial/circulant form.

    With our conventions, if bit i of e0 is 1, the syndrome toggles by rotl(h0, i).
    Likewise for e1 with h1.
    """
    cols: list[int] = []
    for i in range(r):
        cols.append(rotl(h0, r, i))
    for i in range(r):
        cols.append(rotl(h1, r, i))
    return cols
```

### Step 3: A Toy QC-MDPC Bit-Flipping Decoder

Bit-flipping decoding is an iterative heuristic:

1) keep a current syndrome `s`
2) for each bit position, count how many *unsatisfied parity checks* it participates in (a “counter”)
3) flip bits with high counters, and update the syndrome in-place

Real BIKE decoders are much more carefully engineered (threshold schedules, constant-time structure, low DFR),
but the toy version is enough to build intuition.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class BitFlipResult:
    e0: int
    e1: int
    success: bool
    iters: int
    final_syndrome: int


def bitflip_decode_qcmdpc(
    h0: int,
    h1: int,
    syndrome: int,
    r: int,
    *,
    max_iters: int = 20,
    threshold_start: int | None = None,
    threshold_min: int = 1,
) -> BitFlipResult:
    """
    Educational bit-flipping decoder for QC-MDPC syndrome decoding (toy scale).

    This is intentionally tiny and readable, not constant-time, and not tuned for
    real BIKE parameters.
    """
    cols = columns_from_parity_polys(h0, h1, r)
    s = syndrome & mask_r(r)
    e0 = 0
    e1 = 0

    row_weight = popcount(h0 & mask_r(r)) + popcount(h1 & mask_r(r))
    if threshold_start is None:
        threshold_start = (row_weight + 1) // 2

    threshold = threshold_start
    for it in range(1, max_iters + 1):
        if s == 0:
            return BitFlipResult(e0=e0, e1=e1, success=True, iters=it - 1, final_syndrome=0)

        flips: list[int] = []
        for j, col in enumerate(cols):
            if popcount(s & col) >= threshold:
                flips.append(j)

        if not flips:
            if threshold > threshold_min:
                threshold -= 1
                continue
            return BitFlipResult(e0=e0, e1=e1, success=False, iters=it - 1, final_syndrome=s)

        for j in flips:
            s ^= cols[j]
            if j < r:
                e0 ^= 1 << j
            else:
                e1 ^= 1 << (j - r)

        s &= mask_r(r)

    return BitFlipResult(e0=e0, e1=e1, success=(s == 0), iters=max_iters, final_syndrome=s)
```

### Step 4: Tiny BIKE-like KEM + HQC-like PKE Skeleton

This step is **not** BIKE/HQC. It’s a tiny educational skeleton to show where decoding sits:

- A BIKE-like flow: encapsulate → compute syndrome → decapsulate → decode → derive shared secret
- An HQC-like flow: encrypt → compute `u, v` → decrypt → decode a noisy codeword (we use a 3× repetition code)

```python
import hashlib
import random
from dataclasses import dataclass

def sample_fixed_weight(r: int, weight: int, rng: random.Random) -> int:
    if not (0 <= weight <= r):
        raise ValueError("weight out of range")
    positions = rng.sample(range(r), k=weight)
    return poly_from_positions(r, positions)


def split_weight_across_two_blocks(r: int, total_weight: int, rng: random.Random) -> tuple[int, int]:
    if not (0 <= total_weight <= 2 * r):
        raise ValueError("total_weight out of range")
    w0 = rng.randrange(0, total_weight + 1)
    w1 = total_weight - w0
    e0 = sample_fixed_weight(r, w0, rng)
    e1 = sample_fixed_weight(r, w1, rng)
    return e0, e1


def kdf_sha256(label: str, *parts: bytes, out_len: int = 32) -> bytes:
    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    for p in parts:
        h.update(p)
        h.update(b"\x00")
    digest = h.digest()
    if out_len <= len(digest):
        return digest[:out_len]
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        out.extend(hashlib.sha256(digest + ctr.to_bytes(4, "big")).digest())
        ctr += 1
    return bytes(out[:out_len])


@dataclass(frozen=True)
class ToyBikeKeypair:
    r: int
    h0: int
    h1: int


@dataclass(frozen=True)
class ToyBikeCiphertext:
    r: int
    syndrome: int


def toy_bike_keygen(*, r: int, w_each: int, rng: random.Random) -> ToyBikeKeypair:
    h0 = sample_fixed_weight(r, w_each, rng)
    h1 = sample_fixed_weight(r, w_each, rng)
    return ToyBikeKeypair(r=r, h0=h0, h1=h1)


def toy_bike_encaps(pk: ToyBikeKeypair, *, t: int, rng: random.Random) -> tuple[ToyBikeCiphertext, bytes]:
    e0, e1 = split_weight_across_two_blocks(pk.r, t, rng)
    s = syndrome_bike_like(pk.h0, pk.h1, e0, e1, pk.r)
    ct = ToyBikeCiphertext(r=pk.r, syndrome=s)
    ss = kdf_sha256(
        "toy-bike-ss",
        pk.r.to_bytes(2, "big"),
        e0.to_bytes((pk.r + 7) // 8, "little"),
        e1.to_bytes((pk.r + 7) // 8, "little"),
        s.to_bytes((pk.r + 7) // 8, "little"),
    )
    return ct, ss


def toy_bike_decaps(sk: ToyBikeKeypair, ct: ToyBikeCiphertext, *, max_iters: int = 20) -> tuple[bytes, BitFlipResult]:
    if ct.r != sk.r:
        raise ValueError("ciphertext r mismatch")
    res = bitflip_decode_qcmdpc(sk.h0, sk.h1, ct.syndrome, sk.r, max_iters=max_iters)
    ss = kdf_sha256(
        "toy-bike-ss",
        sk.r.to_bytes(2, "big"),
        res.e0.to_bytes((sk.r + 7) // 8, "little"),
        res.e1.to_bytes((sk.r + 7) // 8, "little"),
        ct.syndrome.to_bytes((sk.r + 7) // 8, "little"),
    )
    return ss, res


def rep3_encode(msg_bits: int, k: int) -> int:
    out = 0
    for i in range(k):
        b = (msg_bits >> i) & 1
        if b:
            out |= 1 << (3 * i + 0)
            out |= 1 << (3 * i + 1)
            out |= 1 << (3 * i + 2)
    return out


def rep3_decode(codeword: int, k: int) -> int:
    out = 0
    for i in range(k):
        triplet = (codeword >> (3 * i)) & 0b111
        if popcount(triplet) >= 2:
            out |= 1 << i
    return out


@dataclass(frozen=True)
class ToyHqcKeypair:
    n: int
    h: int
    s: int
    x: int
    y: int
    k: int


@dataclass(frozen=True)
class ToyHqcCiphertext:
    n: int
    u: int
    v: int


def toy_hqc_encrypt_fixed(pk: ToyHqcKeypair, msg_bits: int, *, r1: int, r2: int, e: int) -> ToyHqcCiphertext:
    if msg_bits < 0 or msg_bits >= (1 << pk.k):
        raise ValueError("msg_bits out of range")
    if 3 * pk.k != pk.n:
        raise ValueError("toy HQC uses n=3k for rep3 code")

    r1 &= mask_r(pk.n)
    r2 &= mask_r(pk.n)
    e &= mask_r(pk.n)

    u = r1 ^ poly_mul_mod_xr1(pk.h, r2, pk.n)
    mG = rep3_encode(msg_bits, pk.k)
    v = mG ^ poly_mul_mod_xr1(pk.s, r2, pk.n) ^ e
    return ToyHqcCiphertext(n=pk.n, u=u, v=v)


def toy_hqc_decrypt(sk: ToyHqcKeypair, ct: ToyHqcCiphertext) -> int:
    if ct.n != sk.n:
        raise ValueError("ciphertext n mismatch")
    v_prime = ct.v ^ poly_mul_mod_xr1(ct.u, sk.y, sk.n)
    return rep3_decode(v_prime, sk.k)
```

Run it:

`python3 code/main.py`

## Use It

Production code-based KEM implementations (don’t copy the from-scratch code):

- **Open Quantum Safe `liboqs`**: KEM implementations and known-good test harnesses for BIKE/HQC
- **PQClean**: “clean” reference-style implementations used for cross-checking
- **BIKE suite reference implementation**: decoders, parameter sets, test tooling
- **HQC reference implementation**: concatenated-code encoder/decoder and test vectors

## Pitfalls

- **Bit order / rotation direction mismatch**: you can be “almost correct” and still fail interoperability.
- **Wrong modulus polynomial**: `x^n - 1` vs `x^n + 1` changes convolution (cyclic vs negacyclic).
- **Decoder failure leakage**: timing, branchy loops, or different errors on failure can enable reaction/timing attacks.
- **Non-uniform fixed-weight sampling**: biased sampling can weaken security and/or break proofs.
- **Assuming “DFR is negligible so we can ignore it”**: protocol behavior can amplify tiny failure probabilities.

## Ship It

This lesson ships a copy/paste checklist you can use immediately when reviewing BIKE/HQC code:

- Artifact: `outputs/bike-hqc-review-checklist.md`
- Use it by pasting it into a PR review (or into an LLM) and answering each section against the codebase you’re reviewing.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how the syndrome equation becomes “rotate-and-xor”.
2. Medium: In `code/main.py`, increase the toy BIKE error weight `t` and watch the toy bit-flip decoder start failing.
3. Hard: Install `liboqs` and compare its BIKE/HQC test vectors to your own ring/bit-order conventions. Identify exactly which convention differs when you intentionally flip endianness.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| QC (quasi-cyclic) | “It’s structured, so it’s fast” | A big matrix is built from small circulant blocks; polynomial arithmetic replaces matrix ops. |
| Syndrome | “The ciphertext” | `s = H·e^T` (or polynomial equivalent). It tells you which parity checks are violated. |
| QCSD | “Quasi-cyclic syndrome decoding” | Given a QC matrix `H` and syndrome `s`, find a low-weight `e` with `H·e^T = s`. |
| MDPC | “Moderate density parity-check” | Like LDPC, but denser; decoding is iterative and can fail with small probability. |
| DFR | “Decoder failure rate” | Probability the decoder fails; dangerous if failure is observable (reaction/timing oracles). |

## Further Reading

- BIKE Team, *BIKE Specification* — syndrome form, decoder interface, and KEM transforms
- HQC Team, *HQC Specification* — `u = r1 + h·r2`, `v = mG + s·r2 + e`, and decoding via a public code
- Drucker–Gueron–Kostic, *QC-MDPC decoders with several shades of gray* — decoder engineering and constant-time constraints
- Guo–Johansson–Stankovski (and follow-ups), reaction/timing attack line on QC-MDPC-style schemes — why “failure leakage” matters
