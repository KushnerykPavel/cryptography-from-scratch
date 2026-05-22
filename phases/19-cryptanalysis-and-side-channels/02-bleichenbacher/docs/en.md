# Bleichenbacher’s Attack — RSA PKCS#1 v1.5

> If your RSA decrypt endpoint leaks “PKCS#1 conformant?”, you leak the plaintext.

**Type:** Build
**Languages:** Python
**Prerequisites:** RSA basics; integer/bytes encoding; threat modeling for chosen-ciphertext attacks
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain the “million message attack” model for RSAES-PKCS1-v1_5
- Compute the PKCS#1 v1.5 “block type 2” encoding format and validate it
- Implement a padding-validity oracle for RSA decryption (toy)
- Distinguish OAEP from PKCS#1 v1.5 and why OAEP is preferred
- Apply interval narrowing to recover a plaintext using only oracle queries (toy parameters)

## The Problem

Legacy systems still use RSAES-PKCS1-v1_5 (PKCS#1 v1.5 “encryption padding”) for things like key transport, S/MIME, XML Encryption, and old TLS paths. The decrypt side often produces different behavior for “padding bad” vs “message bad”.

That one-bit leak is enough for an attacker who can send chosen ciphertexts and observe accept/reject. They adaptively craft new ciphertexts based on previous answers and shrink the set of possible plaintexts until only one remains.

This isn’t “RSA is broken.” It’s “RSA + a brittle padding format + an error oracle” is broken. The fix is not “hide errors better” in isolation; the fix is “use a CCA-secure padding scheme (OAEP / KEM) and constant-time, uniform error handling”.

## The Concept

PKCS#1 v1.5 “block type 2” encoding produces an encoded message `EM` of length `k` bytes (where `k` is the RSA modulus length in bytes):

`EM = 0x00 || 0x02 || PS || 0x00 || M`

where `PS` is a string of non-zero bytes with length at least 8. The decoder checks these formatting rules.

Bleichenbacher’s insight: if you have an oracle `O(c)` that tells you whether `RSADecrypt(c)` begins with `0x00 0x02 ... 0x00`, then you can use RSA’s multiplicative property:

`RSADecrypt(c * s^e mod n) = m * s mod n`

and treat “conformant?” as a constraint:

`2B <= (m*s mod n) < 3B` where `B = 2^(8*(k-2))`.

Each conformant `s` shrinks the interval where `m` can live. Repeat until the interval collapses to a single integer.

For a runnable demo, this lesson uses a **toy header oracle** that checks only a few most-significant bits (“does the plaintext start with header value 2?”). For real PKCS#1 v1.5, those bits correspond to the `0x00 0x02` prefix.

## Build It

### Step 1: RSA primitives
```python
def i2osp(x: int, k: int) -> bytes:
    if x < 0 or x >= (1 << (8 * k)):
        raise ValueError("integer too large")
    return x.to_bytes(k, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")
```
RSA encrypt/decrypt works over integers mod `n`, but padding is defined over fixed-length byte strings. These helpers bridge the two worlds.

### Step 2: PKCS#1 v1.5 encoding (format)
```python
def pkcs1v15_encode(message: bytes, k: int, ps: bytes) -> bytes:
    if len(message) > k - 11:
        raise ValueError("message too long")
    if len(ps) != k - 3 - len(message):
        raise ValueError("bad PS length")
    if any(x == 0 for x in ps):
        raise ValueError("PS must be non-zero bytes")
    return b"\x00\x02" + ps + b"\x00" + message


def pkcs1v15_is_conformant(em: bytes) -> bool:
    if len(em) < 11:
        return False
    if not (em[0] == 0 and em[1] == 2):
        return False
    try:
        sep = em.index(b"\x00", 2)
    except ValueError:
        return False
    if sep < 10:
        return False
    if any(x == 0 for x in em[2:sep]):
        return False
    return True
```
This is the “oracle boundary”: real systems rarely return the plaintext, but they often leak whether this decode step would accept.

### Step 3: A fast header oracle (toy)
```python
def header_oracle_factory(key: RSAKey, header_bits: int) -> Callable[[int], bool]:
    if header_bits <= 0 or header_bits > 16:
        raise ValueError("header_bits must be in 1..16 for this demo")

    def oracle(c: int) -> bool:
        k = key.k
        m = rsa_decrypt_int(c, key.n, key.d)
        top = m >> (8 * k - header_bits)
        return top == 2

    return oracle


def toy_prefix_encode(message: bytes, k: int, header_byte: int = 2) -> bytes:
    if not (0 <= header_byte <= 255):
        raise ValueError("bad header_byte")
    if len(message) > k - 1:
        raise ValueError("message too long")
    return bytes([header_byte]) + (b"\x00" * (k - 1 - len(message))) + message


def toy_prefix_decode(em: bytes, message_len: int) -> bytes:
    if message_len < 0 or message_len > len(em):
        raise ValueError("bad message_len")
    return em[-message_len:]
```
Bleichenbacher’s original oracle checks PKCS#1 v1.5 formatting (roughly “does the plaintext start with `0x00 0x02`?”). To keep the demo runnable, we use a header oracle that checks only the most-significant `header_bits` and a toy encoding whose first byte is `0x02`.

### Step 4: Adaptive narrowing (Bleichenbacher-style, toy header)
```python
def ceil_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return -(-a // b)


def floor_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return a // b


def _merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    intervals.sort()
    out = [intervals[0]]
    for a, b in intervals[1:]:
        la, lb = out[-1]
        if a <= lb + 1:
            out[-1] = (la, max(lb, b))
        else:
            out.append((a, b))
    return out


def bleichenbacher_recover_em(
    c: int,
    n: int,
    e: int,
    oracle: Callable[[int], bool],
    header_bits: int,
    max_oracle_calls: int = 250_000,
) -> Tuple[bytes, int]:
    k = (n.bit_length() + 7) // 8
    if header_bits <= 0 or header_bits > 16:
        raise ValueError("header_bits must be in 1..16 for this demo")
    B = 1 << (8 * k - header_bits)
    B2 = 2 * B
    B3m1 = 3 * B - 1

    calls = 0

    def ok(cand: int) -> bool:
        nonlocal calls
        calls += 1
        if calls > max_oracle_calls:
            raise RuntimeError("oracle call limit exceeded")
        return oracle(cand)

    c0 = c
    if not ok(c0):
        raise ValueError("ciphertext not conformant under oracle (demo expects conformant)")

    s = ceil_div(n, 3 * B)
    while not ok((c0 * pow(s, e, n)) % n):
        s += 1

    M: List[Tuple[int, int]] = [(B2, B3m1)]

    while True:
        new_M: List[Tuple[int, int]] = []
        for a, b in M:
            r_min = ceil_div(a * s - B3m1, n)
            r_max = floor_div(b * s - B2, n)
            for r in range(r_min, r_max + 1):
                lo = max(a, ceil_div(B2 + r * n, s))
                hi = min(b, floor_div(B3m1 + r * n, s))
                if lo <= hi:
                    new_M.append((lo, hi))
        M = _merge_intervals(new_M)

        if len(M) == 1 and M[0][0] == M[0][1]:
            m0 = M[0][0]
            return i2osp(m0, k), calls

        if len(M) > 1:
            s += 1
            while not ok((c0 * pow(s, e, n)) % n):
                s += 1
        else:
            a, b = M[0]
            r = ceil_div(2 * (b * s - B2), n)
            while True:
                left = ceil_div(B2 + r * n, b)
                right = floor_div(B3m1 + r * n, a)
                found = None
                for cand_s in range(left, right + 1):
                    if ok((c0 * pow(cand_s, e, n)) % n):
                        found = cand_s
                        break
                if found is not None:
                    s = found
                    break
                r += 1
```
For real key sizes, this is why it can take “many queries”. For toy sizes, we can run the interval machinery and watch it converge. The only thing the attacker gets from the target is the oracle bit.

Run it:
python3 code/main.py

## Use It

- Do not use RSAES-PKCS1-v1_5 for new designs. Prefer a modern KEM or hybrid key exchange.
- If you must support PKCS#1 v1.5 decryption for interoperability: use uniform errors and constant-time, standards-aligned rejection handling.
- Prefer vetted protocol stacks; do not hand-roll RSA decrypt endpoints.

## Pitfalls

- Distinguishable failures: “bad padding” vs “bad key” vs “bad format”.
- Exception text or logging that reveals decode stage.
- Early exit on the first failed byte (timing oracle).
- Loose parsing (“accept near-miss encodings”) that widens the oracle surface.
- Assuming “it’s just one bit” cannot leak a full plaintext.

## Ship It

Save a PR-review checklist for spotting RSA padding-oracle risk: `outputs/rsa-pkcs1v15-oracle-checklist.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe the recovered message and the oracle call count.
2. Medium. Change the message byte and PS, rerun, and compare oracle call counts.
3. Hard. Modify the oracle to leak different reject reasons and show how that speeds recovery in the toy demo.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| PKCS#1 v1.5 padding | “RSA padding” | A format `00 02 PS 00 M` whose validity can be tested by an oracle |
| Conformant | “Valid padding” | `EM` satisfies structural checks and lies in `[2B, 3B-1]` |
| Adaptive chosen-ciphertext | “Attacker can query decrypt” | Attacker crafts queries based on previous accept/reject answers |
| OAEP | “Modern RSA padding” | A design intended to be secure against chosen-ciphertext attacks (with correct implementation) |

## Further Reading

- Bleichenbacher, “Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1” (1998) — the original attack
- RFC 8017 (PKCS#1 v2.2), “RSAES-PKCS1-v1_5” and security considerations — standard guidance and mitigations
