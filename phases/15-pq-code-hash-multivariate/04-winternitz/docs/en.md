# Winternitz One-Time Signatures (WOTS+)
> Turn a huge Lamport signature into a small set of hash chains — and never reuse the key.

**Type:** Build
**Languages:** Python
**Prerequisites:** `../03-lamport/`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how Winternitz compresses Lamport OTS using hash chains
- **Compute** `len_1`, `len_2`, and `len` from `n` and `w`
- **Implement** base-`w` conversion + checksum (RFC 8391 style)
- **Distinguish** WOTS vs WOTS+ (what “+” adds, what it doesn’t)
- **Apply** signing + verification, and predict what breaks if you reuse a key

## The Problem
Lamport one-time signatures are conceptually clean and post-quantum-friendly, but their size is painful: you need to publish and partially reveal *lots* of random values. That’s fine in a toy lesson; it becomes a real engineering problem as soon as you want “many signatures” via Merkle trees (next lessons).

Winternitz one-time signatures (WOTS / WOTS+) fix the size problem by replacing “one secret per bit” with “one secret per *digit*”, where each digit lives on a hash chain. This trades signature size for hash work and becomes the standard building block inside XMSS, LMS, and SPHINCS+.

If you don’t understand WOTS, you’ll get stuck later when you need to: (1) compute correct parameters, (2) map messages to base-`w` digits, (3) build/verify signatures, and (4) respect the one-time rule so you don’t ship an instant “funds can be stolen after reuse” class of bug.

## The Concept
Think of a **hash chain**:

```
sk_i -> H(sk_i) -> H^2(sk_i) -> ... -> H^(w-1)(sk_i) = pk_i
```

If you ever reveal an intermediate value `H^a(sk_i)`, anyone can move *forward* to `H^(a+1)(sk_i)`, `H^(a+2)(sk_i)`, … but (assuming `H` is one-way) cannot move backwards to smaller exponents.

WOTS uses this “forward-only” property to sign a message digest **digit-by-digit**:

- Choose a base `w` (in RFC 8391: `w ∈ {4, 16}`).
- Represent the `n`-byte message digest as `len_1` base-`w` digits.
- Append `len_2` checksum digits so you can’t “only increase digits” to forge.
- For each digit `d_i`, the signature reveals `sig_i = H^{d_i}(sk_i)`.
- The public key is `pk_i = H^{w-1}(sk_i)`.
- Verification “completes the chain” by hashing `sig_i` exactly `(w-1-d_i)` times.

Parameter formulas (RFC 8391):

- `len_1 = ceil(8n / lg(w))`
- `len_2 = floor(lg(len_1 * (w - 1)) / lg(w)) + 1`
- `len = len_1 + len_2`

## Build It
### Step 1: Parameters, base-w digits, checksum
```python
DEFAULT_N = 32
DEFAULT_W = 16  # RFC 8391 uses w in {4, 16}


@dataclass(frozen=True)
class WOTSParams:
    n: int
    w: int
    lg_w: int
    len_1: int
    len_2: int
    length: int


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def wots_params(n: int = DEFAULT_N, w: int = DEFAULT_W) -> WOTSParams:
    if n <= 0:
        raise ValueError("n must be positive")
    if w not in (4, 16):
        raise ValueError("w must be 4 or 16 (RFC 8391 parameter sets)")
    lg_w = int(math.log2(w))
    if (1 << lg_w) != w:
        raise ValueError("w must be a power of two")

    len_1 = math.ceil((8 * n) / lg_w)
    len_2 = math.floor(math.log2(len_1 * (w - 1)) / math.log2(w)) + 1
    return WOTSParams(n=n, w=w, lg_w=lg_w, len_1=len_1, len_2=len_2, length=len_1 + len_2)


def base_w(x: bytes, w: int, out_len: int) -> List[int]:
    """
    Convert bytes to base-w digits as in RFC 8391, Algorithm 1 (base_w).

    For w in {4,16}, lg(w) is 2 or 4, so digits are extracted in big-endian
    order by consuming lg(w) bits at a time.
    """
    params = wots_params(n=1, w=w)
    lg_w = params.lg_w
    max_out = (8 * len(x)) // lg_w
    if out_len < 0 or out_len > max_out:
        raise ValueError("out_len too large for input length and w")

    in_idx = 0
    total = 0
    bits = 0
    out: List[int] = []

    for _ in range(out_len):
        if bits == 0:
            total = x[in_idx]
            in_idx += 1
            bits = 8
        bits -= lg_w
        out.append((total >> bits) & (w - 1))
    return out


def _to_byte(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    return x.to_bytes(length, "big")


def _wots_checksum(msg_base_w: Sequence[int], w: int, len_2: int) -> List[int]:
    lg_w = int(math.log2(w))
    csum = sum((w - 1 - d) for d in msg_base_w)
    shift = (8 - ((len_2 * lg_w) % 8)) % 8
    csum <<= shift
    len_2_bytes = math.ceil((len_2 * lg_w) / 8)
    return base_w(_to_byte(csum, len_2_bytes), w, len_2)


def wots_message_digits(message: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[int]:
    """
    Hash an arbitrary message to n bytes and convert it to len base-w digits,
    including the checksum digits (RFC 8391, Algorithms 5/6).
    """
    p = wots_params(n=n, w=w)
    digest = sha256(message)[:n]
    msg_digits = base_w(digest, w, p.len_1)
    csum_digits = _wots_checksum(msg_digits, w=w, len_2=p.len_2)
    return msg_digits + csum_digits
```
This step turns an arbitrary message into a *fixed-length* list of base-`w` digits (message digits + checksum digits). The checksum is the key insight: it couples all digits so an attacker can’t take a signature and “only move forward” on some digit chains to forge another valid message.

### Step 2: Hash chains and deterministic private key
```python
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def chain(x: bytes, steps: int) -> bytes:
    if steps < 0:
        raise ValueError("steps must be non-negative")
    y = x
    for _ in range(steps):
        y = sha256(y)
    return y


def wots_private_key_from_seed(sk_seed: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    """
    Deterministically derive the WOTS private key elements from a seed.

    Real WOTS+ derives elements via a PRF keyed by a secret seed plus addresses.
    Here we use HMAC-SHA256(SK.seed, b\"WOTS-SK\" || i32) and truncate to n bytes.
    """
    if len(sk_seed) < 16:
        raise ValueError("sk_seed too short; use at least 16 bytes")
    p = wots_params(n=n, w=w)
    out: List[bytes] = []
    for i in range(p.length):
        i32 = i.to_bytes(4, "big")
        out.append(hmac_sha256(sk_seed, b"WOTS-SK" + i32)[:n])
    return out
```
WOTS needs `len` independent secret “chain starts”. In real WOTS+ you derive them from a secret seed and an address; here we use HMAC as a deterministic PRF so the lesson is reproducible and testable without external dependencies.

### Step 3: Public key from private key (commitments)
```python
def wots_public_key_from_private(sk: Sequence[bytes], n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    p = wots_params(n=n, w=w)
    if len(sk) != p.length:
        raise ValueError("wrong private key length for parameters")
    for x in sk:
        if len(x) != n:
            raise ValueError("wrong private key element length")
    return [chain(sk[i], w - 1) for i in range(p.length)]


def wots_keypair_from_seed(sk_seed: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> Tuple[List[bytes], List[bytes]]:
    sk = wots_private_key_from_seed(sk_seed, n=n, w=w)
    pk = wots_public_key_from_private(sk, n=n, w=w)
    return sk, pk
```
The public key is just “the end of every chain”: `pk[i] = H^{w-1}(sk[i])`. Publishing `pk` commits you to all chain starts without revealing any of them.

### Step 4: Sign and verify
```python
def wots_sign(message: bytes, sk_seed: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    p = wots_params(n=n, w=w)
    digits = wots_message_digits(message, n=n, w=w)
    if len(digits) != p.length:
        raise AssertionError("internal error: digits length mismatch")
    sk = wots_private_key_from_seed(sk_seed, n=n, w=w)
    return [chain(sk[i], digits[i]) for i in range(p.length)]


def wots_public_key_from_signature(signature: Sequence[bytes], message: bytes, n: int = DEFAULT_N, w: int = DEFAULT_W) -> List[bytes]:
    p = wots_params(n=n, w=w)
    if len(signature) != p.length:
        raise ValueError("wrong signature length for parameters")
    for x in signature:
        if len(x) != n:
            raise ValueError("wrong signature element length")
    digits = wots_message_digits(message, n=n, w=w)
    return [chain(signature[i], (w - 1) - digits[i]) for i in range(p.length)]


def wots_verify(signature: Sequence[bytes], message: bytes, public_key: Sequence[bytes], n: int = DEFAULT_N, w: int = DEFAULT_W) -> bool:
    p = wots_params(n=n, w=w)
    if len(public_key) != p.length:
        raise ValueError("wrong public key length for parameters")
    derived = wots_public_key_from_signature(signature, message, n=n, w=w)
    return list(public_key) == derived
```
Signing reveals one intermediate node per chain; verifying hashes each node forward the remaining number of steps until it reaches the public key. This is why the scheme is one-time: every signature leaks structured information about the chains.

Run it:
`python3 code/main.py`

## Use It
You almost never deploy “raw WOTS” directly. Instead, you use it as an internal building block:

- **XMSS / XMSS^MT (RFC 8391):** WOTS+ is the one-time signature used at each Merkle leaf.
- **SPHINCS+:** uses WOTS+ as part of its hypertree construction.
- **LMS / LM-OTS (RFC 8554):** a closely related Winternitz-style construction with different encoding details.

Production implementations are careful about domain separation (addresses), per-step bitmasks, and constant-time behavior. This lesson intentionally keeps the math visible by using plain SHA-256 chains.

## Pitfalls
- **Reusing a WOTS key:** signing twice with the same chain starts leaks multiple intermediate nodes; attackers can often combine them into forgeries.
- **Skipping or miscomputing the checksum:** without it, attackers can “hash forward” on some digits to forge new messages.
- **Wrong base-`w` encoding (endianness / bit extraction):** base conversion bugs are silent and lead to signatures that never verify.
- **Mixing parameters between signer and verifier:** `n` and `w` determine lengths; a mismatch looks like random failure.
- **Treating this code as production:** the demo is not constant-time, doesn’t use WOTS+ address/mask randomization, and doesn’t authenticate the public key.

## Ship It
Save the reusable checklist from `outputs/winternitz-audit-checklist.md` and use it when:

- Reviewing an XMSS/LMS/SPHINCS+ implementation
- Auditing a PR that adds “hash-chain signatures” or “one-time keys”
- Writing a threat model section for “stateful signature keys”

It’s designed to be copy-pasted into a PR review comment or an internal security ticket.

## Exercises
1. **Easy:** Run `python3 code/main.py`. Observe how the checksum digits change when the message changes by one byte.
2. **Medium:** Change `DEFAULT_W` to `4` and `16` (keeping `n=32`). Compare `len` and how many hashes verification does on average.
3. **Hard:** Write a small wrapper that compresses the `len`-element public key into a single digest (`sha256(concat(pk))`) and treat that digest as the “published” public key. Update verification to compare digests.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Hash chain | “Repeated hashing” | A forward-only sequence `x, H(x), H^2(x), …` |
| Winternitz parameter (`w`) | “Controls signature size” | Base for digits and chain length; larger `w` → fewer chains but more hashing |
| `len_1`, `len_2`, `len` | “WOTS lengths” | How many digit chains you need for message + checksum |
| Checksum digits | “Forgery prevention” | Forces any increase in message digits to be paid by a decrease elsewhere |
| One-time signature | “Use once” | Security requires each secret key be used to sign at most one message |

## Further Reading
- A. Hülsing et al., *RFC 8391: XMSS: eXtended Merkle Signature Scheme* (2018) — defines WOTS+ parameters, base-`w`, and verification.
- A. Hülsing, *SPHINCS+ specification* (NIST PQC submission) — shows WOTS+ as a building block in a stateless hash-based scheme.
- J. Buchmann et al., *On the security of the Winternitz one-time signature scheme* (2013) — deeper security discussion and trade-offs.
