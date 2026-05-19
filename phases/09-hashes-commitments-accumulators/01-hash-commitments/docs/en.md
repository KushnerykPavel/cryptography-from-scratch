# Hash-Based Commitments
> Commit now, reveal later — without being able to change your mind.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 07 · 09 (SHA-256)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain hiding vs binding for commitments.
- Implement `commit(m, r)` and `verify(c, m, r)` using SHA-256.
- Distinguish safe length-prefix encoding from naive concatenation.
- Apply nonce selection rules to avoid dictionary attacks.
- Compute commitments and validate openings with test vectors.

## The Problem

You want to make a claim now (a choice, a prediction, a bid, a vote), but you
don’t want to reveal it yet. Later, you want to prove you didn’t change it.

Without a commitment scheme, you’re stuck: if you publish the value, you leak
it; if you keep it secret, you can change it later and nobody can prove you
did. This shows up everywhere: sealed-bid auctions, commit-reveal randomness
beacons, on-chain games, password-reset challenges, and even protocol design
work (“we committed to these parameters before seeing the adversary’s data”).

A commitment is the cryptographic version of a sealed envelope: you publish a
small “sealed” string now, and later you open it by revealing the contents and
the randomness that sealed it.

## The Concept

A (non-interactive) commitment scheme has two phases:

- **Commit:** choose message `m` and randomness `r`, output commitment `c`.
- **Open:** reveal `(m, r)`. Anyone can check that it matches `c`.

It should satisfy:

- **Hiding:** from `c` alone, it’s hard to learn `m` (until you open).
- **Binding:** after publishing `c`, it’s hard to open it to a *different* `m'`.

The simplest practical commitment uses a cryptographic hash:

```
c = H(encode(m, r))
```

Where `encode` is an unambiguous encoding of `(m, r)` and `r` is fresh random
bytes (a nonce / salt / blinding factor).

Two facts drive almost every real-world mistake:

1. If you commit as `H(m)`, it’s usually **not hiding** because attackers can
   guess `m` from a small message space.
2. If you commit as `H(m || r)` without lengths or structure, you can get
   **ambiguous openings**: two different `(m, r)` pairs that produce the same
   concatenation.

## Build It

### Step 1: SHA-256 and unambiguous encoding

We encode `(m, r)` as:

```
domain || u32be(len(m)) || m || u32be(len(r)) || r
```

The domain string (“domain separation”) prevents cross-protocol confusion
when the same hash is reused in multiple places. The length prefixes prevent
`(m, r)` ambiguity.

```python
import hashlib
import hmac
import secrets
import struct


COMMITMENT_DOMAIN = b"CFSC-HASH-COMMIT-v1"


def sha256_hex(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).hexdigest()


def _u32be(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("length out of range for u32")
    return struct.pack(">I", n)


def encode_commit_input(*, message: bytes, nonce: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise TypeError("nonce must be bytes-like")

    m = bytes(message)
    r = bytes(nonce)
    return COMMITMENT_DOMAIN + _u32be(len(m)) + m + _u32be(len(r)) + r
```

This gives you a single, unambiguous byte string that you can hash. The
length prefixes mean `(b"a", b"bc")` and `(b"ab", b"c")` are distinct.

### Step 2: Commit and verify (commit-reveal)

Commitment is just the SHA-256 hex digest of the encoded input. Verification
recomputes the digest and compares it in constant-time.

```python
def commit(*, message: bytes, nonce: bytes) -> str:
    return sha256_hex(encode_commit_input(message=message, nonce=nonce))


def _validate_commitment_hex(commitment_hex: str) -> str:
    if not isinstance(commitment_hex, str):
        raise TypeError("commitment_hex must be a string")
    cleaned = commitment_hex.strip().lower()
    if len(cleaned) != 64:
        raise ValueError("commitment_hex must be a 64-character SHA-256 hex digest")
    try:
        bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError("commitment_hex must be hex") from e
    return cleaned


def verify(*, commitment_hex: str, message: bytes, nonce: bytes) -> bool:
    expected = _validate_commitment_hex(commitment_hex)
    got = commit(message=message, nonce=nonce)
    return hmac.compare_digest(got, expected)


def commit_with_random_nonce(*, message: bytes, nonce_len: int = 32) -> tuple[str, bytes]:
    if nonce_len <= 0:
        raise ValueError("nonce_len must be positive")
    r = secrets.token_bytes(nonce_len)
    return commit(message=message, nonce=r), r
```

Operationally: publish `c`. Keep `r` secret. Later reveal `(m, r)` so anyone
can run `verify(c, m, r)`.

### Step 3: Why hiding needs a nonce (dictionary attack)

If you commit as `SHA256(m)` and `m` comes from a small set, an attacker can
precompute all possible hashes and learn `m` immediately. A nonce expands the
search space from “messages” to “messages × nonces”.

```python
def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def step3_hiding_needs_nonce() -> None:
    _print_step(3, "Why hiding needs a nonce (dictionary attack)")
    candidates = [b"red", b"green", b"blue", b"yellow"]
    secret_message = b"green"

    c_no_nonce = sha256_hex(secret_message)
    guessed = next((m for m in candidates if sha256_hex(m) == c_no_nonce), None)
    print(f"commit without nonce: c = SHA256(m) = {c_no_nonce}")
    print(f"attacker guesses m from 4 candidates -> {guessed!r}")

    nonce = b"\x00" * 32
    c_with_nonce = commit(message=secret_message, nonce=nonce)
    guessed2 = next((m for m in candidates if commit(message=m, nonce=nonce) == c_with_nonce), None)
    print(f"commit with nonce (but leaked nonce): c = {c_with_nonce}")
    print(f"attacker guesses if nonce is known -> {guessed2!r}")

    c_secret_nonce, secret_nonce = commit_with_random_nonce(message=secret_message, nonce_len=32)
    guessed3 = next((m for m in candidates if commit(message=m, nonce=secret_nonce) == c_secret_nonce), None)
    print(f"commit with secret nonce: c = {c_secret_nonce}")
    print("attacker cannot test candidates without r (even if m-space is small)")
    print(f"(after reveal) attacker can check: guessed -> {guessed3!r}")
```

Hiding is only as strong as your nonce: it must be long enough and must stay
secret until reveal. If `r` leaks, the attacker is back to brute-forcing `m`.

### Step 4: Pitfall: naive concatenation allows ambiguous openings

If you compute `SHA256(m || r)` with no structure, different `(m, r)` pairs
can produce the same concatenation and therefore the same commitment.

```python
def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def naive_commit(*, message: bytes, nonce: bytes) -> str:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise TypeError("nonce must be bytes-like")
    return sha256_hex(bytes(message) + bytes(nonce))


def step4_ambiguity_attack_on_naive_concat() -> None:
    _print_step(4, "Pitfall: naive concatenation allows ambiguous openings")
    m1, r1 = b"a", b"bc"
    m2, r2 = b"ab", b"c"
    c1 = naive_commit(message=m1, nonce=r1)
    c2 = naive_commit(message=m2, nonce=r2)
    print(f"naive_commit(a, bc) = {c1}")
    print(f"naive_commit(ab, c) = {c2}")
    print(f"same commitment from different (m, r) pairs: {c1 == c2}")

    safe1 = commit(message=m1, nonce=r1)
    safe2 = commit(message=m2, nonce=r2)
    print(f"commit(a, bc)  = {safe1}")
    print(f"commit(ab, c)  = {safe2}")
    print(f"length-prefix encoding prevents ambiguity: {safe1 != safe2}")
```

This isn’t a hash collision — it’s your encoding being ambiguous. The fix is
what you already did in Step 1: structured encoding with lengths.

Run it:
python3 code/main.py

## Use It

Hash-based commitments are used as a building block inside bigger systems:

- **Commit-reveal protocols:** publish `c` in round 1, reveal `(m, r)` in round 2 (on-chain randomness, sealed bids).
- **Bit commitment in protocols:** commit to a bit/string now, prove it later (usually via more advanced commitments).
- **Merkle trees / vector commitments:** use hashes as commitments to larger data structures.

Production equivalents and patterns:

- Use a modern hash (`SHA-256`, `SHA-3`, `BLAKE2/3`) and standard encodings.
- Prefer **domain separation** for every commitment type.
- Use `hmac.compare_digest` for comparing digests in constant-time.

## Pitfalls

1. **No nonce:** committing as `H(m)` is not hiding when `m` is guessable.
2. **Nonce too short:** an 8-bit or 16-bit nonce makes brute-force feasible.
3. **Nonce reuse:** if the same `r` is reused across different messages, you leak relationships and enable cross-guessing.
4. **Ambiguous encoding:** `H(m || r)` can be opened as two different `(m, r)` pairs if boundaries aren’t encoded.
5. **Wrong threat model:** hash commitments are only computationally binding/hiding; if you need stronger properties (selective openings, proofs, partial reveals), you need different commitment schemes.

## Ship It

Save and reuse the audit checklist in `outputs/prompt-hash-commitment-review.md` when you:

- review a commit-reveal protocol PR,
- design an API that stores “commitments” in a database,
- implement on-chain commitments and openings.

Use it as a quick gate: does the design have a nonce, safe encoding, and a
clear reveal phase with validation rules?

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that `naive_commit(a, bc)` equals `naive_commit(ab, c)` but `commit(a, bc)` differs from `commit(ab, c)`.
2. Medium. Extend `code/main.py` with a `commit_to_number(n: int)` helper that commits to a big-endian integer encoding, and add vectors/tests for it.
3. Hard. Design a commit-reveal flow for an auction or randomness beacon and use the checklist in `outputs/` to review your own design; then identify which parts would need Pedersen commitments (next lesson) instead of hashes.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Commitment | “A hash of something” | A two-phase scheme: publish `c` now, reveal `(m, r)` later, with hiding + binding properties. |
| Hiding | “Nobody can see the value” | Given only `c`, it’s hard to learn `m` (typically because `r` is secret and large). |
| Binding | “You can’t change it” | After publishing `c`, it’s hard to find `(m', r') ≠ (m, r)` that verifies. |
| Nonce / salt | “Some random bytes” | Fresh secret randomness that prevents offline guessing of `m`. |
| Domain separation | “A prefix string” | A context tag so the same hash can’t be reused across protocols without confusion. |

## Further Reading

- Wikipedia, Commitment scheme — a short overview of hiding/binding definitions and variants.
- FIPS 180-4, Secure Hash Standard — defines SHA-256.
- Boneh and Shoup, *A Graduate Course in Applied Cryptography* — commitment schemes and security proofs (commit-and-reveal patterns).
