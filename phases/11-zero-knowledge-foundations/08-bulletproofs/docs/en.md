# Bulletproofs (Core): The Inner Product Argument
> Halve the vectors, keep the truth.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/11-zero-knowledge-foundations/04-fiat-shamir`, `phases/11-zero-knowledge-foundations/07-range-proofs`, `phases/11-zero-knowledge-foundations/02-sigma-protocols`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Bulletproofs proofs are logarithmic-size (and what gets “folded” each round).
- Compute the commitments `L_j, R_j` and the Fiat–Shamir challenges `u_j` for one folding round.
- Implement a toy Bulletproofs-style inner product proof (`ipa_prove`) and verifier (`ipa_verify`) from scratch.
- Distinguish what this lesson implements (IPA core) from what full Bulletproofs range proofs add on top (bit-decomposition + polynomial identities + blinding).
- Apply a review checklist to catch transcript-binding and parameter-shape bugs in real Bulletproofs integrations.

## The Problem

You want to prove something about a *hidden* value — e.g. “this committed amount is in range” — without revealing the value. Range proofs show up everywhere: confidential transactions, privacy-preserving accounting, and modern ZK-friendly constraint systems.

The catch is bandwidth. The naive way to prove a vector relation is to just send the vectors. If the witness is length `n`, that’s `O(n)` scalars — which becomes huge once `n` is tied to a bit-length (like 64-bit ranges) or to circuit size.

Bulletproofs fixes this: it produces **short proofs without a trusted setup**, with proof size that grows like `O(log n)`. The engine inside Bulletproofs is a compact **inner product argument (IPA)**: instead of sending two length-`n` vectors, you send only `2·log2(n)` group elements (plus two final scalars).

## The Concept

Bulletproofs range proofs reduce a range statement to an inner product statement. The details of the reduction (bit decomposition, polynomials, and blinding) are real work — but the reusable core is the same every time:

> Prove knowledge of vectors `a, b ∈ Z_q^n` such that a commitment `P'` opens to them, *and* their inner product is consistent.

We’ll use additive notation in a prime-order group `G` of order `q`. In production `G` is an elliptic-curve group (Ristretto/Curve25519, secp256k1, etc.). In this lesson we use a **toy group** where group elements are just integers modulo `q`. This keeps the demo stdlib-only and makes the folding math visible.

### The statement we prove

Given:

- generator vectors `G = (G_0..G_{n-1})`, `H = (H_0..H_{n-1})` (random-looking, no known relations),
- a separate generator `Q`,
- a group element `P'`,

the prover claims knowledge of vectors `a, b ∈ Z_q^n` such that:

```
P' = <a, G> + <b, H> + <a, b> · Q
```

where:

- `<a, G> = Σ_i a_i · G_i` is a multiscalar multiplication,
- `<a, b> = Σ_i a_i · b_i` is a field inner product.

### The folding idea (why it becomes logarithmic)

Assume `n` is a power of two. Split each vector into halves:

- `a = (a_lo || a_hi)`, `b = (b_lo || b_hi)`
- `G = (G_lo || G_hi)`, `H = (H_lo || H_hi)`

The prover sends two “cross-term commitments”:

- `L = <a_lo, G_hi> + <b_hi, H_lo> + <a_lo, b_hi>·Q`
- `R = <a_hi, G_lo> + <b_lo, H_hi> + <a_hi, b_lo>·Q`

Then the verifier samples a challenge `u ∈ Z_q*` (we make it non-interactive via Fiat–Shamir), and both sides **fold**:

- `a ← a_lo·u + a_hi·u^{-1}`
- `b ← b_lo·u^{-1} + b_hi·u`
- `G ← G_lo·u^{-1} + G_hi·u`
- `H ← H_lo·u + H_hi·u^{-1}`

Now the same statement holds but for length `n/2`. Repeat `log2(n)` times and you end with a single pair `(a_final, b_final)`.

## Build It

### Step 1: A transcript and deterministic generators (toy Fiat–Shamir)
```python
def _i2osp(x: int) -> bytes:
    if x < 0:
        raise ValueError("cannot encode negative integers")
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


class Transcript:
    def __init__(self) -> None:
        self._state = bytearray()

    def append_message(self, label: bytes, message: bytes) -> None:
        self._state.extend(len(label).to_bytes(4, "big"))
        self._state.extend(label)
        self._state.extend(len(message).to_bytes(8, "big"))
        self._state.extend(message)

    def append_int(self, label: bytes, x: int) -> None:
        self.append_message(label, _i2osp(x))

    def innerproduct_domain_sep(self, n: int) -> None:
        self.append_message(b"dom-sep", b"ipp-toy v1")
        self.append_int(b"n", n)

    def challenge_scalar(self, label: bytes, q: int) -> int:
        h = sha256()
        h.update(bytes(self._state))
        h.update(b"\x00")
        h.update(label)
        digest = h.digest()
        x = int.from_bytes(digest, "big") % q
        if x == 0:
            x = 1
        self.append_int(label, x)
        return x


def derive_generators(n: int, q: int, seed: bytes) -> list[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    out: list[int] = []
    for i in range(n):
        h = sha256()
        h.update(seed)
        h.update(b"\x00")
        h.update(i.to_bytes(4, "big"))
        x = int.from_bytes(h.digest(), "big") % q
        if x == 0:
            x = 1
        out.append(x)
    return out
```
Fiat–Shamir means “the verifier’s randomness comes from hashing the transcript.”
So we need a transcript that (a) commits to everything that should be bound, and
(b) can deterministically derive challenges `u`. We also need deterministic
“generators” for a runnable demo, so we derive them from seeds with SHA-256.

### Step 2: Commit to vectors and their inner product
```python
def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def inv_q(x: int, q: int) -> int:
    x = x % q
    if x == 0:
        raise ValueError("0 has no inverse in Z_q")
    return pow(x, q - 2, q)


def inner_product(q: int, a: list[int], b: list[int]) -> int:
    if len(a) != len(b):
        raise ValueError("inner product requires equal-length vectors")
    return sum((ai % q) * (bi % q) for ai, bi in zip(a, b, strict=True)) % q


def msm(q: int, scalars: Iterable[int], points: Iterable[int]) -> int:
    acc = 0
    for s, P in zip(scalars, points, strict=True):
        acc = (acc + (s % q) * (P % q)) % q
    return acc


def assert_ipa_params(q: int, G: list[int], H: list[int], Q: int) -> None:
    if q <= 2:
        raise ValueError("q must be a prime > 2 (not validated here)")
    if len(G) != len(H):
        raise ValueError("G and H must have the same length")
    if not is_power_of_two(len(G)):
        raise ValueError("vector length must be a power of two")
    if any((g % q) == 0 for g in G):
        raise ValueError("G contains identity point (0)")
    if any((h % q) == 0 for h in H):
        raise ValueError("H contains identity point (0)")
    if (Q % q) == 0:
        raise ValueError("Q must be non-identity")


def ipa_commit(q: int, G: list[int], H: list[int], Q: int, a: list[int], b: list[int]) -> int:
    if len(a) != len(G) or len(b) != len(H):
        raise ValueError("vector length mismatch")
    c = inner_product(q, a, b)
    return (msm(q, a, G) + msm(q, b, H) + c * (Q % q)) % q
```
This sets up the statement `P' = <a,G> + <b,H> + <a,b>·Q`. In a real Bulletproofs
range proof, `a` and `b` encode “bit” constraints and polynomial identities; the
IPA is the compression mechanism that avoids sending those vectors directly.

### Step 3: Prove by recursive folding (the Bulletproofs IPA)
```python
@dataclass(frozen=True)
class InnerProductProof:
    """Bulletproofs-style inner product proof: (L_k, R_k, ..., L_1, R_1, a, b)."""

    Ls: list[int]
    Rs: list[int]
    a: int
    b: int


T = TypeVar("T")


def _split_half(v: list[T]) -> tuple[list[T], list[T]]:
    mid = len(v) // 2
    return (v[:mid], v[mid:])


def ipa_prove(q: int, G: list[int], H: list[int], Q: int, a: list[int], b: list[int]) -> tuple[int, InnerProductProof]:
    """Produce a non-interactive inner product proof (toy Fiat–Shamir).

    Returns (P_prime, proof) where:
      P_prime = <a,G> + <b,H> + <a,b>*Q
    """
    assert_ipa_params(q, G, H, Q)
    if len(a) != len(G) or len(b) != len(H):
        raise ValueError("vector length mismatch")

    n = len(a)
    transcript = Transcript()
    transcript.innerproduct_domain_sep(n)

    P_prime = ipa_commit(q, G, H, Q, a, b)
    transcript.append_int(b"P", P_prime)
    transcript.append_int(b"Q", Q % q)

    G_round = [g % q for g in G]
    H_round = [h % q for h in H]
    a_round = [x % q for x in a]
    b_round = [x % q for x in b]

    Ls: list[int] = []
    Rs: list[int] = []

    while len(a_round) > 1:
        a_lo, a_hi = _split_half(a_round)
        b_lo, b_hi = _split_half(b_round)
        G_lo, G_hi = _split_half(G_round)
        H_lo, H_hi = _split_half(H_round)

        c_L = inner_product(q, a_lo, b_hi)
        c_R = inner_product(q, a_hi, b_lo)

        L = (msm(q, a_lo, G_hi) + msm(q, b_hi, H_lo) + c_L * (Q % q)) % q
        R = (msm(q, a_hi, G_lo) + msm(q, b_lo, H_hi) + c_R * (Q % q)) % q

        Ls.append(L)
        Rs.append(R)

        transcript.append_int(b"L", L)
        transcript.append_int(b"R", R)
        u = transcript.challenge_scalar(b"u", q)
        u_inv = inv_q(u, q)

        a_round = [(alo * u + ahi * u_inv) % q for alo, ahi in zip(a_lo, a_hi, strict=True)]
        b_round = [(blo * u_inv + bhi * u) % q for blo, bhi in zip(b_lo, b_hi, strict=True)]
        G_round = [(glo * u_inv + ghi * u) % q for glo, ghi in zip(G_lo, G_hi, strict=True)]
        H_round = [(hlo * u + hhi * u_inv) % q for hlo, hhi in zip(H_lo, H_hi, strict=True)]

    proof = InnerProductProof(Ls=Ls, Rs=Rs, a=a_round[0], b=b_round[0])
    return (P_prime, proof)
```
Each round computes “cross-term” commitments `(L, R)`, then hashes them into a
challenge `u` and folds everything in half. After `k = log2(n)` rounds, the
prover sends only `(L_1..L_k, R_1..R_k, a_final, b_final)`.

### Step 4: Verify using the same Fiat–Shamir challenges
```python
def _u_challenges(q: int, n: int, P_prime: int, Q: int, proof: InnerProductProof) -> list[int]:
    transcript = Transcript()
    transcript.innerproduct_domain_sep(n)
    transcript.append_int(b"P", P_prime)
    transcript.append_int(b"Q", Q % q)

    us: list[int] = []
    for L, R in zip(proof.Ls, proof.Rs, strict=True):
        transcript.append_int(b"L", L % q)
        transcript.append_int(b"R", R % q)
        us.append(transcript.challenge_scalar(b"u", q))
    return us


def _s_vector(q: int, us: list[int]) -> list[int]:
    k = len(us)
    n = 1 << k
    inv_us = [inv_q(u, q) for u in us]

    s: list[int] = []
    for i in range(n):
        si = 1
        for idx in range(k):
            bit_index = k - 1 - idx
            if ((i >> bit_index) & 1) == 1:
                si = (si * us[idx]) % q
            else:
                si = (si * inv_us[idx]) % q
        s.append(si)
    return s


def ipa_verify(q: int, G: list[int], H: list[int], Q: int, P_prime: int, proof: InnerProductProof) -> bool:
    try:
        assert_ipa_params(q, G, H, Q)
    except ValueError:
        return False
    n = len(G)
    if len(proof.Ls) != len(proof.Rs):
        return False
    if n != (1 << len(proof.Ls)):
        return False

    try:
        us = _u_challenges(q, n, P_prime, Q, proof)
    except ValueError:
        return False

    u2 = [(u * u) % q for u in us]
    uinv2 = [inv_q(x, q) for x in u2]

    s = _s_vector(q, us)
    inv_s = [inv_q(x, q) for x in s]

    a = proof.a % q
    b = proof.b % q

    rhs = (msm(q, [(a * si) % q for si in s], G) + msm(q, [(b * isi) % q for isi in inv_s], H)) % q
    rhs = (rhs + (a * b) % q * (Q % q)) % q

    for L, R, uu2, uui2 in zip(proof.Ls, proof.Rs, u2, uinv2, strict=True):
        rhs = (rhs - (L % q) * uu2) % q
        rhs = (rhs - (R % q) * uui2) % q

    return (P_prime % q) == rhs
```
The verifier replays Fiat–Shamir to get the same challenges `u_j`, then checks a
single equation that accounts for all folding rounds. In real libraries this is
implemented as a single multiscalar multiplication over curve points.

Run it:
python3 code/main.py

## Use It

Production-grade Bulletproofs implementations run this protocol over an elliptic-curve group and use a proper transcript (Merlin) and constant-time scalar arithmetic.

- Rust: `dalek-cryptography/bulletproofs` (Ristretto/Curve25519) — reference-quality implementation with range proofs and IPA.
- C: `libsecp256k1` Bulletproofs code — used in confidential-transaction stacks.
- Cryptocurrencies: Monero adopted Bulletproofs range proofs to reduce transaction size (and then iterated to Bulletproofs+).

## Pitfalls

1. **Transcript not bound to the statement.** If your challenges don’t commit to `P'`, generator sets, and protocol domain separators, you get malleability bugs.
2. **Wrong vector shape.** IPA assumes `n` is a power of two (or you must pad deterministically). Off-by-one padding breaks verification.
3. **Generator reuse / relations.** If `G_i` and `H_i` are derived incorrectly (or adversary-controlled), binding can fail.
4. **Non-constant-time scalar ops.** IPA is full of inversions and conditional branches; leaking `u`-dependent paths can leak witness structure.
5. **Serialization ambiguity.** If transcript bytes are ambiguous (missing length prefixes / endian bugs), prover and verifier can derive different challenges.

## Ship It

This lesson ships a reusable security review prompt for Bulletproofs/IPA integrations:

- `outputs/prompt-bulletproofs-ipa-review-checklist.md`

Use it when reviewing PRs that “add Bulletproofs range proofs” or “verify an inner product proof”: it forces transcript binding, parameter checks, and serialization sanity checks.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how proof size scales like `2·log2(n)` group elements, not `2·n` scalars.
2. Medium. Change `n` in `code/main.py` to `16` and update `a, b` accordingly. Verify that the proof round count increases by 1 and verification still passes.
3. Hard. Replace the toy group `Z_q` with a real curve group in a production library (e.g. Rust `bulletproofs` crate) and map the transcript items in this lesson to Merlin transcript calls.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Bulletproofs | “short range proofs” | A protocol family that reduces range (and R1CS) statements to inner product proofs with logarithmic proof size. |
| IPA (Inner Product Argument) | “prove an inner product” | A recursive folding proof that replaces sending vectors `(a,b)` with `O(log n)` commitments plus final scalars. |
| Fiat–Shamir | “make it non-interactive” | Derive verifier challenges by hashing a transcript that binds the statement and all prover messages. |
| Transcript | “hash everything” | A structured byte accumulator (with domain separation and unambiguous encoding) used to derive challenges. |
| Multiscalar multiplication | “sum of scalar·point” | The group computation `<a,G> = Σ a_i·G_i`; the hot path in real Bulletproofs verifiers. |

## Further Reading

- Bünz et al., *Bulletproofs: Short Proofs for Confidential Transactions and More* (2018) — the original construction and range proof applications.
- Dalek Bulletproofs docs, *Inner product protocol notes* — implementation-oriented derivation of the prover and verifier equations.
- ZKDocs, *Inner Product Argument* — a step-by-step conceptual buildup from vector commitments to Fiat–Shamir IPA.
