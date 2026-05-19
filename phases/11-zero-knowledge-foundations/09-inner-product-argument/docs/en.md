# Inner Product Argument (IPA)

> Prove a dot product without sending the vectors.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 11 — `04-fiat-shamir`, `08-bulletproofs`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** how IPA compresses an \(n\)-length statement into \(O(\log n)\) messages
- **Compute** commitments of the form \(P' = \langle a, G\rangle + \langle b, H\rangle + \langle a,b\rangle Q\)
- **Implement** a Fiat–Shamir transcript that deterministically produces challenges
- **Distinguish** the toy group used here (\(\mathbb{Z}_p\) under addition) from real curve groups used in production
- **Apply** IPA verification logic, including tamper detection, to catch malformed proofs

## The Problem

You have two secret vectors \(a, b \in \mathbb{Z}_p^n\) and you want to convince a verifier that:
1) you know them, and 2) their inner product \(c = \langle a,b\rangle\) is consistent with a public commitment.

The naive proof is to reveal \(a\) and \(b\). That completely defeats the point in a privacy system (range proofs, ZK circuits, polynomial commitments), because those vectors are typically derived from secrets you *must not* leak.

The inner product argument is the “compression trick” that makes Bulletproofs- and Halo-style systems practical: you send only \(O(\log n)\) group elements, and the verifier checks the same statement without ever seeing the vectors.

## The Concept

### The single equation we want to prove

IPA focuses on a combined statement:

\[
P' = \langle a, G\rangle + \langle b, H\rangle + \langle a,b\rangle Q
\]

- \(a,b\) are secret vectors in \(\mathbb{Z}_p^n\)
- \(G,H\) are *public* vectors of group generators (also length \(n\))
- \(Q\) is a public “extra” generator used to bind the inner product term
- \(\langle a,G\rangle = \sum_i a_i G_i\) is a multi-scalar multiplication (MSM)

In real libraries, the “group elements” are elliptic curve points and MSM is expensive — so saving bandwidth and work matters.

In this lesson, we use a **toy additive group** where “points” are integers mod \(p\) and group addition is integer addition mod \(p\). This is *not secure*, but it makes the algebra easy to see.

### The folding idea (why it becomes \(O(\log n)\))

Split each vector in half: \(a=(a_{\text{lo}},a_{\text{hi}})\), same for \(b,G,H\).

The prover sends two “cross-term commitments”:

\[
\begin{aligned}
L &\gets \langle a_{\text{lo}}, G_{\text{hi}}\rangle + \langle b_{\text{hi}}, H_{\text{lo}}\rangle + \langle a_{\text{lo}}, b_{\text{hi}}\rangle Q \\
R &\gets \langle a_{\text{hi}}, G_{\text{lo}}\rangle + \langle b_{\text{lo}}, H_{\text{hi}}\rangle + \langle a_{\text{hi}}, b_{\text{lo}}\rangle Q
\end{aligned}
\]

Then the verifier challenges the prover with a nonzero scalar \(u\) (Fiat–Shamir makes this deterministic).

Both sides **fold** all vectors to half length using \(u\) and \(u^{-1}\). After one fold, you get the *same-shaped statement* but with vectors of length \(n/2\). Repeat \(\log_2 n\) times until a single coordinate remains.

## Build It

### Step 1: Field + vector helpers

These helpers give us: modular inverses, inner products, “group MSM” in our toy group, and the folding operations used in every IPA round.

```python
P: int = 2_147_483_647  # 2^31 - 1 (prime)


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def modinv(x: int, p: int = P) -> int:
    x %= p
    if x == 0:
        raise ValueError("inverse of 0 does not exist")
    return pow(x, p - 2, p)


def inner_product(a: Sequence[int], b: Sequence[int], p: int = P) -> int:
    if len(a) != len(b):
        raise ValueError("inner_product: length mismatch")
    acc = 0
    for ai, bi in zip(a, b):
        acc = (acc + (ai % p) * (bi % p)) % p
    return acc


def msm(scalars: Sequence[int], bases: Sequence[int], p: int = P) -> int:
    if len(scalars) != len(bases):
        raise ValueError("msm: length mismatch")
    acc = 0
    for s, g in zip(scalars, bases):
        acc = (acc + (s % p) * (g % p)) % p
    return acc


def fold_scalars(lo: Sequence[int], hi: Sequence[int], u: int, u_inv: int, p: int = P) -> list[int]:
    if len(lo) != len(hi):
        raise ValueError("fold_scalars: length mismatch")
    return [((x % p) * u + (y % p) * u_inv) % p for x, y in zip(lo, hi)]


def fold_generators_G(
    lo: Sequence[int], hi: Sequence[int], u: int, u_inv: int, p: int = P
) -> list[int]:
    if len(lo) != len(hi):
        raise ValueError("fold_generators_G: length mismatch")
    return [((g0 % p) * u_inv + (g1 % p) * u) % p for g0, g1 in zip(lo, hi)]


def fold_generators_H(
    lo: Sequence[int], hi: Sequence[int], u: int, u_inv: int, p: int = P
) -> list[int]:
    if len(lo) != len(hi):
        raise ValueError("fold_generators_H: length mismatch")
    return [((h0 % p) * u + (h1 % p) * u_inv) % p for h0, h1 in zip(lo, hi)]
```

### Step 2: Commit to vectors + their inner product

This is the one equation IPA is built around: \(P'\) binds both the vector commitment and the inner product \(\langle a,b\rangle\) using an extra generator \(Q\).

```python
def commit_pprime(
    a: Sequence[int],
    b: Sequence[int],
    G: Sequence[int],
    H: Sequence[int],
    Q: int,
    p: int = P,
) -> int:
    if not (len(a) == len(b) == len(G) == len(H)):
        raise ValueError("commit_pprime: length mismatch")
    c = inner_product(a, b, p)
    return (msm(a, G, p) + msm(b, H, p) + (c * (Q % p)) % p) % p
```

### Step 3: Fiat–Shamir transcript (deterministic challenges)

IPA needs a fresh nonzero challenge \(u\) each round. We get it by hashing everything the verifier would have seen so far (statement + prior messages).

```python
def _i2b(x: int) -> bytes:
    return int(x).to_bytes(32, "big", signed=False)


def hash_to_nonzero_scalar(msg: bytes, p: int = P) -> int:
    counter = 0
    while True:
        digest = hashlib.sha256(msg + counter.to_bytes(1, "big")).digest()
        x = int.from_bytes(digest, "big") % p
        if x != 0:
            return x
        counter = (counter + 1) % 256


class Transcript:
    def __init__(self, label: bytes):
        self._state = hashlib.sha256(b"transcript:" + label).digest()

    def append_bytes(self, label: str, data: bytes) -> None:
        h = hashlib.sha256()
        h.update(self._state)
        h.update(b"append:")
        h.update(label.encode("utf-8"))
        h.update(len(data).to_bytes(4, "big"))
        h.update(data)
        self._state = h.digest()

    def append_int(self, label: str, x: int) -> None:
        self.append_bytes(label, _i2b(x))

    def append_vector(self, label: str, xs: Sequence[int]) -> None:
        self.append_bytes(label + ".len", len(xs).to_bytes(4, "big"))
        for i, x in enumerate(xs):
            self.append_int(f"{label}[{i}]", x)

    def challenge_scalar(self, label: str, p: int = P) -> int:
        return hash_to_nonzero_scalar(self._state + b"challenge:" + label.encode("utf-8"), p)
```

### Step 4: Prover (produce \(L_j, R_j\) for \(\log_2 n\) rounds)

Each round sends two group elements \(L,R\), derives a challenge \(u\), then folds \(a,b,G,H\) to half length and repeats.

```python
@dataclass(frozen=True)
class InnerProductProof:
    Ls: list[int]
    Rs: list[int]
    a: int
    b: int


def _absorb_statement(transcript: Transcript, P_prime: int, G: Sequence[int], H: Sequence[int], Q: int) -> None:
    transcript.append_int("P'", P_prime)
    transcript.append_int("Q", Q)
    transcript.append_vector("G", G)
    transcript.append_vector("H", H)


def ipa_prove(
    a: Sequence[int],
    b: Sequence[int],
    G: Sequence[int],
    H: Sequence[int],
    Q: int,
    p: int = P,
    *,
    transcript_label: bytes = b"ipa-v1",
) -> tuple[int, InnerProductProof]:
    if not (len(a) == len(b) == len(G) == len(H)):
        raise ValueError("ipa_prove: length mismatch")
    if not is_power_of_two(len(a)):
        raise ValueError("ipa_prove: vector length must be a power of two")
    if Q % p == 0:
        raise ValueError("ipa_prove: Q must be nonzero")

    a_cur = [x % p for x in a]
    b_cur = [x % p for x in b]
    G_cur = [x % p for x in G]
    H_cur = [x % p for x in H]

    P_prime = commit_pprime(a_cur, b_cur, G_cur, H_cur, Q, p)

    transcript = Transcript(transcript_label)
    _absorb_statement(transcript, P_prime, G_cur, H_cur, Q)

    Ls: list[int] = []
    Rs: list[int] = []

    while len(a_cur) > 1:
        n = len(a_cur)
        n2 = n // 2
        a_lo, a_hi = a_cur[:n2], a_cur[n2:]
        b_lo, b_hi = b_cur[:n2], b_cur[n2:]
        G_lo, G_hi = G_cur[:n2], G_cur[n2:]
        H_lo, H_hi = H_cur[:n2], H_cur[n2:]

        L = (msm(a_lo, G_hi, p) + msm(b_hi, H_lo, p) + inner_product(a_lo, b_hi, p) * (Q % p)) % p
        R = (msm(a_hi, G_lo, p) + msm(b_lo, H_hi, p) + inner_product(a_hi, b_lo, p) * (Q % p)) % p

        Ls.append(L)
        Rs.append(R)

        transcript.append_int("L", L)
        transcript.append_int("R", R)
        u = transcript.challenge_scalar("u", p)
        u_inv = modinv(u, p)

        a_cur = fold_scalars(a_lo, a_hi, u, u_inv, p)
        b_cur = fold_scalars(b_lo, b_hi, u_inv, u, p)
        G_cur = fold_generators_G(G_lo, G_hi, u, u_inv, p)
        H_cur = fold_generators_H(H_lo, H_hi, u, u_inv, p)

    proof = InnerProductProof(Ls=Ls, Rs=Rs, a=a_cur[0], b=b_cur[0])
    return P_prime, proof
```

### Step 5: Verifier (fold the statement and check the final 1D equation)

Verification replays the transcript to get the same challenges, folds \(G,H\), and updates \(P'\) using \(u^2\) and \(u^{-2}\). At the end it checks a single-scalar relation.

```python
def ipa_verify(
    P_prime: int,
    G: Sequence[int],
    H: Sequence[int],
    Q: int,
    proof: InnerProductProof,
    p: int = P,
    *,
    transcript_label: bytes = b"ipa-v1",
) -> bool:
    if not (len(G) == len(H)):
        raise ValueError("ipa_verify: length mismatch")
    if not is_power_of_two(len(G)):
        raise ValueError("ipa_verify: vector length must be a power of two")
    if len(proof.Ls) != len(proof.Rs):
        raise ValueError("ipa_verify: malformed proof")
    if len(proof.Ls) != (len(G).bit_length() - 1):
        raise ValueError("ipa_verify: wrong proof length for vector size")
    if Q % p == 0:
        raise ValueError("ipa_verify: Q must be nonzero")

    P_cur = P_prime % p
    G_cur = [x % p for x in G]
    H_cur = [x % p for x in H]

    transcript = Transcript(transcript_label)
    _absorb_statement(transcript, P_prime % p, G_cur, H_cur, Q % p)

    for L, R in zip(proof.Ls, proof.Rs):
        transcript.append_int("L", L)
        transcript.append_int("R", R)
        u = transcript.challenge_scalar("u", p)
        u_inv = modinv(u, p)

        u2 = (u * u) % p
        u_inv2 = (u_inv * u_inv) % p

        P_cur = (P_cur + (L % p) * u2 + (R % p) * u_inv2) % p

        n2 = len(G_cur) // 2
        G_cur = fold_generators_G(G_cur[:n2], G_cur[n2:], u, u_inv, p)
        H_cur = fold_generators_H(H_cur[:n2], H_cur[n2:], u, u_inv, p)

    if len(G_cur) != 1 or len(H_cur) != 1:
        return False

    expected = ((proof.a % p) * G_cur[0] + (proof.b % p) * H_cur[0] + ((proof.a % p) * (proof.b % p)) * (Q % p)) % p
    return P_cur == expected
```

Run it:

```bash
python3 code/main.py
```

## Use It

Production systems use the same idea, but over elliptic curve groups with careful transcript design and highly optimized MSM:

- **Bulletproofs (Rust, dalek-cryptography):** an IPA is the core compression step used inside range proofs.
- **Halo2 / IPA polynomial commitments (Rust):** an IPA variant is used to open polynomial commitments in \(O(\log n)\) proof size.
- **ZK proof frameworks:** many “no trusted setup” systems pick IPA-based commitments to avoid pairings (at the cost of larger verifier work than KZG).

## Pitfalls

- **Forgetting domain separation:** if different protocols share a transcript hash state, challenges can collide across contexts.
- **Allowing zero challenges:** IPA needs \(u^{-1}\); if a transcript can output \(u=0\), proofs become undefined (or exploitable).
- **Not binding the statement in the transcript:** if \(P',G,H,Q\) aren’t absorbed, the same \(L,R\) list might “verify” under a different statement.
- **Non power-of-two vector lengths:** this simple implementation rejects them; production implementations pad and must do so consistently on both sides.
- **Reusing generators incorrectly:** \(G\) and \(H\) must be independent generators (unknown discrete log relation). Our toy group can’t model that security requirement.

## Ship It

This lesson ships an IPA review checklist you can use when reading or reviewing ZK code: `outputs/skill-inner-product-argument-review.md`.

Use it when:
- you’re reviewing an IPA implementation (Bulletproofs, Halo2, IPA-PCS), or
- you’re integrating a library and want to sanity-check transcript and verification logic.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that `verify(proof) = True` but `verify(tampered) = False`.
2. **Medium:** Change `demo_instance()` to use \(n=16\) (power of two), and print the number of rounds. Confirm it becomes \(\log_2(n)\).
3. **Hard:** Modify the transcript so it *does not* absorb `G` and `H`. Construct a second statement with different generators and show how dangerous this is conceptually (why “proofs must bind their statement”).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Inner Product Argument (IPA) | “A logarithmic-sized proof for a dot product” | A recursive protocol that folds vectors in half each round using verifier challenges |
| Folding | “Compress the vectors” | Replace \((x_{\text{lo}},x_{\text{hi}})\) with \(x_{\text{lo}}u + x_{\text{hi}}u^{-1}\) (and similarly fold generators) |
| MSM | “Multi-scalar multiplication” | Compute \(\sum_i s_i G_i\) efficiently; a core performance bottleneck in ZK |
| Fiat–Shamir | “Make it non-interactive” | Replace verifier randomness with transcript hashing so both sides derive the same challenges |
| Statement binding | “Hash the public inputs” | Absorb all public parameters into the transcript to prevent replay across statements |

## Further Reading

- Bootle et al., *Efficient Zero-Knowledge Arguments for Arithmetic Circuits in the Discrete Log Setting* (2016) — introduces logarithmic inner-product arguments.
- Bünz et al., *Bulletproofs: Short Proofs for Confidential Transactions and More* (2018) — uses IPA as the core compression step in range proofs.
- The Halo2 Book, *Polynomial commitment using inner product argument* (ongoing) — explains how IPA becomes a polynomial commitment opening proof.
