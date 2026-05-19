# Chaum–Pedersen Equality of Discrete Logs
> One nonce, two equations: prove it’s the same `x`.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/11-zero-knowledge-foundations/02-sigma-protocols`, `phases/11-zero-knowledge-foundations/04-fiat-shamir`, `phases/01-number-theory/03-modular-inverse-and-fast-exp`, `phases/02-abstract-algebra/02-cyclic-groups`
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what a DLEQ proof (Chaum–Pedersen) proves and what it does not.
- Compute the verification equations for a Chaum–Pedersen transcript `(a1, a2, c, s)`.
- Implement a toy Chaum–Pedersen prover, verifier, simulator, and extractor in a prime-order subgroup.
- Distinguish interactive challenges from Fiat–Shamir challenges (and why transcript binding matters).
- Apply a nonce-reuse extractor to recover `x` from two accepting transcripts.

## The Problem

You’re building a system where *two different* public values must be tied to the
*same secret exponent* without revealing that exponent. The classic example is
ElGamal-style encryption or commitments: you want to convince someone that two
group elements were formed using the same secret `x`, but you don’t want to leak
`x` itself.

Without a “same exponent” proof, systems drift into unsafe patterns:
people send the secret (bad), or they rely on ad-hoc checks (“looks consistent”),
or they prove only one relation and forget to bind the other. In real protocols,
that kind of gap turns into exploitable malleability, replay, or “proofs” that
don’t actually prove the intended statement.

Chaum–Pedersen is the Σ-protocol that fixes this: it proves **equality of two
discrete logarithms** (often called a DLEQ proof), and it composes cleanly with
Fiat–Shamir so you can ship it non-interactively.

## The Concept

We work in a cyclic group of prime order `q`. In this lesson we use a toy
subgroup of `Z_p*` for a small prime `p`, but the same protocol is used over
elliptic-curve groups in production.

You have two bases `g` and `h`, and you claim there exists a secret `x` such that:

- `y1 = g^x (mod p)`
- `y2 = h^x (mod p)`

That’s the “DLEQ relation”: `log_g(y1) = log_h(y2) = x`.

Chaum–Pedersen is a Schnorr-like Σ-protocol with **two commitments**:

| Name | Meaning |
|------|---------|
| `a1 = g^r` | commitment under base `g` |
| `a2 = h^r` | commitment under base `h` |
| `c` | verifier challenge |
| `s = r + c·x (mod q)` | prover response |

Verification checks two equations:

- `g^s == a1 · y1^c (mod p)`
- `h^s == a2 · y2^c (mod p)`

Same trick as Schnorr: substitute `s = r + c·x` and use `y1 = g^x`, `y2 = h^x`.

## Build It

### Step 1: The DLEQ statement and transcript
```python
@dataclass(frozen=True)
class ChaumPedersenParams:
    """Toy subgroup parameters for Chaum–Pedersen (DLEQ) proofs.

    Work in a subgroup of Z_p* of prime order q. Both g and h generate that
    same subgroup.
    """

    p: int
    q: int
    g: int
    h: int


@dataclass(frozen=True)
class ChaumPedersenTranscript:
    """A Chaum–Pedersen Σ-protocol transcript: (a1, a2, c, s)."""

    commitment_g: int
    commitment_h: int
    challenge: int
    response: int


def assert_chaum_pedersen_params(params: ChaumPedersenParams, y1: int, y2: int) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("bad group parameters")
    if (params.p - 1) % params.q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < params.g < params.p):
        raise ValueError("g must satisfy 1 < g < p")
    if not (1 < params.h < params.p):
        raise ValueError("h must satisfy 1 < h < p")
    if mod_pow(params.g, params.q, params.p) != 1:
        raise ValueError("g does not have order q")
    if mod_pow(params.h, params.q, params.p) != 1:
        raise ValueError("h does not have order q")
    if mod_pow(y1, params.q, params.p) != 1:
        raise ValueError("y1 is not in the subgroup of order q")
    if mod_pow(y2, params.q, params.p) != 1:
        raise ValueError("y2 is not in the subgroup of order q")
```
`ChaumPedersenParams` fixes the group, subgroup order, and the two bases. The
transcript adds a second commitment, but the mental model stays the same: a Σ
protocol transcript is still “commitments + challenge + response”. Parameter
validation matters because your security proof assumes you’re in a prime-order
subgroup.

### Step 2: Prove and verify (interactive)
```python
def chaum_pedersen_publics(params: ChaumPedersenParams, x: int) -> tuple[int, int]:
    x = x % params.q
    return (mod_pow(params.g, x, params.p), mod_pow(params.h, x, params.p))


def chaum_pedersen_commit(params: ChaumPedersenParams, r: int) -> tuple[int, int]:
    r = r % params.q
    return (mod_pow(params.g, r, params.p), mod_pow(params.h, r, params.p))


def chaum_pedersen_response(q: int, r: int, c: int, x: int) -> int:
    return (r + c * x) % q


def chaum_pedersen_verify(
    params: ChaumPedersenParams,
    y1: int,
    y2: int,
    a1: int,
    a2: int,
    c: int,
    s: int,
) -> bool:
    if not (0 <= c < params.q):
        return False
    if not (0 <= s < params.q):
        return False
    if not (0 <= a1 < params.p) or not (0 <= a2 < params.p):
        return False

    left1 = mod_pow(params.g, s, params.p)
    right1 = mod_mul(a1, mod_pow(y1, c, params.p), params.p)
    if left1 != right1:
        return False

    left2 = mod_pow(params.h, s, params.p)
    right2 = mod_mul(a2, mod_pow(y2, c, params.p), params.p)
    return left2 == right2


def chaum_pedersen_prove(
    params: ChaumPedersenParams, x: int, r: int, c: int
) -> tuple[int, int, ChaumPedersenTranscript]:
    y1, y2 = chaum_pedersen_publics(params, x)
    a1, a2 = chaum_pedersen_commit(params, r)
    s = chaum_pedersen_response(params.q, r, c, x)
    t = ChaumPedersenTranscript(
        commitment_g=a1, commitment_h=a2, challenge=c % params.q, response=s
    )
    return (y1, y2, t)
```
This is the core protocol. The prover commits once (same `r`) under two bases,
the verifier challenges once, and the prover’s single response `s` must satisfy
*both* verification equations. If you can satisfy both for a random `c` without
knowing `x`, you can solve discrete log.

### Step 3: Special HVZK simulation (no witness)
```python
def chaum_pedersen_simulate_hvz(
    params: ChaumPedersenParams, y1: int, y2: int, c: int, s: int
) -> ChaumPedersenTranscript:
    """Special HVZK simulator for Chaum–Pedersen transcripts.

    Pick (c, s) and compute (a1, a2) so that both verification equations hold:

      g^s = a1 * y1^c  =>  a1 = g^s * (y1^c)^(-1)  (mod p)
      h^s = a2 * y2^c  =>  a2 = h^s * (y2^c)^(-1)  (mod p)
    """
    c = c % params.q
    s = s % params.q

    a1 = mod_mul(
        mod_pow(params.g, s, params.p),
        mod_inv(mod_pow(y1, c, params.p), params.p),
        params.p,
    )
    a2 = mod_mul(
        mod_pow(params.h, s, params.p),
        mod_inv(mod_pow(y2, c, params.p), params.p),
        params.p,
    )
    return ChaumPedersenTranscript(
        commitment_g=a1, commitment_h=a2, challenge=c, response=s
    )
```
The simulator proves “zero-knowledge for free” in the honest-verifier model: it
chooses `(c, s)` first and computes commitments that make verification pass.
If simulated transcripts and real transcripts look the same, the transcript
cannot carry information about `x`.

### Step 4: Special soundness (nonce reuse => witness extraction)
```python
def chaum_pedersen_extract_witness(q: int, c1: int, s1: int, c2: int, s2: int) -> int:
    """Extract x from two accepting transcripts with same commitments and c1 != c2."""
    if c1 == c2:
        raise ValueError("need two different challenges to extract")
    num = (s1 - s2) % q
    den = (c1 - c2) % q
    return (num * mod_inv(den, q)) % q
```
If the prover ever reuses the same nonce `r`, they reuse the same commitments
`(a1, a2)`. Two different challenges then give two linear equations in the same
unknown `x`, and the extractor solves for `x`. This is why “nonce reuse” is a
catastrophic class of bugs in Schnorr-like protocols (including signatures).

### Step 5: Fiat–Shamir (make it non-interactive)
```python
def chaum_pedersen_fiat_shamir_challenge(
    params: ChaumPedersenParams, y1: int, y2: int, a1: int, a2: int, domain: str
) -> int:
    return _hash_to_scalar(domain, [params.p, params.q, params.g, params.h, y1, y2, a1, a2], params.q)


def chaum_pedersen_prove_fiat_shamir(
    params: ChaumPedersenParams, x: int, r: int, domain: str
) -> tuple[int, int, ChaumPedersenTranscript]:
    y1, y2 = chaum_pedersen_publics(params, x)
    a1, a2 = chaum_pedersen_commit(params, r)
    c = chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, domain)
    s = chaum_pedersen_response(params.q, r, c, x)
    t = ChaumPedersenTranscript(
        commitment_g=a1, commitment_h=a2, challenge=c, response=s
    )
    return (y1, y2, t)


def chaum_pedersen_verify_fiat_shamir(
    params: ChaumPedersenParams,
    y1: int,
    y2: int,
    a1: int,
    a2: int,
    s: int,
    domain: str,
) -> bool:
    c = chaum_pedersen_fiat_shamir_challenge(params, y1, y2, a1, a2, domain)
    return chaum_pedersen_verify(params, y1, y2, a1, a2, c, s)
```
Fiat–Shamir replaces the verifier’s random challenge with a hash of the
transcript. The key engineering point is **binding**: the challenge must commit
to the protocol domain/version, the full statement `(y1, y2)`, and the
commitments `(a1, a2)`. If you hash too little, proofs become replayable or
transplantable across contexts.

Run it:
```
python3 code/main.py
```

## Use It

Where DLEQ / Chaum–Pedersen shows up:

- **ElGamal correctness proofs:** show that two ciphertext components were formed with the same randomness.
- **Pedersen commitments:** prove equality of openings (“these two commitments hide the same value”).
- **Mixnets / threshold decryption:** prove partial decryptions or re-encryptions are well-formed.

Production equivalents:

- Over elliptic curves, this is implemented as a proof of equality of discrete logs in groups like Ristretto / Curve25519, secp256k1, P-256.
- Some libraries represent the proof as `(c, s)` and recompute `(a1, a2)` during verification; others send `(a1, a2, c, s)` explicitly.

## Pitfalls

1. **Nonce reuse (`r`) leaks `x`:** two accepting transcripts with the same commitments but different challenges let anyone extract `x`.
2. **Missing subgroup / point validation:** if `y1`, `y2`, `g`, or `h` aren’t in the intended prime-order subgroup, verification can accept nonsense.
3. **Weak Fiat–Shamir binding:** if `c` isn’t hashed over `(domain || params || statement || commitments)`, proofs can be replayed or transplanted.
4. **Domain confusion:** mixing `mod p` for group elements and `mod q` for scalars silently breaks correctness and security arguments.
5. **“Same exponent” but wrong statement:** if you don’t clearly define `(y1, y2)` as the statement, you can end up proving a different relation than you think.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-chaum-pedersen-dleq-review.md`

Use it when reviewing a PR or spec that claims to implement Chaum–Pedersen, a
DLEQ proof, or an equality-of-openings proof: it forces transcript binding,
validation, and nonce-safety questions into the open.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that both the real proof and the simulated proof verify, and that Fiat–Shamir produces a deterministic challenge.
2. Medium. Extend `code/main.py` to generate 200 random witnesses `x` and nonces `r`, produce Fiat–Shamir proofs, and assert all proofs verify.
3. Hard. Create a “nonce reuse” demo: fix `r`, answer two different challenges `c1 != c2`, and use `chaum_pedersen_extract_witness` to recover `x`. Then write down what an API must do to prevent reuse (secure RNG + domain separation + no user-supplied `r`).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| DLEQ proof | “Chaum–Pedersen” | A proof that `log_g(y1) = log_h(y2)` without revealing the shared exponent. |
| Commitment(s) | “the first message” | The prover’s `a1=g^r` and `a2=h^r` that lock in the nonce `r`. |
| Challenge | “random verifier question” | The value `c` the prover must answer; Fiat–Shamir derives it by hashing the transcript. |
| Transcript binding | “hash the proof” | Making `c` depend on the exact statement, commitments, and context so proofs can’t be replayed elsewhere. |
| Special soundness | “extractable” | Two accepting transcripts with the same commitments but different challenges reveal `x`. |

## Further Reading

- Chaum, Pedersen, *Wallet Databases with Observers* (CRYPTO 1992/1993) — introduces the equality-of-discrete-logs protocol used widely in DL-based crypto.
- Cramer, Damgård, Schoenmakers, *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols* (1994) — composition and Σ-protocol design patterns.
- Boneh, Shoup, *A Graduate Course in Applied Cryptography* (ongoing) — clear notes on Σ-protocols, Fiat–Shamir, and engineering pitfalls.
