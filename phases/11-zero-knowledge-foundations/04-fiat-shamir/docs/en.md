# Fiat–Shamir Heuristic
> Turn “the verifier’s random challenge” into “a hash of the transcript”.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/11-zero-knowledge-foundations/02-sigma-protocols`, `phases/11-zero-knowledge-foundations/03-schnorr-id-protocol`, `phases/01-number-theory/03-modular-inverse-and-fast-exp`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why public-coin interaction is a deployment bottleneck
- Compute Fiat–Shamir challenges as `c = H(transcript) mod q`
- Implement a non-interactive Schnorr proof using transcript hashing
- Distinguish strong transcript binding from “weak Fiat–Shamir” pitfalls
- Apply a review checklist to spot Fiat–Shamir bugs in real systems

## The Problem

Sigma protocols (commit → challenge → response) are a beautiful way to prove knowledge without revealing secrets. But they come with a practical problem: they’re *interactive*. The verifier must be online to sample and send a fresh random challenge.

That’s fine in a classroom, but it breaks in many real deployments:

- Blockchains and logs want proofs that anyone can verify later, offline.
- APIs want “send one blob, verify it” instead of a round-trip.
- Protocols want to *batch* verification of many proofs without coordinating interactive sessions.

Fiat–Shamir is the bridge. It lets the prover compute the verifier’s challenge by hashing the transcript so far, turning a 3-message public-coin protocol into a 1-message non-interactive proof (and, with a message bound into the hash, into a signature-like object).

## The Concept

A (3-move) Sigma protocol has the shape:

1) Prover sends a **commitment** `t`
2) Verifier sends a random **challenge** `c`
3) Prover sends a **response** `s`

Verification checks a public equation that links `(t, c, s)` to the public statement.

For Schnorr (knowledge of discrete log), in a prime-order subgroup of order `q`:

- Secret: `x ∈ Z_q`
- Public key: `y = g^x (mod p)`
- Commitment: `t = g^r (mod p)`
- Response: `s = r + c·x (mod q)`
- Verify: `g^s ?= t · y^c (mod p)`

Fiat–Shamir replaces the verifier’s random `c` with a hash-derived value:

```
c = H( domain_sep || public_inputs || t || message ) mod q
```

Two implementation details matter more than the math:

- **Transcript binding:** if you forget to hash *something* (like the message, or the statement, or the parameters), you may get a proof that “works” but proves the wrong thing.
- **Encoding / domain separation:** you need an unambiguous, canonical byte encoding and a protocol-specific domain tag so transcripts from different contexts can’t collide.

In this lesson we’ll implement a tiny transcript hash for Schnorr and then demonstrate two concrete breaks you can see with toy parameters.

## Build It

### Step 1: Interactive Schnorr Sigma protocol
```python
from dataclasses import dataclass
import hashlib
from secrets import randbelow


@dataclass(frozen=True)
class SchnorrParams:
    p: int
    q: int
    g: int


def egcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, n):
    if n <= 0:
        raise ValueError("modulus must be positive")
    a = a % n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return x % n


def check_schnorr_params(params):
    p, q, g = params.p, params.q, params.g
    if p <= 2 or q <= 1:
        raise ValueError("p and q must be > 2")
    if (p - 1) % q != 0:
        raise ValueError("q must divide p-1")
    if not (1 < g < p):
        raise ValueError("g must be in [2, p-2]")
    if pow(g, q, p) != 1:
        raise ValueError("g must have order dividing q")
    if g == 1:
        raise ValueError("g must not be 1")


def toy_params():
    return SchnorrParams(p=23, q=11, g=2)


def toy_keypair(params, x):
    check_schnorr_params(params)
    q = params.q
    if not (0 <= x < q):
        raise ValueError("secret x must be in Z_q")
    y = pow(params.g, x, params.p)
    return x, y


def schnorr_commit(params, r):
    check_schnorr_params(params)
    q = params.q
    if not (0 <= r < q):
        raise ValueError("nonce r must be in Z_q")
    return pow(params.g, r, params.p)


def schnorr_response(params, r, c, x):
    check_schnorr_params(params)
    q = params.q
    if not (0 <= r < q):
        raise ValueError("nonce r must be in Z_q")
    if not (0 <= c < q):
        raise ValueError("challenge c must be in Z_q")
    if not (0 <= x < q):
        raise ValueError("secret x must be in Z_q")
    return (r + c * x) % q


def schnorr_verify(params, y, t, c, s):
    check_schnorr_params(params)
    q, p = params.q, params.p
    if not (0 < y < p):
        raise ValueError("public key y must be in [1, p-1]")
    if not (0 < t < p):
        raise ValueError("commitment t must be in [1, p-1]")
    if pow(y, q, p) != 1:
        raise ValueError("public key y must be in the q-order subgroup")
    if pow(t, q, p) != 1:
        raise ValueError("commitment t must be in the q-order subgroup")
    if not (0 <= c < q):
        raise ValueError("challenge c must be in Z_q")
    if not (0 <= s < q):
        raise ValueError("response s must be in Z_q")
    lhs = pow(params.g, s, p)
    rhs = (t * pow(y, c, p)) % p
    return lhs == rhs
```

This step sets up a toy Schnorr Sigma protocol: a prover sends `t = g^r`, receives a random `c`, replies with `s = r + c·x`, and the verifier checks `g^s = t·y^c`. The only thing the verifier must contribute is a fresh, unpredictable `c`.

### Step 2: Fiat–Shamir challenge from a transcript
```python
def _int_to_fixed_length_bytes(n, length):
    if n < 0:
        raise ValueError("cannot encode negative integers")
    return int(n).to_bytes(length, "big")


def _encode_transcript(params, y, t, message, domain_sep):
    check_schnorr_params(params)
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if not isinstance(domain_sep, (bytes, bytearray)):
        raise TypeError("domain_sep must be bytes")
    p_len = (params.p.bit_length() + 7) // 8
    out = bytearray()
    out += domain_sep
    out += _int_to_fixed_length_bytes(params.p, p_len)
    out += _int_to_fixed_length_bytes(params.q, p_len)
    out += _int_to_fixed_length_bytes(params.g, p_len)
    out += _int_to_fixed_length_bytes(y, p_len)
    out += _int_to_fixed_length_bytes(t, p_len)
    out += len(message).to_bytes(4, "big")
    out += message
    return bytes(out)


def hash_to_int(data, q):
    if q <= 1:
        raise ValueError("q must be > 1")
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % q


def fiat_shamir_challenge(params, y, t, message, domain_sep=b"FS-SCHNORR-v1"):
    transcript = _encode_transcript(params, y, t, message, domain_sep)
    return hash_to_int(transcript, params.q)
```

Fiat–Shamir is “just” transcript hashing, but the transcript must be encoded safely. Here we build `domain_sep || p || q || g || y || t || len(message) || message` and hash it with SHA-256, reducing mod `q` to get a challenge in `Z_q`.

### Step 3: Non-interactive Schnorr proof via Fiat–Shamir
```python
def fs_prove(params, x, message, nonce=None, domain_sep=b"FS-SCHNORR-v1"):
    check_schnorr_params(params)
    q = params.q
    if nonce is None:
        nonce = randbelow(q)
    t = schnorr_commit(params, nonce)
    _, y = toy_keypair(params, x)
    c = fiat_shamir_challenge(params, y, t, message, domain_sep=domain_sep)
    s = schnorr_response(params, nonce, c, x)
    return {"t": t, "s": s}


def fs_verify(params, y, message, proof, domain_sep=b"FS-SCHNORR-v1"):
    c = fiat_shamir_challenge(params, y, proof["t"], message, domain_sep=domain_sep)
    return schnorr_verify(params, y, proof["t"], c, proof["s"])
```

This is the transform in code: the prover computes `c` locally as a hash of the transcript, then computes `s` exactly like the interactive protocol. The verifier recomputes `c` from the same transcript and checks the Schnorr verification equation.

### Step 4: Two real breaks: weak binding and grinding
```python
def weak_fiat_shamir_challenge_without_message(params, y, t):
    check_schnorr_params(params)
    p_len = (params.p.bit_length() + 7) // 8
    data = b"WEAK-FS-v1" + _int_to_fixed_length_bytes(y, p_len) + _int_to_fixed_length_bytes(t, p_len)
    return hash_to_int(data, params.q)


def weak_fs_prove_without_message(params, x, nonce=None):
    check_schnorr_params(params)
    q = params.q
    if nonce is None:
        nonce = randbelow(q)
    t = schnorr_commit(params, nonce)
    _, y = toy_keypair(params, x)
    c = weak_fiat_shamir_challenge_without_message(params, y, t)
    s = schnorr_response(params, nonce, c, x)
    return {"t": t, "s": s}


def weak_fs_verify_without_message(params, y, proof):
    c = weak_fiat_shamir_challenge_without_message(params, y, proof["t"])
    return schnorr_verify(params, y, proof["t"], c, proof["s"])


def forge_fs_proof_by_grinding(params, y, message, domain_sep=b"FS-SCHNORR-v1"):
    check_schnorr_params(params)
    q, p = params.q, params.p

    for c_guess in range(q):
        y_to_c = pow(y, c_guess, p)
        inv_y_to_c = mod_inverse(y_to_c, p)
        for s_guess in range(q):
            t = (pow(params.g, s_guess, p) * inv_y_to_c) % p
            c_actual = fiat_shamir_challenge(params, y, t, message, domain_sep=domain_sep)
            if c_actual == c_guess:
                proof = {"t": t, "s": s_guess}
                if fs_verify(params, y, message, proof, domain_sep=domain_sep):
                    return proof
    raise RuntimeError("failed to forge proof (unexpected for toy parameters)")
```

Two “it passes tests but it’s broken” failure modes:

1) **Weak binding:** if you don’t hash the message (or statement), the proof is no longer bound to what you think it’s bound to.
2) **Grinding / small challenge space:** Fiat–Shamir security depends on an astronomically large challenge space. With toy `q=11`, you can brute force a valid proof without the secret by searching for a fixed point `c_guess = H(t, message)`.

Run it:

`python3 code/main.py`

## Use It

In production, Fiat–Shamir is usually implemented as a *transcript object* that supports:

- domain separation (`protocol_name`, `challenge_id`)
- binding a sequence of values (scalars, points, bytes)
- deriving challenges in a fixed order (each challenge usually hashes the previous one too)

| Context | Typical library | Notes |
|---|---|---|
| Rust ZK systems | `arkworks`, `halo2`, `winterfell`, `plonky2` ecosystems | Usually have transcript helpers or integrate Poseidon/Keccak transcripts |
| Go ZK systems | `gnark-crypto/fiat-shamir` | Transcript pattern: `Bind(...)` then `Challenge(...)` |
| Signatures from Sigma protocols | Schnorr-style signatures (various libs) | The hash binds `R`, public key, and message |

## Pitfalls

1. **Not hashing the full statement.** If `p, q, g` (or curve / domain parameters) are implicit, make sure both sides agree on them and they’re included via domain separation.
2. **Not binding the message.** If you want “proof of knowledge for *this* message”, the message must be in the transcript (or you’ll get transferable proofs).
3. **Ambiguous encodings.** Concatenating variable-length fields without length prefixes can create collisions (`a||bc` vs `ab||c`). Use fixed-length or explicit lengths.
4. **No domain separation.** Reusing the same hash transcript format across protocols can lead to cross-protocol attacks or accidental validity in the wrong context.
5. **Too-small challenge space / grinding.** Fiat–Shamir proofs inherit soundness from the challenge space. If the challenge is small, “try until the hash looks good” becomes practical.

## Ship It

This lesson ships a Fiat–Shamir transcript review checklist.

1. Open `outputs/fiat_shamir_transcript_review_checklist.md`.
2. Paste it into a PR review or protocol design doc any time you see “Fiat–Shamir”, “transcript”, “hash-to-challenge”, or “non-interactive”.
3. Use it to catch the real bugs: missing binding, bad encoding, missing domain separation, and grinding risk.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that changing the message breaks verification for the strong Fiat–Shamir proof, but not for the weak “no-message” version.
2. Medium: Extend `code/main.py` to implement a tiny `Transcript` class with `bind_int()`, `bind_bytes()`, and `challenge_scalar(label)` so you can derive multiple challenges in sequence.
3. Hard: Design a Schnorr-signature-style API around `fs_prove/fs_verify` that binds `(public_key, message)` and returns a signature `(t, s)`. Write down what you’d need to change to make it production-grade (curve group, canonical encoding, constant-time operations, deterministic nonces).

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Fiat–Shamir | “Make it non-interactive” | Replace verifier randomness with a hash-derived challenge from the transcript |
| Transcript | “Things we hash” | A canonical byte encoding of all public inputs and prover messages so far |
| Domain separation | “A tag” | A protocol-specific label preventing cross-protocol transcript collisions |
| Sigma protocol | “3-move ZK proof” | Commit → challenge → response proof system with special soundness and HVZK properties |
| Soundness error | “Cheating probability” | Probability a prover can pass without a witness; often about `1/|challenge_space|` |

## Further Reading

- Amos Fiat, Adi Shamir, *How to Prove Yourself: Practical Solutions to Identification and Signature Problems* (1986/1987) — Original heuristic for compiling interaction into hashing.
- Mihir Bellare, Phillip Rogaway, *Random Oracles are Practical* (1993) — Formalizes the random oracle model used to analyze Fiat–Shamir-like designs.
- David Pointcheval, Jacques Stern, *Security Proofs for Signature Schemes* (EUROCRYPT 1996) — Forking lemma and security analyses for Fiat–Shamir signatures in the ROM.
- Shafi Goldwasser, Yael Tauman Kalai, *On the (In)security of the Fiat–Shamir Paradigm* (2003) — Shows limits: ROM proofs don’t automatically transfer to real hash instantiations.
