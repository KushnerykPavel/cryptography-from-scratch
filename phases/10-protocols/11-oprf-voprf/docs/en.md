# OPRFs & VOPRFs

> Blind the input, evaluate once, unblind the answer.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 (Modular inverse & fast exponentiation), Phase 2 (Groups, cyclic groups)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what an OPRF gives you (and what it doesn’t)
- **Compute** an OPRF evaluation by hand using group exponentiation and modular inverses
- **Implement** a DH-style OPRF over a toy prime-order group
- **Distinguish** OPRF vs VOPRF and when verifiability is required
- **Apply** an OPRF/VOPRF integration checklist to a real protocol design

## The Problem

You want a server to apply a secret “pepper” to a client’s input, but you cannot send the input in the clear. Passwords are the obvious example: you want the server to contribute secret entropy so the client can derive a strong secret, but you never want the server to learn the password itself (even during registration), and you don’t want a database breach to turn into an offline guessing oracle.

You also want *the opposite* in other settings: a client may want to check membership (“is my email in the breach list?”) or compute an intersection (“which contacts do we share?”) without revealing everything it asks about. Many private-set and anonymous-token constructions reduce to “let me evaluate a PRF on my hidden input”.

An OPRF is the standard building block for “server-keyed PRF on client input, with privacy on both sides”. A VOPRF adds one more crucial property: if the server lies (or is misconfigured), the client can detect it and abort.

## The Concept

An OPRF is a two-party protocol that realizes a PRF-like functionality `F_k(x)` where:

- the server holds a secret key `k`,
- the client holds an input `x`,
- the client learns `F_k(x)`,
- the server learns neither `x` nor `F_k(x)`.

### A DH-style OPRF in one equation

Work in a prime-order group `G` of order `q`. Let `H1` map bytes to a group element and `H2` map bytes to an output string.

- Server secret: `k ∈ Z_q`
- Client random blind: `r ∈ Z_q*`
- Client: `P = H1(x)`, `α = P^r`
- Server: `β = α^k = (P^r)^k`
- Client: `N = β^(1/r) = P^k`
- Output: `y = H2(x || N)`

The server never sees `P` (it only sees `α`), and the client never sees `k` (it only sees `P^k` hidden behind blinding).

### What VOPRF adds

In base OPRF mode, a malicious server could return *any* group element `β'`, causing the client to compute a wrong output without noticing. A VOPRF fixes this by having the server prove (without revealing `k`) that it used the same `k` that corresponds to a known public key `pk = g^k`.

Concretely, the server proves a *discrete log equality* (DLEQ):

```
log_g(pk) = log_α(β)
```

That statement means: “the exponent that links `g -> pk` is the same exponent that links `α -> β`”.

## Build It

### Step 1: Toy group + hashing

We’ll use a **toy** prime-order subgroup of `Z_p*` (safe prime `p = 2q + 1`) so every non-zero scalar has an inverse modulo `q`. We also implement deterministic “hash-to-scalar” and “hash-to-group” helpers with domain separation (DSTs) so we can build reproducible vectors and demos.

```python
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


@dataclass(frozen=True)
class ToyGroup:
    p: int
    q: int
    g: int

    @property
    def element_len(self) -> int:
        return (self.p.bit_length() + 7) // 8


TOY_GROUP = ToyGroup(
    p=304823849380996932578798421988872119159,
    q=152411924690498466289399210994436059579,
    g=26338669013574108186373576571640264969,
)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def i2osp(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("i2osp requires non-negative integer")
    if x >= (1 << (8 * length)):
        raise ValueError("integer too large")
    return x.to_bytes(length, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def is_valid_element(x: int, group: ToyGroup = TOY_GROUP) -> bool:
    if not (2 <= x <= group.p - 2):
        return False
    return pow(x, group.q, group.p) == 1


def serialize_element(x: int, group: ToyGroup = TOY_GROUP) -> bytes:
    if not is_valid_element(x, group):
        raise ValueError("invalid group element")
    return i2osp(x, group.element_len)


def hash_to_scalar(dst: bytes, msg: bytes, group: ToyGroup = TOY_GROUP) -> int:
    if not dst:
        raise ValueError("dst must be non-empty")
    digest = _sha256(b"H2S|" + dst + b"|" + msg)
    s = os2ip(digest) % group.q
    if s == 0:
        s = 1
    return s


def hash_to_group(dst: bytes, msg: bytes, group: ToyGroup = TOY_GROUP) -> int:
    if not dst:
        raise ValueError("dst must be non-empty")
    seed = _sha256(b"H2G|" + dst + b"|" + msg)
    for counter in range(256):
        digest = _sha256(seed + bytes([counter]))
        x = (os2ip(digest) % (group.p - 3)) + 2
        element = pow(x, 2, group.p)
        if element != 1 and is_valid_element(element, group):
            return element
    raise ValueError("hash_to_group failed to find a valid element")


def mod_inverse(a: int, n: int) -> int:
    if n <= 1:
        raise ValueError("modulus must be > 1")
    a %= n
    if a == 0:
        raise ValueError("zero has no inverse")

    t0, t1 = 0, 1
    r0, r1 = n, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1

    if r0 != 1:
        raise ValueError("not invertible")
    return t0 % n


def inv_element(x: int, group: ToyGroup = TOY_GROUP) -> int:
    if not is_valid_element(x, group):
        raise ValueError("invalid group element")
    return pow(x, group.p - 2, group.p)
```

### Step 2: OPRF (blind -> evaluate -> unblind -> finalize)

Now we implement the core protocol. The key idea is that the client blinds `H1(x)` with a random exponent `r`, the server applies its secret exponent `k`, and the client removes the blinding by raising to `r^{-1} mod q`.

```python
def derive_key_pair(seed: bytes, group: ToyGroup = TOY_GROUP) -> tuple[int, int]:
    sk = hash_to_scalar(b"KeyGen", seed, group)
    pk = pow(group.g, sk, group.p)
    return sk, pk


def oprf_blind(input_msg: bytes, blind: int, group: ToyGroup = TOY_GROUP) -> tuple[int, int]:
    if not (1 <= blind < group.q):
        raise ValueError("blind must be in [1, q-1]")
    p = hash_to_group(b"OPRF-H1", input_msg, group)
    alpha = pow(p, blind, group.p)
    return blind, alpha


def oprf_evaluate(blinded_element: int, sk: int, group: ToyGroup = TOY_GROUP) -> int:
    if not is_valid_element(blinded_element, group):
        raise ValueError("invalid blinded element")
    sk %= group.q
    if sk == 0:
        raise ValueError("sk must be non-zero")
    return pow(blinded_element, sk, group.p)


def oprf_unblind(evaluated_element: int, blind: int, group: ToyGroup = TOY_GROUP) -> int:
    if not is_valid_element(evaluated_element, group):
        raise ValueError("invalid evaluated element")
    inv_blind = mod_inverse(blind, group.q)
    return pow(evaluated_element, inv_blind, group.p)


def oprf_finalize(input_msg: bytes, unblinded_element: int, group: ToyGroup = TOY_GROUP) -> bytes:
    enc = serialize_element(unblinded_element, group)
    return _sha256(b"OPRF-Finalize|" + input_msg + b"|" + enc)
```

### Step 3: VOPRF (DLEQ proof)

For verifiability, the server proves that the exponent used to compute `pk = g^k` is the same exponent used to compute `β = α^k`. We implement a simplified non-interactive DLEQ proof with a Fiat–Shamir challenge derived from hashing the transcript.

```python
def dleq_challenge(
    g: int, pk: int, alpha: int, beta: int, t1: int, t2: int, group: ToyGroup = TOY_GROUP
) -> int:
    transcript = (
        b"DLEQ|"
        + serialize_element(g, group)
        + serialize_element(pk, group)
        + serialize_element(alpha, group)
        + serialize_element(beta, group)
        + serialize_element(t1, group)
        + serialize_element(t2, group)
    )
    return hash_to_scalar(b"DLEQ-Challenge", transcript, group)


def dleq_prove(
    sk: int, alpha: int, beta: int, *, nonce: int, group: ToyGroup = TOY_GROUP
) -> tuple[int, int]:
    if not is_valid_element(alpha, group) or not is_valid_element(beta, group):
        raise ValueError("invalid elements")
    sk %= group.q
    if sk == 0:
        raise ValueError("sk must be non-zero")
    if not (1 <= nonce < group.q):
        raise ValueError("nonce must be in [1, q-1]")

    pk = pow(group.g, sk, group.p)
    t1 = pow(group.g, nonce, group.p)
    t2 = pow(alpha, nonce, group.p)
    c = dleq_challenge(group.g, pk, alpha, beta, t1, t2, group)
    s = (nonce + c * sk) % group.q
    return c, s


def dleq_verify(pk: int, alpha: int, beta: int, proof: tuple[int, int], group: ToyGroup = TOY_GROUP) -> bool:
    c, s = proof
    if not (0 <= c < group.q) or not (0 <= s < group.q):
        return False
    if not is_valid_element(pk, group):
        return False
    if not is_valid_element(alpha, group) or not is_valid_element(beta, group):
        return False

    t1 = (pow(group.g, s, group.p) * inv_element(pow(pk, c, group.p), group)) % group.p
    t2 = (pow(alpha, s, group.p) * inv_element(pow(beta, c, group.p), group)) % group.p
    expected_c = dleq_challenge(group.g, pk, alpha, beta, t1, t2, group)
    return c == expected_c


def voprf_evaluate(
    blinded_element: int, sk: int, *, proof_nonce: int, group: ToyGroup = TOY_GROUP
) -> tuple[int, tuple[int, int], int]:
    beta = oprf_evaluate(blinded_element, sk, group)
    pk = pow(group.g, sk % group.q, group.p)
    proof = dleq_prove(sk, blinded_element, beta, nonce=proof_nonce, group=group)
    return beta, proof, pk
```

### Step 4: What breaks when verification is missing

Finally, we wire everything into a runnable script that prints step headers and shows concrete inputs → outputs. We also demonstrate a “tamper `β`” failure case: without a proof, the client can’t detect a malicious evaluation.

```python
def _fmt_elem(x: int) -> str:
    return f"0x{x:x}"


def main():
    rng = random.Random(12345)

    print("=== Step 1: Toy group + hashing ===")
    print(f"p = {_fmt_elem(TOY_GROUP.p)}")
    print(f"q = {_fmt_elem(TOY_GROUP.q)}")
    print(f"g = {_fmt_elem(TOY_GROUP.g)}")
    sample_point = hash_to_group(b"OPRF-H1", b"demo@example.com", TOY_GROUP)
    sample_scalar = hash_to_scalar(b"demo", b"demo@example.com", TOY_GROUP)
    print(f"H1('demo@example.com') = {_fmt_elem(sample_point)}")
    print(f"H_scalar('demo@example.com') = {sample_scalar}")
    print()

    print("=== Step 2: OPRF (blind -> evaluate -> unblind -> finalize) ===")
    sk, pk = derive_key_pair(b"server key seed (demo)", TOY_GROUP)
    print(f"server sk = {sk}")
    print(f"server pk = {_fmt_elem(pk)}")
    print()

    input_msg = b"correct horse battery staple"
    blind = rng.randrange(1, TOY_GROUP.q)
    _, alpha = oprf_blind(input_msg, blind, TOY_GROUP)
    beta = oprf_evaluate(alpha, sk, TOY_GROUP)
    unblinded = oprf_unblind(beta, blind, TOY_GROUP)
    output = oprf_finalize(input_msg, unblinded, TOY_GROUP)
    print(f"input = {input_msg!r}")
    print(f"blind r = {blind}")
    print(f"alpha = H1(input)^r = {_fmt_elem(alpha)}")
    print(f"beta  = alpha^k     = {_fmt_elem(beta)}")
    print(f"N     = beta^(1/r)  = {_fmt_elem(unblinded)}")
    print(f"output = sha256(...) = {output.hex()}")
    print()

    print("=== Step 3: VOPRF (DLEQ proof) ===")
    proof_nonce = rng.randrange(1, TOY_GROUP.q)
    beta2, proof, pk2 = voprf_evaluate(alpha, sk, proof_nonce=proof_nonce, group=TOY_GROUP)
    assert beta2 == beta and pk2 == pk
    ok = dleq_verify(pk, alpha, beta2, proof, TOY_GROUP)
    print(f"proof (c, s) = ({proof[0]}, {proof[1]})")
    print(f"verify = {ok}")
    print()

    print("=== Step 4: What breaks when verification is missing ===")
    bad_beta = (beta * TOY_GROUP.g) % TOY_GROUP.p
    ok_bad = dleq_verify(pk, alpha, bad_beta, proof, TOY_GROUP)
    print(f"tampered beta verifies? {ok_bad}")
    if ok_bad:
        raise AssertionError("tampering should not verify")


if __name__ == "__main__":
    main()
```

Run it:

```bash
python3 code/main.py
```

## Use It

Production protocols do not use our toy `Z_p*` group or our toy hash-to-group. They use standardized prime-order groups (often elliptic curves) and standardized hash-to-curve / hash-to-group constructions.

Where you’ll see OPRFs/VOPRFs in the real world:

- **OPAQUE (aPAKE):** uses an OPRF so the server contributes a secret “pepper” without seeing the password.
- **Privacy Pass / anonymous tokens:** uses a VOPRF so a client can verify it got a properly-issued token without revealing which token it asked for.
- **Private Set Intersection (PSI):** many PSI constructions use OPRF evaluations to encode set items privately.

Real implementations to read (and use instead of this lesson code):

- RFC 9497 implementations (e.g., `facebook/voprf`, Rust `voprf` crate, Cloudflare `voprf-ts`)
- OPAQUE libraries that embed OPRF as a subprotocol

## Pitfalls

1. **Skipping group membership checks.** If `α` is not in the correct prime-order group, small-subgroup and invalid-group attacks can leak bits of the server key or let clients forge transcripts.
2. **Reusing blinds.** Reusing the same `r` across inputs links requests and can leak information about `x` (and in some constructions, enables algebraic attacks).
3. **No domain separation.** If `H1`, `H2`, and DLEQ challenges share hashing without context strings, cross-protocol collisions become plausible engineering failures.
4. **Not verifying in VOPRF mode.** If you accept `β` without checking the proof, you are back to “server says so”, and verifiability is gone.
5. **Treating educational code as production crypto.** Real VOPRFs must use standardized groups, robust hash-to-group, constant-time scalar operations, and careful transcript encoding.

## Ship It

This lesson ships a reusable review artifact:

- `outputs/skill-oprf-voprf-integration-checklist.md`

Use it when you:

- design a protocol that needs an OPRF/VOPRF subroutine,
- review a PR that adds OPRF/VOPRF to an authentication or token system,
- audit whether verifiability and domain separation are actually enforced.

Paste it into your LLM, or keep it as a checklist for design reviews.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that `N = beta^(1/r)` is stable and that tampering `beta` makes verification fail.
2. Medium. Extend `main()` to evaluate a *batch* of inputs (e.g., 5 passwords) with different blinds and print whether all unblinded values match direct evaluation `H1(x)^k`.
3. Hard. Replace the toy group with a real curve group using a vetted library and RFC 9497 semantics (hash-to-group, encoding rules, DLEQ transcript), then cross-check against known RFC test vectors.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| OPRF | “A PRF where the server doesn’t learn the input.” | A two-party protocol that lets the client learn `F_k(x)` while hiding `x` from the server and hiding `k` from the client. |
| VOPRF | “An OPRF with proofs.” | An OPRF where the client can verify the server evaluated using a specific key (usually via a DLEQ proof). |
| Blind | “Randomness that hides my input.” | A scalar `r` used to randomize the client’s query so the server can’t link it back to `x`. |
| Unblind | “Remove the randomness.” | Using `r^{-1} mod q` to cancel the blinding after the server’s evaluation. |
| DLEQ proof | “Proves two discrete logs match.” | A proof that the same exponent relates `(g, pk)` and `(α, β)` without revealing that exponent. |

## Further Reading

- Davidson, Faz-Hernandez, Sullivan, Wood, **Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups** (RFC 9497, 2023) — the modern OPRF/VOPRF specification and test vectors.
- Krawczyk et al., **The OPAQUE Augmented PAKE Protocol** (RFC 9807, 2024) — shows how OPRFs are used to secure password authentication.
