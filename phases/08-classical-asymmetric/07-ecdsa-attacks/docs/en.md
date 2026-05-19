# Attacking ECDSA — Nonce Reuse and Weak RNG

> In ECDSA, the nonce **is** the private key: reuse it, leak it, or make it guessable, and you lose `d`.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 08 · 06 (DSA & ECDSA), modular arithmetic (inverses mod `n`), elliptic curves (point add/mul)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why ECDSA nonce failures recover the private key
- Compute `k` and `d` from two signatures that reuse the same nonce
- Implement a minimal ECDSA sign/verify loop over `secp256k1` (educational)
- Distinguish “reused nonce”, “known nonce”, and “small-range nonce” attacks
- Apply a mitigation checklist (deterministic nonces + validation) to a real system

## The Problem

You’re reviewing a system that signs JWTs (or blockchain transactions) with ECDSA. Everything “looks right”: it uses SHA-256, it uses a standard curve, and signatures verify. Then an incident hits: one machine had a broken RNG after a VM snapshot restore, or an HSM firmware update introduced bias, or a debug build logged one ephemeral value by accident.

ECDSA has a sharp edge: the per-signature nonce `k` must be **uniform, unique, and secret**. If `k` is ever reused (even once), or if an attacker learns `k` for one signature, the long-term private key `d` can be solved with a couple modular inverses. If `k` is drawn from a small range, attackers can brute-force `k` and still recover `d`.

This lesson gives you the “red team math” for these failures, plus the practical mitigations you should demand in production.

## The Concept

ECDSA signing over a curve group of order `n` computes:

- Pick a nonce `k` uniformly from `[1, n-1]`.
- Compute `R = k·G` and `r = R_x mod n`.
- Hash the message to an integer `z`.
- Output `s = k^{-1} (z + r·d) mod n`.

The key relation to memorize is:

`s·k ≡ z + r·d (mod n)`

From that:

- If `k` is known: `d ≡ (s·k - z) · r^{-1} (mod n)`
- If the same `k` signs two messages with the same `r`:
  - `k ≡ (z1 - z2) · (s1 - s2)^{-1} (mod n)`
  - then recover `d` from either signature.
- If `k` is drawn from a small range, you can search for `k` by matching `r = (k·G)_x mod n`, then recover `d` as if `k` were known.

Mitigations follow directly: make `k` deterministic (RFC6979) or generated inside hardened hardware, and never allow `k` reuse across messages.

## Build It

### Step 1: Implement secp256k1 group operations
```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

Point = Optional[tuple[int, int]]  # (x, y) or None for point-at-infinity


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def G(self) -> Point:
        return (self.gx, self.gy)


SECP256K1 = Curve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def mod_inv(a: int, m: int) -> int:
    a %= m
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")

    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("a is not invertible mod m")
    return t % m


def is_on_curve(P: Point, curve: Curve = SECP256K1) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def point_add(P: Point, Q: Point, curve: Curve = SECP256K1) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None

    if P == Q:
        lam = (3 * x1 * x1 + curve.a) * mod_inv(2 * y1, curve.p)
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, curve.p)
    lam %= curve.p

    x3 = (lam * lam - x1 - x2) % curve.p
    y3 = (lam * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def scalar_mul(k: int, P: Point, curve: Curve = SECP256K1) -> Point:
    if k % curve.n == 0 or P is None:
        return None
    if k < 0:
        x, y = scalar_mul(-k, P, curve)
        return (x, (-y) % curve.p)

    out = None
    addend = P
    while k:
        if k & 1:
            out = point_add(out, addend, curve)
        addend = point_add(addend, addend, curve)
        k >>= 1
    return out
```

This is the minimal elliptic-curve “calculator” ECDSA needs: point addition and scalar multiplication over a prime field. It is correct but not constant-time and is not hardened against side channels.

### Step 2: Implement ECDSA sign/verify with an explicit nonce `k`
```python
import hashlib


def sha256_int(msg: bytes, n: int) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % n


def ecdsa_pubkey(priv: int, curve: Curve = SECP256K1) -> Point:
    if not (1 <= priv < curve.n):
        raise ValueError("private key out of range")
    return scalar_mul(priv, curve.G, curve)


def ecdsa_sign_with_k(msg: bytes, priv: int, k: int, curve: Curve = SECP256K1) -> tuple[int, int]:
    if not (1 <= priv < curve.n):
        raise ValueError("private key out of range")
    k = k % curve.n
    if k == 0:
        raise ValueError("k must be in [1, n-1]")

    R = scalar_mul(k, curve.G, curve)
    if R is None:
        raise ValueError("invalid k (k*G == infinity)")
    r = R[0] % curve.n
    if r == 0:
        raise ValueError("invalid k (r == 0)")

    z = sha256_int(msg, curve.n)
    s = (mod_inv(k, curve.n) * (z + r * priv)) % curve.n
    if s == 0:
        raise ValueError("invalid k (s == 0)")
    return (r, s)


def ecdsa_verify(msg: bytes, pub: Point, sig: tuple[int, int], curve: Curve = SECP256K1) -> bool:
    r, s = sig
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    if not is_on_curve(pub, curve):
        return False

    z = sha256_int(msg, curve.n)
    try:
        w = mod_inv(s, curve.n)
    except Exception:
        return False
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n
    X = point_add(scalar_mul(u1, curve.G, curve), scalar_mul(u2, pub, curve), curve)
    if X is None:
        return False
    return (X[0] % curve.n) == r
```

The important design choice here is that `ecdsa_sign_with_k` takes `k` as an input. That makes the attacks explicit: if you can force or learn `k`, you can recover `d`.

### Step 3: Recover the private key when the same nonce is reused
```python
def recover_k_from_reused_nonce(
    msg1: bytes,
    sig1: tuple[int, int],
    msg2: bytes,
    sig2: tuple[int, int],
    curve: Curve = SECP256K1,
) -> int:
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("nonce reuse attack needs r1 == r2 (same k => same r)")

    z1 = sha256_int(msg1, curve.n)
    z2 = sha256_int(msg2, curve.n)
    return ((z1 - z2) * mod_inv(s1 - s2, curve.n)) % curve.n


def recover_privkey_from_known_nonce(
    msg: bytes, sig: tuple[int, int], k: int, curve: Curve = SECP256K1
) -> int:
    r, s = sig
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        raise ValueError("invalid signature")
    z = sha256_int(msg, curve.n)
    return ((s * (k % curve.n) - z) * mod_inv(r, curve.n)) % curve.n


def recover_privkey_from_reused_nonce(
    msg1: bytes,
    sig1: tuple[int, int],
    msg2: bytes,
    sig2: tuple[int, int],
    curve: Curve = SECP256K1,
) -> tuple[int, int]:
    k = recover_k_from_reused_nonce(msg1, sig1, msg2, sig2, curve)
    d = recover_privkey_from_known_nonce(msg1, sig1, k, curve)
    return (d, k)
```

Nonce reuse gives you two equations in the same unknown `k`. One subtraction eliminates `d`, leaving a single modular inverse that recovers `k`, and then `d`.

### Step 4: Recover the private key when `k` is small (brute-force the nonce)
```python
def brute_force_k_from_small_range(
    r: int, max_k: int, curve: Curve = SECP256K1, start_k: int = 1
) -> int:
    if max_k < start_k:
        raise ValueError("empty search range")
    target = r % curve.n
    for k in range(start_k, max_k + 1):
        R = scalar_mul(k, curve.G, curve)
        if R is None:
            continue
        if (R[0] % curve.n) == target:
            return k
    raise ValueError("k not found in range")
```

This attack is “just search”: if `k` comes from a 12–16 bit RNG, you can enumerate candidates, match `r`, and then compute `d` using the “known nonce” formula.

### Step 5: Mitigation — deterministic nonces (RFC6979-style)
```python
import hmac


def rfc6979_nonce_sha256(msg: bytes, priv: int, curve: Curve = SECP256K1) -> int:
    if not (1 <= priv < curve.n):
        raise ValueError("private key out of range")

    x = priv.to_bytes(32, "big")
    h1 = hashlib.sha256(msg).digest()
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        nonce = candidate % curve.n
        if 1 <= nonce < curve.n:
            return nonce
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
```

RFC6979-style nonces replace “RNG quality” with “hash/HMAC correctness”: the nonce becomes a deterministic function of `(d, msg)`. This prevents RNG failures from causing nonce reuse, but it does not make ECDSA immune to side-channel leakage of nonce bits.

Run it:
python3 code/main.py

## Use It

In production you should avoid implementing ECDSA yourself. Use audited libraries and APIs that already implement nonce hardening and edge-case validation:

- `OpenSSL` (or your platform’s crypto provider) for ECDSA verification and signing in a hardened backend.
- `cryptography` (Python) for high-level, safe ECDSA APIs (it delegates to OpenSSL).
- `libsecp256k1` for secp256k1 signing/verification (Bitcoin-grade engineering).
- Cloud KMS / HSM signing APIs to keep `d` out of application memory and reduce nonce leakage risk.

If you must implement ECDSA (you usually shouldn’t), demand:

- Deterministic nonces (RFC6979) or hardware-generated nonces inside a certified HSM
- Strict public-key validation and signature validation (range checks, curve membership)
- Side-channel defenses (constant-time scalar mul and inversion, blinding)

## Pitfalls

- **Using `random` instead of `secrets`.** Python’s `random` is not a CSPRNG; repeated seeds or state compromise can leak or repeat `k`.
- **Nonce reuse across processes/VM snapshots.** Restoring a snapshot can restore RNG state; ECDSA then repeats `k`.
- **“Almost random” nonces.** Biased or low-entropy `k` can be attacked (brute force in small ranges; lattice attacks when many signatures leak bits).
- **Skipping signature/public-key validation.** If you don’t enforce `1 ≤ r,s < n` and “public key is on curve”, weird edge cases turn into vulnerabilities.
- **Logging or tracing ephemeral values.** A single leaked nonce (or partial nonce through side channels) can be enough to recover `d`.

## Ship It

Save and reuse the nonce-audit checklist in `outputs/skill-ecdsa-nonce-audit.md`:

- Paste it into a PR review when you see ECDSA signing code.
- Use it as an incident-response checklist when “ECDSA key compromise” is suspected.
- Use it to decide whether to migrate to deterministic signatures (RFC6979) or a KMS/HSM.

To sanity-check this lesson’s implementation, run:

- `python3 code/main.py`
- `python3 tests/test_vectors.py`

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that reused `k` recovers the private key exactly.
2. Medium. Extend the demo to search `k` in `[1, 65536]` and measure how long brute force takes on your machine.
3. Hard. Pick a real library you use (OpenSSL, `cryptography`, a KMS). Verify which nonce strategy it uses for ECDSA and write a one-page risk assessment using the shipped checklist.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Nonce (`k`) | “Random per signature” | A secret scalar; if reused/leaked/guessable, it reveals `d` |
| Reused nonce | “Two signatures share a nonce” | Same `k` ⇒ same `r` ⇒ solve `k` and then `d` |
| Known nonce | “Attacker learned `k` once” | One signature + `k` gives `d` with one modular inverse |
| Biased nonce | “Not perfectly uniform” | Many signatures can leak bits of `k` ⇒ advanced recovery (often lattice) |
| RFC6979 | “Deterministic ECDSA” | Derive `k = HMAC(d, H(msg))` to avoid RNG failures |

## Further Reading

- Certicom, SEC 1: Elliptic Curve Cryptography (2009) — ECDSA definition and required validation rules.
- Certicom, SEC 2: Recommended Elliptic Curve Domain Parameters (2010) — secp256k1 parameters.
- T. Pornin, RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA and ECDSA) (2013) — how to derive safe nonces from `(d, msg)`.
