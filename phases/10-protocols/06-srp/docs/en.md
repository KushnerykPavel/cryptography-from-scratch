# SRP — Secure Remote Password
> Prove you know the password — without sending it (and without the server storing it).

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/07-symmetric-crypto/09-hash-functions`, `phases/07-symmetric-crypto/13-kdfs`, `phases/08-classical-asymmetric/04-diffie-hellman`  
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why SRP prevents offline password guessing after a network capture
- **Compute** the SRP values `x`, `v`, `A`, `B`, `u` and interpret what each “means”
- **Implement** SRP-6a key agreement with verifier-based authentication
- **Distinguish** SRP (balanced PAKE) from “salted password over TLS” and from OPAQUE
- **Apply** protocol checks that prevent common SRP implementation flaws

## The Problem
Passwords are still the default login secret, but naive password login is fragile: if the server stores `H(password)` and your database leaks, attackers can brute-force guesses offline until they find a match. If you send the password to the server every login, a phishing site or active network attacker can steal it.

SRP (Secure Remote Password) is a PAKE: it lets a client and server agree on a strong session key while authenticating the client *using only a password*, but without sending the password and without the server ever storing it. The server stores a **verifier** derived from the password; a database leak is still bad, but the attacker doesn’t get an immediate “check this guess in a hash loop” oracle.

## The Concept
SRP is “Diffie–Hellman with a password mixed in, plus a transcript-bound proof.”

At registration time, the server stores:

| Value | Definition | Intuition |
|---|---|---|
| `s` | random salt | per-user randomness |
| `x` | `H(s || H(I ":" P))` | password mapped into an exponent |
| `v` | `g^x mod N` | verifier (password “public key”) |

At login, the client sends `A = g^a mod N`, the server replies with `s` and `B = (k*v + g^b) mod N`, and both compute:

- `u = H(A || B)` (a “mixing” scalar)
- Client secret: `S_c = (B - k*g^x)^(a + u*x) mod N`
- Server secret: `S_s = (A * v^u)^b mod N`
- Session key: `K = H(S)`

Then the client proves it has `K` by sending `M1 = H(transcript || K)`, and the server replies with `M2 = H(A || M1 || K)` so the client knows *the server* also derived `K`.

## Build It

### Step 1: Parameters + hashing
```python
import hashlib

RFC5054_N_1024_HEX = (
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1"
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC"
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
)


def group_1024() -> tuple[int, int]:
    return int(RFC5054_N_1024_HEX, 16), 2


def _h(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _i2b(n: int, length: int | None = None) -> bytes:
    if n < 0:
        raise ValueError("negative integers are not supported")
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


def _b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _pad_int(n: int, N: int) -> bytes:
    return _i2b(n, (N.bit_length() + 7) // 8)


def _h_int(*parts: bytes) -> int:
    return _b2i(_h(*parts))


def compute_k(N: int, g: int) -> int:
    nlen = (N.bit_length() + 7) // 8
    return _h_int(_i2b(N, nlen), _i2b(g, nlen))
```
SRP is specified over a large safe prime `N` and generator `g`. We also need a careful, *deterministic* byte encoding for integers so both sides hash the same transcript. Here we use `SHA-256` and the 1024-bit group from RFC 5054, and we define `k = H(N || g)` (with fixed-length encodings) as a protocol constant.

### Step 2: Registration (salt → verifier)
```python
from dataclasses import dataclass

def compute_x(salt: bytes, username: str, password: str) -> int:
    inner = _h((username + ":" + password).encode("utf-8"))
    return _h_int(salt, inner)


def compute_v(N: int, g: int, x: int) -> int:
    return pow(g, x, N)


@dataclass(frozen=True)
class RegistrationRecord:
    username: str
    salt: bytes
    v: int


def register_user(N: int, g: int, username: str, password: str, salt: bytes) -> RegistrationRecord:
    x = compute_x(salt, username, password)
    v = compute_v(N, g, x)
    return RegistrationRecord(username=username, salt=salt, v=v)
```
The server should not store `P` (password) or even `H(P)`. Instead it stores a per-user salt `s` and verifier `v = g^x`. In SRP, `x` is derived from both the salt and `H(I ":" P)` (where `I` is the username), so the verifier is bound to the account identifier too.

### Step 3: Handshake (A, B, u, S, K)
```python
def compute_A(N: int, g: int, a: int) -> int:
    A = pow(g, a, N)
    if A % N == 0:
        raise ValueError("invalid A (A mod N == 0)")
    return A


def compute_B(N: int, g: int, k: int, v: int, b: int) -> int:
    B = (k * v + pow(g, b, N)) % N
    if B % N == 0:
        raise ValueError("invalid B (B mod N == 0)")
    return B


def compute_u(N: int, A: int, B: int) -> int:
    nlen = (N.bit_length() + 7) // 8
    u = _h_int(_i2b(A, nlen), _i2b(B, nlen))
    if u == 0:
        raise ValueError("invalid u (u == 0)")
    return u


def derive_K(N: int, S: int) -> bytes:
    return _h(_pad_int(S, N))


def client_compute_S(N: int, g: int, k: int, x: int, a: int, B: int, u: int) -> int:
    gx = pow(g, x, N)
    base = (B - k * gx) % N
    exp = a + u * x
    return pow(base, exp, N)


def server_compute_S(N: int, v: int, A: int, u: int, b: int) -> int:
    avu = (A * pow(v, u, N)) % N
    return pow(avu, b, N)
```
This is the SRP “magic”: both sides compute the same `S` even though the server never learns `x` and the client never learns `b`. The checks `A mod N != 0`, `B mod N != 0`, and `u != 0` are not optional: skipping them opens real attacks.

### Step 4: Key confirmation (M1, M2)
```python
def compute_M1(
    N: int,
    g: int,
    username: str,
    salt: bytes,
    A: int,
    B: int,
    K: bytes,
) -> bytes:
    nlen = (N.bit_length() + 7) // 8
    HN = _h(_i2b(N, nlen))
    Hg = _h(_i2b(g, nlen))
    Hxor = bytes(a ^ b for a, b in zip(HN, Hg, strict=True))
    HI = _h(username.encode("utf-8"))
    return _h(Hxor, HI, salt, _i2b(A, nlen), _i2b(B, nlen), K)


def compute_M2(N: int, A: int, M1: bytes, K: bytes) -> bytes:
    nlen = (N.bit_length() + 7) // 8
    return _h(_i2b(A, nlen), M1, K)
```
SRP without key confirmation is unfinished: you might derive `K`, but you don’t know if the other side derived the *same* `K`, or if an active attacker spliced messages. `M1` and `M2` bind the session key to the full transcript (including username and salt).

Run it:
`python3 code/main.py`

## Use It
- **TLS-SRP**: SRP can be used as a TLS ciphersuite (rare today).
- **Modern PAKE preference**: In 2026, many teams prefer **OPAQUE** (stronger leakage properties for server compromise), but SRP still appears in legacy systems.
- **If you need “password login” in production**: use a well-reviewed PAKE implementation rather than shipping your own SRP math.

## Pitfalls
- Skipping the checks `A % N != 0`, `B % N != 0`, `u != 0` (leads to trivial key recovery / forced keys).
- Hashing the wrong transcript encoding (non-canonical integer-to-bytes causes client/server disagreement or downgrade bugs).
- Reusing ephemeral secrets `a` or `b` (turns a PAKE into “recoverable password” territory).
- Treating `K = H(S)` as a password hash (it’s a session key; it must be used with an AEAD/HMAC and include channel binding).
- Assuming SRP is “secure password storage” by itself (it helps, but server compromise is still serious; choose designs carefully).

## Ship It
Save the SRP audit checklist in `outputs/srp-audit-checklist.md`. Use it to review:
- in-house SRP implementations,
- legacy SRP code in an acquired codebase,
- protocol-level PRs (message encoding, checks, proof binding).

## Exercises
1. Easy. Run `code/main.py`. Observe that the server never receives the password, but both sides still derive the same `K`.
2. Medium. Modify the demo to use a different username/password and confirm `M1` changes (transcript binding).
3. Hard. Sketch how you’d wrap `K` into an authenticated channel (e.g., derive `Kc2s`, `Ks2c` and use an AEAD).

## Key Terms
| Term | What people say | What it actually means |
|---|---|---|
| PAKE | “Password-based key exchange” | A protocol that turns a low-entropy password into a high-entropy session key without revealing the password |
| Verifier | “A salted password hash” | A public-value `v = g^x` that lets the server authenticate without storing `P` |
| Salt `s` | “Random bytes” | Per-user randomness that prevents precomputed attacks and binds `x` to an account |
| Key confirmation | “Mutual auth” | Transcript-bound proofs `M1`, `M2` that both sides derived the same `K` |

## Further Reading
- T. Wu, *The Secure Remote Password Protocol* (1998) — original SRP proposal and intuition.
- D. Taylor et al., *RFC 5054: Using the Secure Remote Password (SRP) Protocol for TLS Authentication* (2007) — group parameters and transcript conventions.
