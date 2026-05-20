# ZK Engineering Lab — Build a ZK App End to End

> Proofs don’t fail in the math — they fail at the boundaries.

**Type:** Build
**Languages:** Python
**Prerequisites:**
- `phases/01-number-theory/14-index-calculus-discrete-log`
- `phases/05-probability-and-information/08-the-simulator`
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why ZK proofs must be bound to a fresh session challenge.
- Compute a Fiat–Shamir challenge scalar from a canonical transcript.
- Implement Schnorr NIZK prove/verify over a safe-prime subgroup.
- Distinguish crypto verification from application authorization and state.
- Apply a ZK integration audit checklist to a login-style flow.

## The Problem

You can have a “correct” ZK proof and still ship a broken ZK app. In production, most incidents come from seams: ambiguous encoding, missing domain separation, forgetting to bind the proof to a session, or verifying a proof but failing to enforce replay protection and authorization.

This lesson is an end-to-end lab that makes those seams visible. We’ll build a tiny ZK login flow in pure Python (stdlib only): a client proves knowledge of a secret `x` without revealing it, and a server verifies the proof and issues a token. Then we’ll demonstrate what breaks if you skip bindings or mishandle nonces.

## The Concept

Think of a ZK app as two layers that must agree:

| Layer | You’re trying to guarantee | Typical failure mode |
|------:|-----------------------------|----------------------|
| Proof layer | “This statement is true.” | Wrong statement, wrong transcript, wrong parameters |
| App layer | “This is the right proof, for this user, for this action, right now.” | Replay, missing freshness, missing authorization, state bugs |

In a Schnorr-style proof of knowledge (discrete log), the *statement* is “I know `x` such that `pk = g^x (mod p)`.” The proof transcript has values that must be hashed in a *canonical* way to derive a challenge `c` (Fiat–Shamir). If you don’t bind the transcript to the app context (user + session + action), an attacker can replay proofs or move them across contexts.

## Build It

### Step 1: Canonical encoding + domain-separated hashing

We start with a canonical, length-prefixed encoding for integers/bytes, plus a domain-separated hash-to-scalar function. This prevents “different values, same bytes” bugs and keeps transcripts unambiguous.

```python
import hashlib
import struct


def _u16(n: int) -> bytes:
    if not (0 <= n <= 0xFFFF):
        raise ValueError("u16 out of range")
    return struct.pack(">H", n)


def encode_bytes(b: bytes) -> bytes:
    return _u16(len(b)) + b


def encode_int(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative integers not supported")
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return encode_bytes(raw)


def decode_bytes(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated u16 length")
    (n,) = struct.unpack(">H", data[offset : offset + 2])
    start = offset + 2
    end = start + n
    if end > len(data):
        raise ValueError("truncated bytes payload")
    return data[start:end], end


def decode_int(data: bytes, offset: int = 0) -> tuple[int, int]:
    raw, next_offset = decode_bytes(data, offset)
    return int.from_bytes(raw, "big"), next_offset


def hash_to_scalar(domain: str, parts: list[bytes], q: int) -> int:
    if q <= 0:
        raise ValueError("q must be positive")
    h = hashlib.sha256()
    h.update(domain.encode("utf-8"))
    h.update(b"\x00")
    for part in parts:
        h.update(part)
    return int.from_bytes(h.digest(), "big") % q
```

### Step 2: Schnorr NIZK prove/verify (Fiat–Shamir)

Now we implement a Schnorr-style NIZK proof of knowledge in a subgroup of `Z_p*` with order `q`. The prover produces `(R, s)` and the verifier recomputes `c` from the transcript and checks `g^s == R · pk^c (mod p)`.

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class DLGroup:
    p: int
    q: int
    g: int


def validate_group(params: DLGroup) -> None:
    if params.p <= 2 or params.q <= 1:
        raise ValueError("invalid sizes")
    if not (2 <= params.g < params.p):
        raise ValueError("g out of range")
    if (params.p - 1) % params.q != 0:
        raise ValueError("q must divide p-1")
    if pow(params.g, params.q, params.p) != 1:
        raise ValueError("g^q must be 1 mod p (subgroup check)")
    if pow(params.g, (params.p - 1) // params.q, params.p) == 1:
        raise ValueError("g does not have exact order q")


def public_key(params: DLGroup, x: int) -> int:
    if not (0 <= x < params.q):
        raise ValueError("secret out of range")
    return pow(params.g, x, params.p)


@dataclass(frozen=True)
class SchnorrProof:
    R: int
    s: int


def _challenge(params: DLGroup, pk: int, R: int, message: bytes) -> int:
    return hash_to_scalar(
        "ZKLAB-SCHNORR-V1",
        [
            encode_int(params.p),
            encode_int(params.q),
            encode_int(params.g),
            encode_int(pk),
            encode_int(R),
            encode_bytes(message),
        ],
        params.q,
    )


def schnorr_prove(params: DLGroup, x: int, message: bytes, nonce: int) -> SchnorrProof:
    if not (0 <= nonce < params.q):
        raise ValueError("nonce out of range")
    pk = public_key(params, x)
    R = pow(params.g, nonce, params.p)
    c = _challenge(params, pk, R, message)
    s = (nonce + c * x) % params.q
    return SchnorrProof(R=R, s=s)


def schnorr_verify(params: DLGroup, pk: int, message: bytes, proof: SchnorrProof) -> bool:
    if not (1 < pk < params.p):
        return False
    if not (1 < proof.R < params.p):
        return False
    if not (0 <= proof.s < params.q):
        return False
    if pow(pk, params.q, params.p) != 1:
        return False
    c = _challenge(params, pk, proof.R, message)
    left = pow(params.g, proof.s, params.p)
    right = (proof.R * pow(pk, c, params.p)) % params.p
    return left == right
```

### Step 3: App wiring (register → login → token)

We now wrap proof verification in application state: user registration, challenge binding (`make_login_message`), and replay protection (tracking used `(user_id, session_id)`).

```python
def make_login_message(user_id: str, session_id: str) -> bytes:
    if "|" in user_id or "|" in session_id:
        raise ValueError("invalid delimiter in id")
    return b"login|" + user_id.encode("utf-8") + b"|" + session_id.encode("utf-8")


class ZKLoginServer:
    def __init__(self, params: DLGroup):
        validate_group(params)
        self._params = params
        self._users: dict[str, int] = {}
        self._used_sessions: set[tuple[str, str]] = set()

    @property
    def params(self) -> DLGroup:
        return self._params

    def register(self, user_id: str, pk: int) -> None:
        if user_id in self._users:
            raise ValueError("user already exists")
        if pow(pk, self._params.q, self._params.p) != 1:
            raise ValueError("invalid public key element")
        self._users[user_id] = pk

    def verify_login(self, user_id: str, session_id: str, proof: SchnorrProof) -> str | None:
        if (user_id, session_id) in self._used_sessions:
            return None
        pk = self._users.get(user_id)
        if pk is None:
            return None
        msg = make_login_message(user_id, session_id)
        if not schnorr_verify(self._params, pk, msg, proof):
            return None
        self._used_sessions.add((user_id, session_id))
        t = hashlib.sha256(b"token|" + encode_bytes(msg) + encode_int(proof.R) + encode_int(proof.s)).hexdigest()
        return t[:32]
```

### Step 4: Failure modes & a concrete extraction attack (nonce reuse)

Even if verification is correct, engineering mistakes can leak the secret. The classic Schnorr failure mode is nonce reuse: two accepting transcripts with the same `R` but different challenges reveal `x`.

```python
def recover_secret_from_nonce_reuse(params: DLGroup, proof1: SchnorrProof, c1: int, proof2: SchnorrProof, c2: int) -> int:
    if proof1.R != proof2.R:
        raise ValueError("proofs do not reuse the same nonce (R differs)")
    if c1 == c2:
        raise ValueError("challenges must differ")
    num = (proof1.s - proof2.s) % params.q
    den = (c1 - c2) % params.q
    inv = pow(den, -1, params.q)
    return (num * inv) % params.q
```

Run it:

`python3 code/main.py`

## Use It

In real systems you rarely implement the proof system yourself. Instead you:

- **Define a circuit/program**: Circom, Noir, Halo2, RISC0/SP1, etc.
- **Generate proving/verifying keys**: trusted setup (if needed) + versioned artifacts.
- **Integrate verification**:
  - off-chain: verifier library + API boundary,
  - on-chain: verifier contract + calldata encoding + replay/nullifier logic.

Production equivalents to look at:

- Circom + snarkjs (Groth16/PLONK toolchain)
- Halo2 (Rust) / arkworks (Rust) for PLONK-ish ecosystems
- Semaphore (identity + nullifiers) as a reference for app-layer replay protection

## Pitfalls

- **No freshness binding**: proof verifies, but the app accepts replays because the transcript isn’t tied to a unique challenge (session id / nonce / nullifier).
- **Ambiguous transcript encoding**: prover and verifier serialize fields differently (or concatenate without lengths), creating “same bytes, different meaning” bugs.
- **Skipping key/element validation**: accepting `pk` outside the intended subgroup can break soundness assumptions.
- **Nonce reuse**: bad randomness, concurrency bugs, or deterministic reuse leaks the secret (the extraction attack in Step 4).
- **Confusing verification with authorization**: “proof ok” is not the same as “this user may do this action now.”

## Ship It

Save and reuse the audit artifact:

- `outputs/zk-app-end-to-end-review-checklist.md`

Use it as a PR review checklist for any ZK integration (off-chain or on-chain). The goal is to catch boundary bugs before they become incidents.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe which fields are hashed into the challenge and how replay is rejected at the server layer.
2. Medium. Extend the login message to include an action string (e.g., `GET /transfer?amount=...`) and show that the same proof no longer verifies for a different action.
3. Hard. Re-implement the same “bind-to-session + replay protection” pattern in a real ZK stack (e.g., Circom+snarkjs or Halo2) and document the exact transcript/public inputs used by the verifier.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Transcript | “The proof bytes” | The ordered set of values hashed/sent that define what is being proven |
| Domain separation | “A protocol label” | A mechanism to prevent the same bytes being valid in multiple protocols/roles |
| Fiat–Shamir | “Make it non-interactive” | Replace verifier randomness with a hash-derived challenge in a ROM model |
| Replay protection | “Use a nonce” | App-level state that prevents reusing a valid proof to repeat an action |
| Nonce reuse | “RNG bug” | A catastrophic condition where repeated randomness lets attackers extract secrets |

## Further Reading

- Fiat, Shamir, *How to Prove Yourself: Practical Solutions to Identification and Signature Problems* (1986) — Introduces the Fiat–Shamir transform.
- Schnorr, *Efficient Identification and Signatures for Smart Cards* (1991) — Schnorr identification/signatures and the core algebra.
- Boneh, Shoup, *A Graduate Course in Applied Cryptography* (2020) — A clear reference for sigma protocols, transcripts, and reductions.
- “Semaphore” documentation and papers (various) — A strong example of nullifiers + application-layer anti-replay in ZK identity systems.
