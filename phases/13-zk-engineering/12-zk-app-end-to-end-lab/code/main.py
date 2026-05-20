"""ZK engineering lab: build a toy end-to-end ZK login flow (stdlib only).

Implements a Schnorr-style NIZK proof of knowledge of a discrete-log secret and
wires it into a minimal "register → challenge → prove → verify → issue token"
app flow, highlighting the engineering seams (encoding, domain separation,
session binding, replay protection).

Run: python3 code/main.py
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass


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


def recover_secret_from_nonce_reuse(params: DLGroup, proof1: SchnorrProof, c1: int, proof2: SchnorrProof, c2: int) -> int:
    if proof1.R != proof2.R:
        raise ValueError("proofs do not reuse the same nonce (R differs)")
    if c1 == c2:
        raise ValueError("challenges must differ")
    num = (proof1.s - proof2.s) % params.q
    den = (c1 - c2) % params.q
    inv = pow(den, -1, params.q)
    return (num * inv) % params.q


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


def rand_scalar(q: int) -> int:
    if q <= 0:
        raise ValueError("q must be positive")
    return secrets.randbelow(q)


def main():
    params = DLGroup(p=2039, q=1019, g=4)
    validate_group(params)

    print("=== Step 1: canonical encoding + domain-separated hashing ===")
    encoded = encode_int(2039) + encode_bytes(b"hello")
    a, off = decode_int(encoded, 0)
    b, off = decode_bytes(encoded, off)
    print(f"  decode_int(encode_int(2039)) → {a}")
    print(f"  decode_bytes(encode_bytes(b'hello')) → {b!r}")
    demo_scalar = hash_to_scalar("demo", [encode_bytes(b"hello")], params.q)
    print(f"  hash_to_scalar('demo', 'hello') mod q → {demo_scalar}")

    print()
    print("=== Step 2: Schnorr NIZK prove/verify (Fiat–Shamir) ===")
    user_secret = 123
    pk = public_key(params, user_secret)
    session_msg = make_login_message("alice", "session-123")
    proof = schnorr_prove(params, user_secret, session_msg, nonce=456)
    ok = schnorr_verify(params, pk, session_msg, proof)
    print(f"  public key pk = g^x mod p → {pk}")
    print(f"  proof (R, s) = ({proof.R}, {proof.s})")
    print(f"  verify(pk, msg, proof) → {ok}")

    print()
    print("=== Step 3: app wiring (register → login → token) ===")
    server = ZKLoginServer(params)
    server.register("alice", pk)
    token = server.verify_login("alice", "session-123", proof)
    print(f"  server.verify_login(...) → token={token!r}")
    token_replay = server.verify_login("alice", "session-123", proof)
    print(f"  replay same (user, session) → {token_replay!r}")

    print()
    print("=== Step 4: what breaks if you miss bindings ===")
    wrong_session_msg = make_login_message("alice", "session-999")
    ok_wrong = schnorr_verify(params, pk, wrong_session_msg, proof)
    print(f"  verify with different session_id → {ok_wrong}")
    msg1 = make_login_message("alice", "s1")
    msg2 = make_login_message("alice", "s2")
    reused_nonce = 777
    proof1 = schnorr_prove(params, user_secret, msg1, nonce=reused_nonce)
    proof2 = schnorr_prove(params, user_secret, msg2, nonce=reused_nonce)
    c1 = _challenge(params, pk, proof1.R, msg1)
    c2 = _challenge(params, pk, proof2.R, msg2)
    recovered = recover_secret_from_nonce_reuse(params, proof1, c1, proof2, c2)
    print(f"  nonce reuse leaks secret: recovered x = {recovered} (expected {user_secret})")


if __name__ == "__main__":
    main()
