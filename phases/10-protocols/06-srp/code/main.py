"""
SRP-6a (Secure Remote Password) from scratch (educational).

Runs a deterministic end-to-end SRP login to show:
- how the server stores a verifier (not the password),
- how client/server derive the same session key,
- how key confirmation prevents an active MITM.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


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


def compute_x(salt: bytes, username: str, password: str) -> int:
    inner = _h((username + ":" + password).encode("utf-8"))
    return _h_int(salt, inner)


def compute_v(N: int, g: int, x: int) -> int:
    return pow(g, x, N)


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


@dataclass(frozen=True)
class RegistrationRecord:
    username: str
    salt: bytes
    v: int


def register_user(N: int, g: int, username: str, password: str, salt: bytes) -> RegistrationRecord:
    x = compute_x(salt, username, password)
    v = compute_v(N, g, x)
    return RegistrationRecord(username=username, salt=salt, v=v)


@dataclass(frozen=True)
class ClientHello:
    username: str
    A: int


@dataclass(frozen=True)
class ServerHello:
    salt: bytes
    B: int


@dataclass(frozen=True)
class ClientSession:
    username: str
    salt: bytes
    A: int
    B: int
    u: int
    S: int
    K: bytes
    M1: bytes


@dataclass(frozen=True)
class ServerSession:
    username: str
    salt: bytes
    A: int
    B: int
    u: int
    S: int
    K: bytes
    M1: bytes
    M2: bytes


def client_start(N: int, g: int, username: str, a: int) -> tuple[ClientHello, int]:
    A = compute_A(N, g, a)
    return ClientHello(username=username, A=A), A


def server_start(N: int, g: int, record: RegistrationRecord, A: int, b: int) -> ServerHello:
    if A % N == 0:
        raise ValueError("invalid A (A mod N == 0)")
    if record.v <= 1 or record.v >= N:
        raise ValueError("invalid verifier")
    k = compute_k(N, g)
    B = compute_B(N, g, k, record.v, b)
    return ServerHello(salt=record.salt, B=B)


def client_finish(
    N: int,
    g: int,
    username: str,
    password: str,
    a: int,
    salt: bytes,
    A: int,
    B: int,
) -> ClientSession:
    if B % N == 0:
        raise ValueError("invalid B (B mod N == 0)")
    u = compute_u(N, A, B)
    k = compute_k(N, g)
    x = compute_x(salt, username, password)
    S = client_compute_S(N, g, k, x, a, B, u)
    K = derive_K(N, S)
    M1 = compute_M1(N, g, username, salt, A, B, K)
    return ClientSession(username=username, salt=salt, A=A, B=B, u=u, S=S, K=K, M1=M1)


def server_finish(N: int, g: int, record: RegistrationRecord, A: int, B: int, b: int, M1: bytes) -> ServerSession:
    if A % N == 0:
        raise ValueError("invalid A (A mod N == 0)")
    if B % N == 0:
        raise ValueError("invalid B (B mod N == 0)")
    u = compute_u(N, A, B)
    S = server_compute_S(N, record.v, A, u, b)
    K = derive_K(N, S)
    expected_M1 = compute_M1(N, g, record.username, record.salt, A, B, K)
    if expected_M1 != M1:
        raise ValueError("client proof M1 is invalid (wrong password or active attack)")
    M2 = compute_M2(N, A, M1, K)
    return ServerSession(
        username=record.username,
        salt=record.salt,
        A=A,
        B=B,
        u=u,
        S=S,
        K=K,
        M1=M1,
        M2=M2,
    )


def _hex(b: bytes) -> str:
    return b.hex()


def _hex_int(n: int) -> str:
    return hex(n)[2:]


def main() -> None:
    N, g = group_1024()

    username = "alice"
    password = "correct horse battery staple"

    salt = bytes.fromhex("beb25379d1a8581eb5a727673a2441ee")
    a = int("60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393", 16)
    b = int("e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20", 16)

    print("=== Step 1: Parameters + hashing ===")
    print(f"N_bits={N.bit_length()} g={g} k={compute_k(N, g)}")
    print()

    print("=== Step 2: Registration (salt -> verifier) ===")
    record = register_user(N, g, username, password, salt)
    print(f"username={record.username}")
    print(f"salt={_hex(record.salt)}")
    print(f"v={_hex_int(record.v)[:64]}... (len={record.v.bit_length()} bits)")
    print()

    print("=== Step 3: Handshake (A, B, u, S, K) ===")
    ch, A = client_start(N, g, username, a)
    sh = server_start(N, g, record, A, b)
    B = sh.B
    u = compute_u(N, A, B)
    print(f"A={_hex_int(A)[:64]}...")
    print(f"B={_hex_int(B)[:64]}...")
    print(f"u={u}")

    client = client_finish(N, g, ch.username, password, a, sh.salt, A, sh.B)
    print(f"S_client={_hex_int(client.S)[:64]}...")
    print(f"K_client={_hex(client.K)}")
    print()

    print("=== Step 4: Key confirmation (M1, M2) ===")
    server = server_finish(N, g, record, A, sh.B, b, client.M1)
    m2 = compute_M2(N, A, client.M1, client.K)
    print(f"M1={_hex(client.M1)}")
    print(f"M2_server={_hex(server.M2)}")
    print(f"M2_client={_hex(m2)}")
    print(f"keys_match={server.K == client.K} proofs_match={server.M2 == m2}")
    print()

    print("=== Failure demo: wrong password ===")
    try:
        bad_client = client_finish(N, g, ch.username, "wrong password", a, sh.salt, A, sh.B)
        _ = server_finish(N, g, record, A, sh.B, b, bad_client.M1)
        print("unexpected: server accepted wrong password")
    except ValueError as e:
        print(f"server rejects: {e}")


if __name__ == "__main__":
    main()
