"""
Toy OPRF and VOPRF (verifiable OPRF) over a prime-order subgroup of Z_p*.

This file implements:
- A DH-style OPRF (blind -> evaluate -> unblind -> finalize)
- A simplified non-interactive DLEQ proof to make it verifiable (VOPRF)

Run:
  python3 code/main.py

Educational implementation. Not constant-time. Not production-safe.
"""

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
