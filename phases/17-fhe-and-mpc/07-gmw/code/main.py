"""
Educational implementation of the GMW protocol (2-party MPC over boolean circuits).

What this file does:
- Implements XOR secret-sharing over bits (mod 2).
- Implements a toy 1-out-of-2 Oblivious Transfer (Chou–Orlandi "Simplest OT"),
  instantiated in the multiplicative group modulo a prime.
- Uses two OTs to evaluate an AND gate on XOR-shared bits (GMW-style).
- Evaluates a small boolean circuit (2-bit equality) gate-by-gate on shares.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Iterable, List, Sequence, Tuple


def _int_to_bytes(x: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return b"\x00"
    nbytes = (x.bit_length() + 7) // 8
    return x.to_bytes(nbytes, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length byte strings")
    return bytes(x ^ y for x, y in zip(a, b))


def _require_bit(x: int, name: str) -> None:
    if x not in (0, 1):
        raise ValueError(f"{name} must be a bit (0 or 1)")


class HashRNG:
    """
    Deterministic RNG based on SHA-256(seed || counter).

    This is not intended to be secure randomness; it is used so that:
    - demos are reproducible
    - test vectors are stable across Python versions
    """

    def __init__(self, seed: int):
        if not isinstance(seed, int):
            raise TypeError("seed must be an int")
        self._seed = seed.to_bytes(32, "big", signed=False)
        self._counter = 0

    def _block(self) -> bytes:
        c = self._counter.to_bytes(8, "big", signed=False)
        self._counter += 1
        return hashlib.sha256(self._seed + c).digest()

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        limit = (1 << 256) - ((1 << 256) % n)
        while True:
            x = int.from_bytes(self._block(), "big")
            if x < limit:
                return x % n

    def randbit(self) -> int:
        return self.randbelow(2)


def xor_share_bit(bit: int, rng: HashRNG) -> Tuple[int, int]:
    """
    Split a bit into two XOR shares (share0, share1) such that:
      bit == share0 ^ share1
    """
    _require_bit(bit, "bit")
    s1 = rng.randbit()
    s0 = bit ^ s1
    return s0, s1


def xor_reconstruct(share0: int, share1: int) -> int:
    """Reconstruct a XOR-shared bit."""
    _require_bit(share0, "share0")
    _require_bit(share1, "share1")
    return share0 ^ share1


def xor_shares(x_sh: Tuple[int, int], y_sh: Tuple[int, int]) -> Tuple[int, int]:
    """Compute XOR gate locally on XOR shares."""
    x0, x1 = x_sh
    y0, y1 = y_sh
    _require_bit(x0, "x0")
    _require_bit(x1, "x1")
    _require_bit(y0, "y0")
    _require_bit(y1, "y1")
    return x0 ^ y0, x1 ^ y1


def not_shares(x_sh: Tuple[int, int]) -> Tuple[int, int]:
    """
    Compute NOT gate locally on XOR shares.

    We flip exactly one party's share so reconstruction toggles:
      (x0 ^ 1) ^ x1 == 1 ^ (x0 ^ x1) == NOT(x)
    """
    x0, x1 = x_sh
    _require_bit(x0, "x0")
    _require_bit(x1, "x1")
    return x0 ^ 1, x1


def _toy_ot_params() -> Tuple[int, int]:
    """
    Toy DH group parameters.

    p = 2^127 - 1 (a Mersenne prime)
    g is a small generator candidate (security is not the goal here).
    """
    p = 170141183460469231731687303715884105727  # 2^127 - 1
    g = 3
    return p, g


def _kdf_stream(key_material: bytes, out_len: int) -> bytes:
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    out = b""
    counter = 0
    while len(out) < out_len:
        out += hashlib.sha256(key_material + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:out_len]


def ot1of2_simplest(m0: bytes, m1: bytes, choice: int, rng: HashRNG) -> bytes:
    """
    1-out-of-2 OT (semi-honest, educational) using the "Simplest OT" structure.

    Sender holds (m0, m1). Receiver holds choice c in {0,1} and learns m_c.
    The sender should not learn c; the receiver should not learn m_{1-c}.
    """
    _require_bit(choice, "choice")
    if not isinstance(m0, (bytes, bytearray)) or not isinstance(m1, (bytes, bytearray)):
        raise TypeError("m0 and m1 must be bytes")
    m0 = bytes(m0)
    m1 = bytes(m1)

    p, g = _toy_ot_params()

    a = 1 + rng.randbelow(p - 2)
    A = pow(g, a, p)

    b = 1 + rng.randbelow(p - 2)
    gb = pow(g, b, p)
    if choice == 0:
        B = gb
    else:
        B = (A * gb) % p

    k0 = pow(B, a, p)
    invA = pow(A, -1, p)
    k1 = pow((B * invA) % p, a, p)

    k0_bytes = hashlib.sha256(_int_to_bytes(k0)).digest()
    k1_bytes = hashlib.sha256(_int_to_bytes(k1)).digest()
    c0 = _xor_bytes(m0, _kdf_stream(k0_bytes, len(m0)))
    c1 = _xor_bytes(m1, _kdf_stream(k1_bytes, len(m1)))

    kc = pow(A, b, p)
    kc_bytes = hashlib.sha256(_int_to_bytes(kc)).digest()
    if choice == 0:
        return _xor_bytes(c0, _kdf_stream(kc_bytes, len(c0)))
    return _xor_bytes(c1, _kdf_stream(kc_bytes, len(c1)))


@dataclasses.dataclass
class GMWStats:
    and_gates: int = 0
    ot_calls: int = 0


def gmw_and_shares(
    x_sh: Tuple[int, int],
    y_sh: Tuple[int, int],
    rng: HashRNG,
    stats: GMWStats | None = None,
) -> Tuple[int, int]:
    """
    Evaluate an AND gate on XOR shares using two 1-out-of-2 OTs.

    Inputs:
      x = x0 ^ x1
      y = y0 ^ y1
    Outputs:
      z0, z1 such that (z0 ^ z1) == (x & y)
    """
    x0, x1 = x_sh
    y0, y1 = y_sh
    _require_bit(x0, "x0")
    _require_bit(x1, "x1")
    _require_bit(y0, "y0")
    _require_bit(y1, "y1")

    if stats is not None:
        stats.and_gates += 1

    r = rng.randbit()
    t0 = ot1of2_simplest(bytes([r]), bytes([r ^ x0]), y1, rng)[0]
    if stats is not None:
        stats.ot_calls += 1

    s = rng.randbit()
    t1 = ot1of2_simplest(bytes([s]), bytes([s ^ x1]), y0, rng)[0]
    if stats is not None:
        stats.ot_calls += 1

    z0 = (x0 & y0) ^ r ^ t1
    z1 = (x1 & y1) ^ s ^ t0
    return z0, z1


@dataclasses.dataclass(frozen=True)
class Gate:
    op: str
    a: int
    b: int | None = None


class BoolCircuit:
    """
    Minimal boolean circuit with inputs owned by Party0 (A) and Party1 (B).

    Wires 0..(na-1) are A's input bits.
    Wires na..(na+nb-1) are B's input bits.
    Each gate appends one new wire.
    """

    def __init__(self, na: int, nb: int):
        if na < 0 or nb < 0:
            raise ValueError("na and nb must be non-negative")
        self.na = na
        self.nb = nb
        self.gates: List[Gate] = []
        self._wires = na + nb

    def wire_a(self, i: int) -> int:
        if not (0 <= i < self.na):
            raise ValueError("invalid A wire index")
        return i

    def wire_b(self, i: int) -> int:
        if not (0 <= i < self.nb):
            raise ValueError("invalid B wire index")
        return self.na + i

    def add_xor(self, w1: int, w2: int) -> int:
        out = self._wires
        self._wires += 1
        self.gates.append(Gate("XOR", w1, w2))
        return out

    def add_and(self, w1: int, w2: int) -> int:
        out = self._wires
        self._wires += 1
        self.gates.append(Gate("AND", w1, w2))
        return out

    def add_not(self, w: int) -> int:
        out = self._wires
        self._wires += 1
        self.gates.append(Gate("NOT", w, None))
        return out

    @property
    def num_wires(self) -> int:
        return self._wires


def _bits_of_uint(x: int, width: int) -> List[int]:
    if x < 0:
        raise ValueError("x must be non-negative")
    return [(x >> i) & 1 for i in range(width)]


def _require_bits(bits: Sequence[int], name: str) -> None:
    for i, b in enumerate(bits):
        if b not in (0, 1):
            raise ValueError(f"{name}[{i}] must be a bit (0 or 1)")


def gmw_eval_circuit_2pc(
    circuit: BoolCircuit,
    a_bits: Sequence[int],
    b_bits: Sequence[int],
    rng: HashRNG,
    output_wire: int,
    stats: GMWStats | None = None,
) -> Tuple[int, int]:
    """
    Evaluate circuit gate-by-gate on XOR shares.

    Returns output XOR shares (out0, out1).
    """
    if len(a_bits) != circuit.na:
        raise ValueError("a_bits length must match circuit.na")
    if len(b_bits) != circuit.nb:
        raise ValueError("b_bits length must match circuit.nb")
    _require_bits(a_bits, "a_bits")
    _require_bits(b_bits, "b_bits")

    wire_shares: List[Tuple[int, int]] = []
    for bit in a_bits:
        wire_shares.append(xor_share_bit(bit, rng))
    for bit in b_bits:
        wire_shares.append(xor_share_bit(bit, rng))

    for gate in circuit.gates:
        if gate.op == "XOR":
            assert gate.b is not None
            wire_shares.append(xor_shares(wire_shares[gate.a], wire_shares[gate.b]))
            continue
        if gate.op == "NOT":
            wire_shares.append(not_shares(wire_shares[gate.a]))
            continue
        if gate.op == "AND":
            assert gate.b is not None
            wire_shares.append(gmw_and_shares(wire_shares[gate.a], wire_shares[gate.b], rng, stats=stats))
            continue
        raise ValueError(f"unknown gate op: {gate.op}")

    if not (0 <= output_wire < len(wire_shares)):
        raise ValueError("invalid output_wire")
    return wire_shares[output_wire]


def build_2bit_equality_circuit() -> Tuple[BoolCircuit, int]:
    """
    Circuit computes eq(a0,a1,b0,b1) = (a0 XNOR b0) AND (a1 XNOR b1).
    """
    c = BoolCircuit(na=2, nb=2)
    a0 = c.wire_a(0)
    a1 = c.wire_a(1)
    b0 = c.wire_b(0)
    b1 = c.wire_b(1)

    x0 = c.add_xor(a0, b0)
    x1 = c.add_xor(a1, b1)
    nx0 = c.add_not(x0)
    nx1 = c.add_not(x1)
    out = c.add_and(nx0, nx1)
    return c, out


def xor_share_bit_seeded(bit: int, seed: int) -> Tuple[int, int]:
    return xor_share_bit(bit, HashRNG(seed))


def ot1of2_simplest_bit_seeded(m0_bit: int, m1_bit: int, choice: int, seed: int) -> int:
    _require_bit(m0_bit, "m0_bit")
    _require_bit(m1_bit, "m1_bit")
    out = ot1of2_simplest(bytes([m0_bit]), bytes([m1_bit]), choice, HashRNG(seed))
    return out[0]


def gmw_and_plain_seeded(x: int, y: int, seed: int) -> Tuple[int, int, int]:
    _require_bit(x, "x")
    _require_bit(y, "y")
    rng = HashRNG(seed)
    x_sh = xor_share_bit(x, rng)
    y_sh = xor_share_bit(y, rng)
    z0, z1 = gmw_and_shares(x_sh, y_sh, rng)
    return z0, z1, z0 ^ z1


def gmw_eq2_plain_seeded(a: int, b: int, seed: int) -> int:
    if not (0 <= a < 4) or not (0 <= b < 4):
        raise ValueError("a and b must be 2-bit unsigned integers (0..3)")
    rng = HashRNG(seed)
    circuit, out_wire = build_2bit_equality_circuit()
    a_bits = _bits_of_uint(a, 2)
    b_bits = _bits_of_uint(b, 2)
    out0, out1 = gmw_eval_circuit_2pc(circuit, a_bits, b_bits, rng, out_wire)
    return out0 ^ out1


def main():
    rng = HashRNG(2026)

    print("=== Step 1: XOR secret sharing ===")
    x = 1
    x0, x1 = xor_share_bit(x, rng)
    print(f"share({x}) -> (x0={x0}, x1={x1}), reconstruct -> {xor_reconstruct(x0, x1)}")
    y = 0
    y0, y1 = xor_share_bit(y, rng)
    s0, s1 = xor_shares((x0, x1), (y0, y1))
    print(f"reconstruct(x XOR y) -> {xor_reconstruct(s0, s1)} (expected {x ^ y})")
    n0, n1 = not_shares((x0, x1))
    print(f"reconstruct(NOT x) -> {xor_reconstruct(n0, n1)} (expected {x ^ 1})")

    print("\n=== Step 2: 1-out-of-2 Oblivious Transfer (toy) ===")
    m0 = b"red"
    m1 = b"blue"
    choice = 1
    got = ot1of2_simplest(m0, m1, choice, rng)
    print(f"sender has (m0={m0!r}, m1={m1!r}), receiver chooses c={choice} -> {got!r}")

    print("\n=== Step 3: GMW AND gate via OT ===")
    x = 1
    y = 1
    x_sh = xor_share_bit(x, rng)
    y_sh = xor_share_bit(y, rng)
    z0, z1 = gmw_and_shares(x_sh, y_sh, rng)
    z = xor_reconstruct(z0, z1)
    print(f"x={x}, y={y}, reconstruct(AND) -> {z} (expected {x & y})")

    print("\n=== Step 4: Circuit evaluation (2-bit equality) ===")
    circuit, out_wire = build_2bit_equality_circuit()
    a = 2
    b = 2
    stats = GMWStats()
    out0, out1 = gmw_eval_circuit_2pc(
        circuit, _bits_of_uint(a, 2), _bits_of_uint(b, 2), rng, out_wire, stats=stats
    )
    out = out0 ^ out1
    print(f"a={a:02b}, b={b:02b} -> eq = {out} (expected 1)")
    print(f"AND gates used: {stats.and_gates}, OT calls used: {stats.ot_calls}")
    a = 3
    b = 1
    stats = GMWStats()
    out0, out1 = gmw_eval_circuit_2pc(
        circuit, _bits_of_uint(a, 2), _bits_of_uint(b, 2), rng, out_wire, stats=stats
    )
    out = out0 ^ out1
    print(f"a={a:02b}, b={b:02b} -> eq = {out} (expected 0)")
    print(f"AND gates used: {stats.and_gates}, OT calls used: {stats.ot_calls}")


if __name__ == "__main__":
    main()
