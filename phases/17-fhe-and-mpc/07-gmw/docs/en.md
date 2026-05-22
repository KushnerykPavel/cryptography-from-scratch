# GMW Protocol (Boolean MPC)
> XOR is free; AND costs communication.

**Type:** Build
**Languages:** Python
**Prerequisites:** `17-fhe-and-mpc/06-yao-garbled-circuits`, Diffie–Hellman (earlier key exchange lesson)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how GMW maintains XOR-shared values on every wire.
- **Compute** XOR/NOT gates locally on shares without communication.
- **Implement** a toy 1-out-of-2 Oblivious Transfer (OT) primitive.
- **Distinguish** “free” (XOR/NOT) gates from interactive (AND) gates in the cost model.
- **Apply** 2-party GMW to evaluate a small boolean circuit (2-bit equality).

## The Problem
Two parties often need to compute a boolean function on private inputs: “are our 2-bit IDs equal?”, “does my password hash match yours?”, “did we both vote yes?”, or “is my risk score above your threshold?”. If one side sends their input, privacy is gone. If you outsource to a trusted third party, that party becomes a single point of failure and a legal/compliance burden.

Yao’s Garbled Circuits gives a classic 2-party solution. But there’s another generic MPC approach that becomes very attractive when your circuit has lots of XORs: **GMW**. GMW’s key engineering insight is that XOR and NOT can be done *locally* on secret shares, so the online communication cost is driven mostly by the number of AND gates.

## The Concept
GMW represents each wire value `w ∈ {0,1}` as an XOR sharing between two parties:

```
w = w0 ⊕ w1
Party 0 holds w0
Party 1 holds w1
```

With XOR sharing:
- **XOR gate:** `(x0 ⊕ x1) ⊕ (y0 ⊕ y1)` can be computed share-wise:
  - Party 0: `z0 = x0 ⊕ y0`
  - Party 1: `z1 = x1 ⊕ y1`
- **NOT gate:** `¬x = 1 ⊕ x` can be done by flipping exactly one share:
  - Party 0: `z0 = x0 ⊕ 1`, Party 1: `z1 = x1`
- **AND gate:** `x ∧ y` is non-linear, and *cannot* be computed locally from XOR shares. This is where **Oblivious Transfer (OT)** shows up.

The cost model you should remember:

| Gate | Communication? | Why |
|---|---:|---|
| XOR | No | linear over `GF(2)` |
| NOT | No | `¬x = 1 ⊕ x` |
| AND | Yes | needs OT (or preprocessing like Beaver triples) |

## Build It

### Step 1: XOR secret sharing
We’ll represent every wire as two random-looking bits whose XOR equals the real value.

```python
import hashlib

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

def xor_share_bit(bit: int, rng: HashRNG):
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

def xor_shares(x_sh, y_sh):
    """Compute XOR gate locally on XOR shares."""
    x0, x1 = x_sh
    y0, y1 = y_sh
    _require_bit(x0, "x0")
    _require_bit(x1, "x1")
    _require_bit(y0, "y0")
    _require_bit(y1, "y1")
    return x0 ^ y0, x1 ^ y1

def not_shares(x_sh):
    """
    Compute NOT gate locally on XOR shares.

    We flip exactly one party's share so reconstruction toggles:
      (x0 ^ 1) ^ x1 == 1 ^ (x0 ^ x1) == NOT(x)
    """
    x0, x1 = x_sh
    _require_bit(x0, "x0")
    _require_bit(x1, "x1")
    return x0 ^ 1, x1
```
This gives you the basic invariant: each wire is always represented as `(w0, w1)` with `w = w0 ⊕ w1`.

### Step 2: 1-out-of-2 Oblivious Transfer (toy)
For an AND gate, parties need a tiny interactive primitive: the receiver learns one of two masked values, but doesn’t learn the other; the sender doesn’t learn which one was chosen.

```python
import hashlib

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

def _toy_ot_params():
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
```
This is intentionally “toy”: it’s enough to understand how OT enables AND gates, but it’s not a production-ready OT stack.

### Step 3: GMW AND gate via OT
The trick is to compute the AND gate output as XOR shares, without either party learning `x` or `y`.

```python
import dataclasses

@dataclasses.dataclass
class GMWStats:
    and_gates: int = 0
    ot_calls: int = 0

def gmw_and_shares(x_sh, y_sh, rng: HashRNG, stats: GMWStats | None = None):
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
```
After this, the AND gate output wire is *again* a normal XOR sharing. That’s the whole point: you can keep evaluating the circuit wire-by-wire.

### Step 4: Circuit evaluation (2-bit equality)
We’ll evaluate a circuit for `(a == b)` where each party provides a 2-bit input.

```python
import dataclasses
from typing import List, Sequence, Tuple

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

def build_2bit_equality_circuit():
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
```
This is the “GMW loop”: secret-share inputs, run gates left-to-right, reveal only the final output wire by XORing shares.

Run it:
```bash
python3 code/main.py
```

## Use It
Production MPC frameworks typically implement GMW (and many variants/optimizations) with OT extension, preprocessing, and strong threat-model knobs:

| Tooling | What you get |
|---|---|
| **EMP-toolkit / emp-ag2pc** | Fast 2PC building blocks (OT, GC, and more) |
| **ABY / ABY2.0** | Mixed-protocol 2PC (Arithmetic/Boolean/Yao) with conversions |
| **MP-SPDZ** | Multiple MPC protocols (incl. boolean/garbled/arith) and compiler toolchain |

## Pitfalls
1. **Forgetting the cost model**: in GMW, XORs are cheap but ANDs dominate. A “small” circuit with many AND gates can still be communication-heavy.
2. **Treating toy OT as real OT**: our OT is educational. Real systems use curve groups, hardened implementations, and OT extension; rolling your own OT is a common source of catastrophic breaks.
3. **Mixing share types**: XOR-shared bits (boolean sharing) behave differently from arithmetic shares mod `p`. Conversions are protocols, not casts.
4. **Assuming malicious security**: the demo is semi-honest. Malicious adversaries require extra checks (commitments, MACs, cut-and-choose, etc.).
5. **Side channels**: constant-time requirements don’t disappear just because you’re doing MPC.

## Ship It
Save and reuse the checklist in `outputs/gmw_checklist.md` when you design or review an MPC system that claims “we use GMW”.

## Exercises
1. **Easy**: Run `python3 code/main.py`. Observe that the number of OT calls is `2 × (# AND gates)` for this 2-party implementation.
2. **Medium**: Extend `build_2bit_equality_circuit()` into a 3-bit equality circuit, and confirm the OT count matches the new AND gate count.
3. **Hard**: Replace OT-based AND with a preprocessing-based AND (Beaver triples over `GF(2)`), and compare the online communication.

## Key Terms
| Term | What people say | What it actually means |
|---|---|---|
| **XOR sharing** | “Split a bit into two parts.” | A 2-out-of-2 secret sharing where `w = w0 ⊕ w1` and each share is uniformly random alone. |
| **Wire (in MPC)** | “A variable in the circuit.” | A value that stays secret-shared across gates until you explicitly reconstruct it. |
| **Oblivious Transfer (OT)** | “Receiver gets one of two messages.” | A protocol where the receiver learns `m_c` but not `m_{1-c}`, and the sender doesn’t learn `c`. |
| **Semi-honest** | “Everyone follows the protocol.” | Adversaries may try to learn extra information from transcripts but don’t deviate from prescribed steps. |
| **AND gate interaction** | “AND is expensive.” | Non-linear operations on XOR shares require communication (OT or preprocessing). |

## Further Reading
- Goldreich, Micali, Wigderson, *How to Play any Mental Game* (1987) — the original GMW line of work.
- Chou, Orlandi, *The Simplest Protocol for Oblivious Transfer* (2015) — a minimal OT construction (and a gateway to OT extension).
- Keller, Orsini, Scholl, *MASCOT / SPDZ family papers* (2016+) — practical preprocessing and malicious-security techniques used in modern MPC stacks.
