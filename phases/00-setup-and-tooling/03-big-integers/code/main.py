from __future__ import annotations


def os2ip(x: bytes) -> int:
    n = 0
    for b in x:
        n = (n << 8) | b
    return n


def _min_bytes_len_uint(x: int) -> int:
    if x == 0:
        return 1
    return (x.bit_length() + 7) // 8


def uint_to_bytes_be(x: int, length: int | None = None) -> bytes:
    if x < 0:
        raise ValueError("x must be nonnegative")
    out_len = _min_bytes_len_uint(x) if length is None else length
    if out_len <= 0:
        raise ValueError("length must be positive")
    if x >= (1 << (8 * out_len)):
        raise ValueError("integer too large")

    out = bytearray(out_len)
    v = x
    for i in range(out_len - 1, -1, -1):
        out[i] = v & 0xFF
        v >>= 8
    return bytes(out)


def i2osp(x: int, x_len: int) -> bytes:
    return uint_to_bytes_be(x, x_len)


def split_uint_le_limbs(x: int, *, limb_bits: int = 32) -> list[int]:
    if x < 0:
        raise ValueError("x must be nonnegative")
    if limb_bits <= 0:
        raise ValueError("limb_bits must be positive")

    mask = (1 << limb_bits) - 1
    limbs: list[int] = []
    v = x
    while v:
        limbs.append(v & mask)
        v >>= limb_bits
    return limbs or [0]


def combine_uint_le_limbs(limbs: list[int], *, limb_bits: int = 32) -> int:
    if limb_bits <= 0:
        raise ValueError("limb_bits must be positive")
    if not limbs:
        raise ValueError("limbs must be non-empty")

    base = 1 << limb_bits
    n = 0
    for i in range(len(limbs) - 1, -1, -1):
        limb = limbs[i]
        if limb < 0 or limb >= base:
            raise ValueError("limb out of range")
        n = n * base + limb
    return n


def add_le_limbs(a: list[int], b: list[int], *, limb_bits: int = 32) -> list[int]:
    if limb_bits <= 0:
        raise ValueError("limb_bits must be positive")
    if not a or not b:
        raise ValueError("limb lists must be non-empty")

    base = 1 << limb_bits
    carry = 0
    out: list[int] = []
    n = max(len(a), len(b))
    for i in range(n):
        ai = a[i] if i < len(a) else 0
        bi = b[i] if i < len(b) else 0
        if ai < 0 or ai >= base or bi < 0 or bi >= base:
            raise ValueError("limb out of range")
        s = ai + bi + carry
        out.append(s & (base - 1))
        carry = s >> limb_bits
    if carry:
        out.append(carry)
    return out


def main() -> None:
    samples = [
        0,
        1,
        9,
        255,
        256,
        (1 << 130) + 12345,
    ]

    print("Big integers in Python (unbounded `int`)")
    print()
    for x in samples:
        b = uint_to_bytes_be(x)
        rt = os2ip(b)
        print(f"x = {x}")
        print(f"  bit_length = {x.bit_length()}")
        print(f"  bytes(be,min) = {b.hex()}")
        print(f"  roundtrip(os2ip) = {rt}")
        assert rt == x
        print()

    x = (1 << 96) + 7
    limbs = split_uint_le_limbs(x, limb_bits=32)
    rebuilt = combine_uint_le_limbs(limbs, limb_bits=32)
    print("Limb representation (32-bit limbs, little-endian list)")
    print(f"  x = {x}")
    print(f"  limbs = {limbs}")
    print(f"  rebuilt = {rebuilt}")
    assert rebuilt == x


if __name__ == "__main__":
    main()
