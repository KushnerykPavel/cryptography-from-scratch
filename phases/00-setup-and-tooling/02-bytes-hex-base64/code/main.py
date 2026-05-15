from __future__ import annotations

import base64
import binascii


_HEX_LOWER = "0123456789abcdef"
_HEX_UPPER = "0123456789ABCDEF"

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def to_bytes(text: str, *, encoding: str = "utf-8") -> bytes:
    return text.encode(encoding)


def from_bytes(data: bytes, *, encoding: str = "utf-8", errors: str = "strict") -> str:
    return data.decode(encoding, errors=errors)


def hex_encode(data: bytes, *, uppercase: bool = False) -> str:
    alphabet = _HEX_UPPER if uppercase else _HEX_LOWER
    out = []
    for b in data:
        out.append(alphabet[b >> 4])
        out.append(alphabet[b & 0x0F])
    return "".join(out)


def _hex_value(ch: str) -> int:
    o = ord(ch)
    if 48 <= o <= 57:
        return o - 48
    if 97 <= o <= 102:
        return o - 97 + 10
    if 65 <= o <= 70:
        return o - 65 + 10
    raise ValueError(f"non-hex character: {ch!r}")


def hex_decode(hex_str: str) -> bytes:
    if len(hex_str) % 2 != 0:
        raise ValueError("hex string must have even length")
    out = bytearray()
    for i in range(0, len(hex_str), 2):
        hi = _hex_value(hex_str[i])
        lo = _hex_value(hex_str[i + 1])
        out.append((hi << 4) | lo)
    return bytes(out)


def b64_encode(data: bytes) -> str:
    if not data:
        return ""

    out = []
    i = 0
    while i + 3 <= len(data):
        block = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(_B64_ALPHABET[(block >> 18) & 0x3F])
        out.append(_B64_ALPHABET[(block >> 12) & 0x3F])
        out.append(_B64_ALPHABET[(block >> 6) & 0x3F])
        out.append(_B64_ALPHABET[block & 0x3F])
        i += 3

    rem = len(data) - i
    if rem == 1:
        block = data[i] << 16
        out.append(_B64_ALPHABET[(block >> 18) & 0x3F])
        out.append(_B64_ALPHABET[(block >> 12) & 0x3F])
        out.append("=")
        out.append("=")
    elif rem == 2:
        block = (data[i] << 16) | (data[i + 1] << 8)
        out.append(_B64_ALPHABET[(block >> 18) & 0x3F])
        out.append(_B64_ALPHABET[(block >> 12) & 0x3F])
        out.append(_B64_ALPHABET[(block >> 6) & 0x3F])
        out.append("=")

    return "".join(out)


def _b64_value(ch: str) -> int:
    o = ord(ch)
    if 65 <= o <= 90:
        return o - 65
    if 97 <= o <= 122:
        return o - 97 + 26
    if 48 <= o <= 57:
        return o - 48 + 52
    if ch == "+":
        return 62
    if ch == "/":
        return 63
    raise ValueError(f"non-base64 character: {ch!r}")


def b64_decode(b64_str: str) -> bytes:
    if not b64_str:
        return b""

    if len(b64_str) % 4 != 0:
        raise ValueError("base64 length must be a multiple of 4")

    out = bytearray()
    i = 0
    while i < len(b64_str):
        chunk = b64_str[i : i + 4]
        if len(chunk) != 4:
            raise ValueError("invalid base64 length")

        pad = chunk.count("=")
        if pad not in (0, 1, 2):
            raise ValueError("invalid base64 padding")
        if pad and i + 4 != len(b64_str):
            raise ValueError("padding '=' may only appear in the final quartet")
        if pad == 1 and chunk[3] != "=":
            raise ValueError("single '=' padding must be in the last position")
        if pad == 2 and chunk[2:] != "==":
            raise ValueError("double '==' padding must be in the last two positions")

        v0 = _b64_value(chunk[0])
        v1 = _b64_value(chunk[1])
        v2 = 0 if chunk[2] == "=" else _b64_value(chunk[2])
        v3 = 0 if chunk[3] == "=" else _b64_value(chunk[3])

        block = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3
        out.append((block >> 16) & 0xFF)
        if chunk[2] != "=":
            out.append((block >> 8) & 0xFF)
        if chunk[3] != "=":
            out.append(block & 0xFF)

        if pad:
            break

        i += 4

    return bytes(out)


def _stdlib_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


def _stdlib_unhex(hex_str: str) -> bytes:
    return binascii.unhexlify(hex_str)


def _stdlib_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _stdlib_unb64(b64_str: str) -> bytes:
    return base64.b64decode(b64_str, validate=True)


def main():
    samples = [
        "hello",
        "cryptography from scratch",
        "π≈3.14159",
        "\x00\x01\x02 not text",
    ]

    for s in samples:
        b = to_bytes(s)
        hx = hex_encode(b)
        b64 = b64_encode(b)
        print(f"text: {s!r}")
        print(f"  bytes: {b!r}")
        print(f"  hex: {hx}")
        print(f"  base64: {b64}")
        print(f"  roundtrip(hex): {from_bytes(hex_decode(hx), errors='replace')!r}")
        print(f"  roundtrip(b64): {from_bytes(b64_decode(b64), errors='replace')!r}")
        print()

    msg = b"foobar"
    print("sanity checks vs stdlib:")
    print(f"  hex  ours={hex_encode(msg)} stdlib={_stdlib_hex(msg)}")
    print(f"  b64  ours={b64_encode(msg)} stdlib={_stdlib_b64(msg)}")
    assert hex_encode(msg) == _stdlib_hex(msg)
    assert hex_decode(_stdlib_hex(msg)) == msg
    assert b64_encode(msg) == _stdlib_b64(msg)
    assert b64_decode(_stdlib_b64(msg)) == msg
    assert _stdlib_unhex(_stdlib_hex(msg)) == msg
    assert _stdlib_unb64(_stdlib_b64(msg)) == msg


if __name__ == "__main__":
    main()
