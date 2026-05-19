"""Toy Tor onion routing (educational, stdlib only).

This script builds and forwards a toy "onion packet" across a fixed route
(guard -> middle -> exit). Each relay can decrypt only its own layer to learn:

- the next hop to forward to, and
- the remaining onion packet bytes.

To keep the demo stdlib-only, we use a toy AEAD:
- encryption: XOR with an HMAC-SHA256 based keystream
- integrity: truncated HMAC tag (Encrypt-then-MAC)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Sequence


NONCE_LEN = 16
TAG_LEN = 16


def sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes-like")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hmac.new(bytes(key), bytes(data), hashlib.sha256).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if not isinstance(a, (bytes, bytearray, memoryview)):
        raise TypeError("a must be bytes-like")
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError("b must be bytes-like")
    aa = bytes(a)
    bb = bytes(b)
    if len(aa) != len(bb):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(aa, bb))


def prg_stream(*, key: bytes, nonce: bytes, length: int) -> bytes:
    if not isinstance(length, int):
        raise TypeError("length must be int")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 1_000_000:
        raise ValueError("length too large for demo")
    if not isinstance(nonce, (bytes, bytearray, memoryview)):
        raise TypeError("nonce must be bytes-like")
    nn = bytes(nonce)
    if len(nn) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")

    stream_key = hmac_sha256(key, b"toy-aead|stream-key")
    out = b""
    counter = 0
    while len(out) < length:
        block = hmac_sha256(stream_key, b"toy-aead|stream" + nn + counter.to_bytes(4, "big"))
        out += block
        counter += 1
    return out[:length]


def seal(*, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    if not isinstance(aad, (bytes, bytearray, memoryview)):
        raise TypeError("aad must be bytes-like")
    pt = bytes(plaintext)
    nn = bytes(nonce)
    if len(nn) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")

    ct = xor_bytes(pt, prg_stream(key=key, nonce=nn, length=len(pt)))
    mac_key = hmac_sha256(key, b"toy-aead|mac-key")
    tag = hmac_sha256(mac_key, b"toy-aead|tag" + nn + bytes(aad) + ct)[:TAG_LEN]
    return nn + tag + ct


def open_sealed(*, key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    if not isinstance(aad, (bytes, bytearray, memoryview)):
        raise TypeError("aad must be bytes-like")
    blob = bytes(data)
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError("sealed data too short")
    nn = blob[:NONCE_LEN]
    tag = blob[NONCE_LEN : NONCE_LEN + TAG_LEN]
    ct = blob[NONCE_LEN + TAG_LEN :]

    mac_key = hmac_sha256(key, b"toy-aead|mac-key")
    expected = hmac_sha256(mac_key, b"toy-aead|tag" + nn + bytes(aad) + ct)[:TAG_LEN]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("tag verification failed")

    return xor_bytes(ct, prg_stream(key=key, nonce=nn, length=len(ct)))


def dumps_canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def loads_json(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return json.loads(bytes(data).decode("utf-8"))


def encode_exit_payload(*, dest: str, message: bytes) -> bytes:
    if not isinstance(dest, str):
        raise TypeError("dest must be str")
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    obj = {"dest": dest, "kind": "exit", "message_hex": bytes(message).hex()}
    return dumps_canonical_json(obj)


def decode_exit_payload(payload: bytes) -> tuple[str, bytes]:
    obj = loads_json(payload)
    if not isinstance(obj, dict):
        raise ValueError("exit payload must be a JSON object")
    if obj.get("kind") != "exit":
        raise ValueError("not an exit payload")
    dest = obj.get("dest")
    msg_hex = obj.get("message_hex")
    if not isinstance(dest, str) or not isinstance(msg_hex, str):
        raise ValueError("invalid exit payload fields")
    try:
        msg = bytes.fromhex(msg_hex)
    except ValueError as e:
        raise ValueError("invalid message_hex") from e
    return dest, msg


def encode_relay_payload(*, next_hop: str, inner_packet: bytes) -> bytes:
    if not isinstance(next_hop, str):
        raise TypeError("next_hop must be str")
    if not isinstance(inner_packet, (bytes, bytearray, memoryview)):
        raise TypeError("inner_packet must be bytes-like")
    obj = {"inner_hex": bytes(inner_packet).hex(), "kind": "relay", "next_hop": next_hop}
    return dumps_canonical_json(obj)


def decode_relay_payload(payload: bytes) -> tuple[str, bytes]:
    obj = loads_json(payload)
    if not isinstance(obj, dict):
        raise ValueError("relay payload must be a JSON object")
    if obj.get("kind") != "relay":
        raise ValueError("not a relay payload")
    next_hop = obj.get("next_hop")
    inner_hex = obj.get("inner_hex")
    if not isinstance(next_hop, str) or not isinstance(inner_hex, str):
        raise ValueError("invalid relay payload fields")
    try:
        inner = bytes.fromhex(inner_hex)
    except ValueError as e:
        raise ValueError("invalid inner_hex") from e
    return next_hop, inner


def onion_aad(*, hop_name: str) -> bytes:
    if not isinstance(hop_name, str):
        raise TypeError("hop_name must be str")
    return b"toy-onion|hop:" + hop_name.encode("utf-8")


def nonce_for_layer(*, packet_seed: bytes, layer_index: int) -> bytes:
    if not isinstance(layer_index, int):
        raise TypeError("layer_index must be int")
    if layer_index < 0:
        raise ValueError("layer_index must be non-negative")
    if not isinstance(packet_seed, (bytes, bytearray, memoryview)):
        raise TypeError("packet_seed must be bytes-like")
    return sha256(b"toy-onion|nonce" + bytes(packet_seed) + layer_index.to_bytes(4, "big"))[:NONCE_LEN]


@dataclass(frozen=True)
class Hop:
    name: str
    key: bytes


def build_onion_packet(
    *,
    route: Sequence[Hop],
    dest: str,
    message: bytes,
    packet_seed: bytes,
) -> bytes:
    if not isinstance(route, Sequence):
        raise TypeError("route must be a sequence of Hop")
    if len(route) == 0:
        raise ValueError("route must be non-empty")
    if any(not isinstance(h, Hop) for h in route):
        raise TypeError("route must contain Hop elements")

    onion = encode_exit_payload(dest=dest, message=message)
    for i in range(len(route) - 1, -1, -1):
        hop = route[i]
        if not isinstance(hop.name, str) or hop.name == "":
            raise ValueError("hop.name must be non-empty str")
        if not isinstance(hop.key, (bytes, bytearray, memoryview)):
            raise TypeError("hop.key must be bytes-like")
        next_hop = route[i + 1].name if i + 1 < len(route) else "<exit>"
        payload = encode_relay_payload(next_hop=next_hop, inner_packet=onion)
        onion = seal(
            key=bytes(hop.key),
            nonce=nonce_for_layer(packet_seed=packet_seed, layer_index=i),
            plaintext=payload,
            aad=onion_aad(hop_name=hop.name),
        )
    return onion


def peel_one_layer(*, hop: Hop, onion_packet: bytes) -> tuple[str, bytes]:
    pt = open_sealed(key=hop.key, data=onion_packet, aad=onion_aad(hop_name=hop.name))
    return decode_relay_payload(pt)


def simulate_route(*, route: Sequence[Hop], onion_packet: bytes) -> tuple[str, bytes]:
    cur = onion_packet
    for hop in route:
        next_hop, cur = peel_one_layer(hop=hop, onion_packet=cur)
        print(f"{hop.name} learns next_hop={next_hop!r} and forwards {len(cur)} bytes")
    dest, msg = decode_exit_payload(cur)
    return dest, msg


def main() -> int:
    print("\n=== Step 1: Toy AEAD (XOR stream + HMAC tag) ===\n")
    demo_key = sha256(b"demo-key")
    demo_nonce = b"\x00" * NONCE_LEN
    pt = b"hello onion"
    aad = b"header"
    sealed = seal(key=demo_key, nonce=demo_nonce, plaintext=pt, aad=aad)
    opened = open_sealed(key=demo_key, data=sealed, aad=aad)
    print(f"plaintext  = {pt!r}")
    print(f"sealed_hex = {sealed.hex()}")
    print(f"opened     = {opened!r}")

    print("\n=== Step 2: Deterministic payload encoding ===\n")
    exit_payload = encode_exit_payload(dest="example.com:80", message=b"GET / HTTP/1.0\r\n\r\n")
    relay_payload = encode_relay_payload(next_hop="middle", inner_packet=b"\x01\x02\x03")
    print(f"exit_payload  = {exit_payload!r}")
    print(f"relay_payload = {relay_payload!r}")

    print("\n=== Step 3: Build an onion packet (layered encryption) ===\n")
    route = [
        Hop(name="guard", key=sha256(b"guard-key")),
        Hop(name="middle", key=sha256(b"middle-key")),
        Hop(name="exit", key=sha256(b"exit-key")),
    ]
    packet_seed = sha256(b"packet-seed")  # in real Tor, this would be per-packet randomness
    onion = build_onion_packet(
        route=route,
        dest="example.com:80",
        message=b"GET / HTTP/1.0\r\n\r\n",
        packet_seed=packet_seed,
    )
    print(f"route = {[h.name for h in route]}")
    print(f"onion_packet_len = {len(onion)} bytes")
    print(f"onion_packet_prefix_hex = {onion[:32].hex()}...")

    print("\n=== Step 4: Relay peeling and forwarding ===\n")
    dest, msg = simulate_route(route=route, onion_packet=onion)
    print(f"\nexit delivers to dest={dest!r} message={msg!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
