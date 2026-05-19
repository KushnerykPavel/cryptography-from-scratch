# Tor & Onion Routing
> Each relay peels one layer; no relay sees the whole path.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 07 · 09 (SHA-256), Phase 07 · 12 (HMAC), Phase 07 · 07 (AEAD), Phase 10 · 03 (Noise handshake wiring)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what onion routing hides (and what it does not).
- Compute what each relay can learn from an onion packet in a 3-hop route.
- Implement a toy onion packet with layered encrypt-then-MAC protection (stdlib only).
- Distinguish “layered encryption for routing privacy” from “end-to-end encryption for content privacy.”
- Apply a review checklist to spot onion-routing footguns (integrity, replay, padding, correlation).

## The Problem

You want a client to reach a destination without revealing the destination to every network observer on the way. With normal routing, intermediate networks and servers can often see where you connect, when you connect, and how much data you send. Even if the payload is encrypted (HTTPS), the *metadata* can still be sensitive: which site you visited, which service you used, or which endpoint you are talking to.

“Just use a VPN” concentrates trust: the VPN provider sees both who you are and where you go. Onion routing tries to split that knowledge so no single relay learns the whole story. The price is complexity: key setup, layered encryption, replay resistance, padding policies, and careful handling of errors so you don’t leak information.

This lesson gives you a runnable mental model: a 3-hop circuit and a toy onion packet where each hop can decrypt only its own layer to learn the next hop and forward the remaining onion.

## The Concept

Think of a route as a chain of relays:

```
client -> guard -> middle -> exit -> destination
```

Onion routing’s core invariant is **local knowledge**:

| Party | What it should learn | What it should not learn |
|------|-----------------------|---------------------------|
| guard | client IP, next hop | destination, full path |
| middle | previous hop, next hop | client IP, destination |
| exit | previous hop, destination | client IP (directly) |

Layered encryption is how you get that behavior. The client builds an onion packet by wrapping the payload multiple times:

```
layer for guard  = Enc_k_guard( next=middle, inner = Enc_k_middle( next=exit, inner = Enc_k_exit( exit_payload )))
```

When the guard decrypts, it learns only `(next=middle, inner=...)`. The inner bytes are still ciphertext to the guard. The middle peels its layer, and so on, until the exit reaches the final “deliver this to destination” payload.

Two practical details matter:

1. **Integrity:** encryption alone is not enough. Relays must reject modified packets, or attackers can flip bits to change routing fields.
2. **Replay & correlation:** even if a relay can’t decrypt content, packet *shape* and *timing* can correlate sender/receiver unless you design padding, batching, and error behavior carefully.

## Build It

### Step 1: Toy AEAD (XOR stream + HMAC tag)

```python
from __future__ import annotations

import hashlib
import hmac

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
```

This gives you an “encrypt + authenticate” box you can use for onion layers. Real Tor uses audited primitives (stream ciphers and message authentication integrated into its cell protocol); we use a toy AEAD so you can see the dataflow without external dependencies.

### Step 2: Deterministic payload encoding

```python
import json
from typing import Any


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
```

Onion routing is routing logic plus cryptography. These encoders make “what the hop should learn after decrypting” explicit: a relay learns a `next_hop` string and a blob of still-encrypted `inner_packet` bytes.

### Step 3: Build an onion packet (layered encryption)

```python
from dataclasses import dataclass
from typing import Sequence


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
```

The build loop runs “inside out”: start with the exit payload, then wrap it with the exit’s layer, then the middle’s, then the guard’s. The result is one blob of bytes where only the guard can peel the first layer, only the middle can peel the second, and so on.

### Step 4: Relay peeling and forwarding

```python
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
```

`peel_one_layer` is the whole onion-routing mechanic: decrypt one layer, learn the next hop, and forward the remaining bytes. `simulate_route` just runs that logic for a fixed route so you can see what each hop learns.

Run it:
python3 code/main.py

## Use It

In production you don’t “import onion routing” as a library; you run a network with careful protocol design. Places to look:

- **Tor (C)**: the reference implementation and protocol specs (cell format, circuit building, relay commands).
- **Arti (Rust)**: Tor’s newer Rust implementation; a good codebase to read for modern engineering practices.
- **Stem (Python)**: a controller library to interact with a Tor client (build circuits, query status); it’s not the onion crypto itself, but it’s how applications talk to Tor.

When you see onion routing in the wild, it almost always comes with:

- a key-establishment protocol (to set up per-hop keys),
- replay handling and flow control, and
- traffic-analysis defenses (padding / batching / circuit rotation policies).

## Pitfalls

1. **Encrypt without integrity:** if you don’t authenticate each layer, an attacker can flip bits to change `next_hop` or corrupt the inner packet in ways that leak information.
2. **Nonce reuse:** stream ciphers (and many AEADs) break catastrophically if you reuse `(key, nonce)` across different messages.
3. **Leaky errors:** different error messages (or different timing) for “bad tag” vs “bad parse” can become a decryption oracle.
4. **Size & timing correlation:** even with perfect crypto, matching packet sizes and timestamps across hops can deanonymize users without padding and batching.
5. **Overclaiming privacy:** onion routing hides routing metadata from *individual relays*; it does not magically defeat a global passive adversary observing enough of the network.

## Ship It

Save the checklist in `outputs/prompt-onion-routing-review.md` and reuse it when you:

- review PRs that claim “we implemented onion routing / multi-hop proxying,”
- design a multi-relay privacy system (mixnets, VPN chaining, message relays), or
- audit a protocol that uses layered encryption for routing metadata.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that each hop prints only a `next_hop` and an opaque byte length, while the exit prints the destination and message.
2. Medium. Extend the demo to a 4-hop route and verify that the first hop still cannot decode the exit payload (it should only ever see the next hop).
3. Hard. Replace the toy AEAD with a real AEAD in a production setting (e.g., ChaCha20-Poly1305) and write down the nonce/key schedule you would enforce to make reuse impossible.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Onion routing | “Traffic is encrypted many times” | A design where each hop can remove exactly one layer to learn only the next hop. |
| Circuit | “A tunnel” | A fixed sequence of relays with per-hop keys; multiple streams can be multiplexed over it. |
| Guard relay | “First hop” | The entry relay chosen for longer periods to reduce exposure to malicious first hops. |
| Exit relay | “The node that decrypts everything” | The last hop that connects to the destination; it can see plaintext unless the application layer encrypts it. |
| Traffic analysis | “Breaking crypto” | Inferring who talks to whom from timing, volume, and patterns, even if payloads are encrypted. |

## Further Reading

- Roger Dingledine, Nick Mathewson, Paul Syverson, *Tor: The Second-Generation Onion Router* (2004) — the classic design paper and threat model.
- Michael G. Reed, Paul F. Syverson, David M. Goldschlag, *Anonymous Connections and Onion Routing* (1998/1999) — early onion routing design ideas.
- Tor Project, *Tor Protocol Specification (tor-spec.txt)* — the on-wire protocol details (cells, circuits, relay commands).
- George Danezis, Claudia Diaz, *A Survey of Anonymous Communication Channels* (2008) — broader context and attack/defense landscape.
