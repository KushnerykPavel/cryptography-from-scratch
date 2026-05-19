# Mix Networks — Batching, Shuffling, Delaying
> Hide who talks to whom by encrypting *content* and mixing *metadata* in batches.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 7 · 02 (Stream Ciphers), Phase 7 · 12 (HMAC), Phase 7 · 13 (KDFs), Phase 10 · 09 (Tor & Onion Routing)
**Time:** ~50 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** what a mix network protects (and what it doesn’t)
- **Distinguish** onion routing from mix networks at the metadata level
- **Implement** a toy onion packet with per-hop authentication
- **Apply** batching + shuffling to break input↔output linkage
- **Compute** how padding and batch size affect anonymity and leakage

## The Problem

Encryption hides *content*, but most real-world leaks are about *metadata*: who is talking to whom, when, and how often. If an observer can correlate “Alice sent a packet at 12:00:01” with “Bob received a packet at 12:00:01”, the message body can be perfectly encrypted and privacy still fails.

Onion routing (Tor) addresses this by relaying traffic through multiple hops. But low-latency routing still leaks timing structure: with enough observation, you can often correlate flows by packet sizes, timing, and volume.

Mix networks attack the correlation problem directly: they accept messages in *batches*, remove one encryption layer per hop, then *shuffle (permute) the batch* and optionally add *delays* and *cover traffic*. The goal is to make “which output corresponds to which input?” computationally and statistically hard.

## The Concept

Think in terms of *anonymity sets*:

- With 1 message in a batch, there is no anonymity: the output is obviously linked to the input.
- With `B` messages in a batch, a passive observer faces up to `B!` possible input↔output matchings after one shuffle (before accounting for side-channels like timing and size).

A minimal mix network looks like this:

```
senders -> [ Mix 1 ] -> [ Mix 2 ] -> [ Mix 3 ] -> recipients
             peel        peel        peel
             shuffle     shuffle     shuffle
```

Each sender wraps their message in *layers* so that Mix 1 can peel only the outermost layer, Mix 2 peels the next, and so on (an “onion packet”). After peeling, a mix node forwards the inner packets in a permuted order.

Two practical rules dominate real deployments:

1. **Fixed-size packets.** If packet lengths differ, you leak information even if you shuffle.
2. **Large, regular batches.** Tiny or irregular batches make timing correlation easy.

## Build It

### Step 1: toy authenticated encryption (stream XOR + HMAC)
```python
NONCE_LEN = 16
TAG_LEN = 32  # HMAC-SHA256


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def kdf_stream(key: bytes, nonce: bytes, nbytes: int) -> bytes:
    if nbytes < 0:
        raise ValueError("kdf_stream: nbytes must be non-negative")
    out = b""
    counter = 0
    while len(out) < nbytes:
        out += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:nbytes]


def encrypt_then_mac(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise ValueError("encrypt_then_mac: bad nonce length")
    stream = kdf_stream(key, nonce, len(plaintext))
    ciphertext = xor_bytes(plaintext, stream)
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def decrypt_then_verify(key: bytes, packet: bytes) -> bytes:
    if len(packet) < NONCE_LEN + TAG_LEN:
        raise ValueError("decrypt_then_verify: packet too short")
    nonce = packet[:NONCE_LEN]
    tag = packet[-TAG_LEN:]
    ciphertext = packet[NONCE_LEN:-TAG_LEN]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("decrypt_then_verify: authentication failed")
    stream = kdf_stream(key, nonce, len(ciphertext))
    return xor_bytes(ciphertext, stream)
```

This is a tiny “AEAD-like” construction for the lesson: encrypt by XOR’ing with a SHA-256-derived keystream, then authenticate `(nonce || ciphertext)` with HMAC-SHA256. Every mix hop needs *integrity* checks, or an attacker can inject and tamper with packets to deanonymize users.

### Step 2: fixed-size cells (pad to constant length)
```python
CELL_LEN = 64  # fixed-size payload to avoid trivial length leakage in the demo


def pack_cell(text: str, *, cell_len: int = CELL_LEN) -> bytes:
    raw = text.encode("utf-8")
    if cell_len < 2:
        raise ValueError("pack_cell: cell_len must be >= 2")
    if len(raw) > cell_len - 2:
        raise ValueError("pack_cell: message too long for cell")
    return struct.pack(">H", len(raw)) + raw + b"\x00" * (cell_len - 2 - len(raw))


def unpack_cell(cell: bytes) -> str:
    if len(cell) < 2:
        raise ValueError("unpack_cell: cell too short")
    (n,) = struct.unpack(">H", cell[:2])
    if n > len(cell) - 2:
        raise ValueError("unpack_cell: invalid length prefix")
    return cell[2 : 2 + n].decode("utf-8")
```

Real mixnets try hard to make packets indistinguishable. In this toy model we pack a UTF-8 message into a constant-size “cell”: a 2-byte length prefix plus zero padding. Without fixed sizes, an observer can often match inputs and outputs by length alone—even if you shuffle perfectly.

### Step 3: onion-wrap a cell for 3 mix hops
```python
def onion_encrypt(plaintext: bytes, keys: Sequence[bytes], nonces: Sequence[bytes]) -> bytes:
    if len(keys) != len(nonces):
        raise ValueError("onion_encrypt: keys/nonces length mismatch")
    packet = plaintext
    for key, nonce in reversed(list(zip(keys, nonces))):
        packet = encrypt_then_mac(key, nonce, packet)
    return packet


def peel_one_layer(packet: bytes, key: bytes) -> bytes:
    return decrypt_then_verify(key, packet)
```

Each sender wraps the message in layers so that hop 1 removes only the outer layer, revealing the packet intended for hop 2, and so on. The critical idea: no single mix node sees both the *sender* and the *final plaintext* (unless it colludes with others).

### Step 4: mix rounds (peel + shuffle batches)
```python
def apply_permutation(items: Sequence[bytes], permutation: Sequence[int]) -> List[bytes]:
    n = len(items)
    if len(permutation) != n:
        raise ValueError("apply_permutation: wrong permutation length")
    if sorted(permutation) != list(range(n)):
        raise ValueError("apply_permutation: not a permutation")
    return [items[i] for i in permutation]


def mix_round(packets: Sequence[bytes], hop_key: bytes, permutation: Sequence[int]) -> List[bytes]:
    peeled = [peel_one_layer(p, hop_key) for p in packets]
    return apply_permutation(peeled, permutation)
```

A single hop of a mix network does two things: (1) peel one layer (integrity-checked), and (2) shuffle the batch. Repeating this across several hops makes correlation harder because an observer must now reason about multiple unknown permutations, delays, and the fact that packets stay encrypted until the last hop.

Run it:
`python3 code/main.py`

## Use It

Real mix networks use public-key onion packets and carefully engineered replay protection, padding, and timing strategies. Examples to recognize:

- **Sphinx packets** (packet format) — widely used onion packet construction for mixnets.
- **Mixminion** — classic “Type III” anonymous remailer design with Sphinx-like ideas.
- **Loopix / Katzenpost / Nym** — modern mixnets that add cover traffic and delay strategies to resist traffic analysis.

Decision rule: if you need **low latency**, you tend to use onion routing (Tor-like). If you can tolerate **higher latency**, mixnets can offer stronger resistance to global passive observers by destroying timing structure with batching and delays.

## Pitfalls

- **Tiny batches.** A batch of size 2 gives at most 2 possibilities; timing correlation can still win easily.
- **Variable packet sizes.** If sizes differ, many packets are linkable without any crypto breaks.
- **No replay/dup detection.** Attackers can resend packets to learn how mixes behave and shrink the anonymity set.
- **Deterministic routing/epochs.** If you always flush at fixed times with small volumes, you leak timing fingerprints.
- **Assuming “encrypted = private”.** Mixnets protect against *some* observers under a threat model; they do not magically erase all metadata.

## Ship It

Save the reusable checklist at `outputs/prompt-mixnet-review-checklist.md`. Use it when reviewing an anonymity network design or PR: paste it into a code review, ask it against a spec, or use it to drive a threat-modeling session.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe how the packet fingerprints change after each hop and how the final order differs from the input order.
2. **Medium.** Change the batch size in Step 4 (try 2, 5, 20). How does your intuition about “hard to link inputs to outputs” change as `B` grows?
3. **Hard.** Extend `code/main.py` to add a per-hop random *delay bucket* (e.g., each packet is delayed by 0–2 rounds before forwarding). What does this do to a timing-correlation attacker in your mental model?

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Mix node | “An anonymity relay” | A server that peels a layer, shuffles a batch, and forwards packets |
| Batch | “A set of messages processed together” | The unit that determines the anonymity set size and timing leakage |
| Anonymity set | “How many people could it be?” | The number of plausible senders/receivers consistent with what the observer sees |
| Cover traffic | “Fake packets” | Additional traffic to hide real traffic patterns and volumes |
| Packet padding | “Make everything the same size” | Prevent trivial linkability via length/shape side-channels |
| Global passive observer | “The worst-case network watcher” | An attacker who can observe traffic entering and leaving the network at scale |

## Further Reading

- David Chaum, *Untraceable Electronic Mail, Return Addresses, and Digital Pseudonyms* (1981) — the original mixnet idea.
- George Danezis, *Mix-Networks with Restricted Routes* (2003) — design space and trade-offs for routing and mixing.
- Ian Goldberg, George Danezis, Roger Dingledine, *Sphinx: A Compact and Provably Secure Mix Format* (2009) — a standard onion packet format for mixnets.
- Ania Piotrowska et al., *The Loopix Anonymity System* (2017) — mixnets + cover traffic + delays for stronger traffic analysis resistance.
