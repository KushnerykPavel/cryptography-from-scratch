# SQIsign — Compact Isogeny Signatures

> Commit to a curve, hash a challenge, respond with a path.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/16-pq-isogenies-and-migration/01-isogenies`, `phases/16-pq-isogenies-and-migration/02-sidh-broken`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** the “SQIsign shape”: a one-round identification protocol turned into a signature via Fiat–Shamir
- **Compute** a deterministic challenge from `(public key, commitment, message)` using a hash
- **Implement** a toy commit–challenge–response signature with “Fiat–Shamir with aborts”
- **Distinguish** SQIsign’s “sign by producing an isogeny” from SIDH’s “key exchange that leaked torsion structure”
- **Apply** this mental model to migration: what a verifier can check, what a signer must keep secret, and where side-channels show up

## The Problem

Post-quantum migration needs **signatures** as much as it needs **key exchange**. You’ll replace (or hybridize) RSA/ECDSA/Ed25519 signatures in things like software updates, device identities, certificate chains, and signed telemetry. If you can’t reason about *what a post-quantum signature is proving*, you can’t review integrations, measure risks, or spot “it verifies but it’s unsafe” traps.

SQIsign is an isogeny-based signature family that targets *very small signatures and keys*. That’s attractive in places where bandwidth or storage are tight (embedded, constrained protocols, long-lived cert chains). But the “how” is very different from classical signatures: instead of “prove knowledge of a discrete log”, you can think “prove you can produce an isogeny with a particular relationship to a challenge curve”.

This lesson gives you a runnable, end-to-end model of the SQIsign *protocol shape* — commitment, Fiat–Shamir challenge, and response — without requiring quaternion algebra or curve arithmetic. The goal is to make you fluent in the transcript mechanics and the migration pitfalls.

## The Concept

### The SQIsign mental model (protocol shape)

SQIsign can be understood at a high level as:

- Public key: a supersingular curve `E_A` (a node in a supersingular isogeny graph)
- Secret key: hidden structure that lets the signer efficiently find “short” isogenies from `E_A`
- Identification protocol:
  1) signer commits to an intermediate curve `E_1`
  2) verifier challenges with a curve `E_2` derived from `E_1`
  3) signer responds with evidence that links `E_A` to `E_2`
- Signature: make the verifier’s challenge deterministic:
  - `challenge = H(public_key, commitment, message)` (Fiat–Shamir)

### Why “with aborts” shows up

In many post-quantum signature designs, not every commitment leads to a “good” challenge. The signer may need to **retry** commitments until the derived challenge satisfies some property (e.g., response exists, response is short, response has a certain shape). This is called **Fiat–Shamir with aborts**.

In this lesson’s toy model:

- Curves are just integers (graph nodes).
- Isogenies are just “walk steps” along deterministic edges.
- The signer’s “trapdoor” is simulated by a **short-path search** (BFS) plus aborts:
  - keep retrying commitments until the challenge curve happens to be within a small radius of the public key in the toy graph.

This is not secure cryptography. It is a clean way to see the *transcript mechanics* you will need when reading SQIsign specs and reviewing integrations.

## Build It

### Step 1: A toy supersingular isogeny graph (deterministic neighbors)

We’ll model a supersingular isogeny graph as a function `neighbors(node) -> [node, node, node]` (a 3-regular graph). Real supersingular graphs are enormous and have special algebraic structure; our toy graph is just deterministic hashing.

```python
from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass


def _u64(x: int) -> int:
    return x & ((1 << 64) - 1)


def hash_to_u64(label: str, *parts: object) -> int:
    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    for p in parts:
        h.update(b"|")
        h.update(str(p).encode("utf-8"))
    return int.from_bytes(h.digest()[:8], "big")


def derive_indices(label: str, seed: str, count: int, degree: int) -> list[int]:
    if degree <= 0:
        raise ValueError("degree must be >= 1")
    if count < 0:
        raise ValueError("count must be >= 0")
    out: list[int] = []
    for i in range(count):
        out.append(int(hash_to_u64(label, seed, i) % degree))
    return out


@dataclass(frozen=True)
class ToyIsogenyGraph:
    modulus: int
    degree: int = 3
    salt: str = "sqisign-toy-v1"

    def __post_init__(self) -> None:
        if self.modulus <= 3:
            raise ValueError("modulus must be > 3")
        if self.degree < 1:
            raise ValueError("degree must be >= 1")

    def neighbors(self, node: int) -> list[int]:
        node %= self.modulus
        used = {node}
        out: list[int] = []
        for i in range(self.degree):
            ctr = 0
            while True:
                cand = int(hash_to_u64("edge", self.salt, node, i, ctr) % self.modulus)
                if cand not in used:
                    out.append(cand)
                    used.add(cand)
                    break
                ctr += 1
        return out
```

This gives us a stable, public “graph” everyone can compute from the same parameters.

### Step 2: Isogenies as walks (edge-index paths)

An isogeny chain becomes a short list of edge indices like `[2, 0, 1, ...]`. Given a start node, `walk()` applies those steps.

```python
def walk(graph: ToyIsogenyGraph, start: int, path_indices: list[int]) -> int:
    cur = int(start % graph.modulus)
    for idx in path_indices:
        if not (0 <= int(idx) < graph.degree):
            raise ValueError("path index out of range")
        cur = graph.neighbors(cur)[int(idx)]
    return cur
```

This is the core “curve -> curve” computation in our model.

### Step 3: Fiat–Shamir challenge as a deterministic walk

We’ll derive a challenge from `(pk, commitment, message)` by hashing and turning the hash stream into edge indices. The verifier can recompute the same challenge.

```python
def challenge_path_from_transcript(
    graph: ToyIsogenyGraph,
    pk_node: int,
    com_node: int,
    message: str,
    challenge_len: int,
) -> list[int]:
    if challenge_len < 0:
        raise ValueError("challenge_len must be >= 0")
    seed = f"pk={pk_node}|com={com_node}|msg={message}"
    return derive_indices("challenge", seed, challenge_len, graph.degree)
```

This matches the “Fiat–Shamir transform” idea: the verifier’s challenge is replaced by `H(transcript)`.

### Step 4: Sign and verify (Fiat–Shamir with aborts)

Keygen makes a public key by walking from a fixed base curve `E0` using a secret path.

Signing:

1) choose a commitment by walking from `E0`
2) derive the challenge from `(pk, commitment, message)` and walk it to get `E2`
3) respond with a short path from `pk` to `E2` (we simulate the trapdoor by BFS)
4) if no short response exists, abort and try a new commitment

```python
def find_short_path_bfs(
    graph: ToyIsogenyGraph,
    start: int,
    target: int,
    max_depth: int,
) -> list[int] | None:
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    start %= graph.modulus
    target %= graph.modulus
    if start == target:
        return []

    q: deque[int] = deque([start])
    parent: dict[int, tuple[int, int]] = {}  # node -> (prev_node, edge_index)
    depth: dict[int, int] = {start: 0}

    while q:
        node = q.popleft()
        d = depth[node]
        if d >= max_depth:
            continue

        nbrs = graph.neighbors(node)
        for edge_idx, nxt in enumerate(nbrs):
            if nxt in depth:
                continue
            parent[nxt] = (node, edge_idx)
            depth[nxt] = d + 1
            if nxt == target:
                q.clear()
                break
            q.append(nxt)

    if target not in parent:
        return None

    path_rev: list[int] = []
    cur = target
    while cur != start:
        prev, edge_idx = parent[cur]
        path_rev.append(edge_idx)
        cur = prev
    return list(reversed(path_rev))


def toy_sqisign_keygen(
    graph: ToyIsogenyGraph,
    base_node: int,
    secret_seed: str,
    secret_len: int,
) -> tuple[list[int], int]:
    sk_path = derive_indices("sk", secret_seed, secret_len, graph.degree)
    pk_node = walk(graph, base_node, sk_path)
    return sk_path, pk_node


def toy_sqisign_sign(
    graph: ToyIsogenyGraph,
    base_node: int,
    pk_node: int,
    secret_seed: str,
    message: str,
    commitment_len: int,
    challenge_len: int,
    response_max_depth: int,
    max_tries: int,
) -> dict:
    if max_tries <= 0:
        raise ValueError("max_tries must be >= 1")

    for attempt in range(max_tries):
        commit_seed = f"sk={secret_seed}|msg={message}|attempt={attempt}"
        com_path = derive_indices("commit", commit_seed, commitment_len, graph.degree)
        com_node = walk(graph, base_node, com_path)

        chl_path = challenge_path_from_transcript(graph, pk_node, com_node, message, challenge_len)
        chl_node = walk(graph, com_node, chl_path)

        resp_path = find_short_path_bfs(graph, pk_node, chl_node, response_max_depth)
        if resp_path is None:
            continue

        return {
            "com": int(com_node),
            "resp": [int(x) for x in resp_path],
            "tries": int(attempt + 1),
        }

    raise ValueError("signing failed: no solvable challenge found within max_tries")


def toy_sqisign_verify(
    graph: ToyIsogenyGraph,
    pk_node: int,
    message: str,
    signature: dict,
    challenge_len: int,
    response_max_depth: int,
) -> bool:
    if not isinstance(signature, dict):
        return False
    if "com" not in signature or "resp" not in signature:
        return False
    if not isinstance(signature["com"], int):
        return False
    if not isinstance(signature["resp"], list):
        return False
    if len(signature["resp"]) > response_max_depth:
        return False
    if any((not isinstance(x, int)) or x < 0 or x >= graph.degree for x in signature["resp"]):
        return False

    com_node = int(signature["com"])
    chl_path = challenge_path_from_transcript(graph, pk_node, com_node, message, challenge_len)
    chl_node = walk(graph, com_node, chl_path)
    got = walk(graph, pk_node, [int(x) for x in signature["resp"]])
    return got == chl_node


def encode_signature(signature: dict) -> str:
    com = int(signature["com"])
    resp = [int(x) for x in signature["resp"]]
    return f"com:{com};resp:" + ",".join(str(x) for x in resp)


def decode_signature(s: str) -> dict:
    if not isinstance(s, str):
        raise TypeError("signature must be a string")
    parts = s.split(";")
    if len(parts) != 2:
        raise ValueError("bad signature encoding")
    if not parts[0].startswith("com:"):
        raise ValueError("bad signature encoding (com)")
    if not parts[1].startswith("resp:"):
        raise ValueError("bad signature encoding (resp)")
    com = int(parts[0][len("com:") :])
    resp_txt = parts[1][len("resp:") :]
    resp = [] if resp_txt == "" else [int(x) for x in resp_txt.split(",")]
    return {"com": com, "resp": resp}
```

Run it:

```bash
python3 code/main.py
```

## Use It

When you’re ready to move beyond the toy model:

- **Official SQIsign code and ongoing development**: the SQIsign project’s repositories (reference implementation and variants).
- **Specification PDFs**: SQIsign algorithm specification and supporting documentation.
- **Portability baselines**: PQClean historically served as a “clean, portable C” baseline for PQC schemes (but check its maintenance status before depending on it).

In production you should only use well-reviewed, constant-time implementations from an actively maintained project.

## Pitfalls

- **Hash domain separation mistakes**: if the challenge hash doesn’t bind `message`, `public key`, and `commitment`, you can get signature replay, cross-protocol attacks, or “valid signature for the wrong context”.
- **Nonce/commitment reuse**: in Fiat–Shamir signatures, reusing randomness across messages can leak secret structure (or enable forgery). Treat commitment generation like nonce generation in Schnorr/ECDSA: unique per message.
- **Abort timing as a side-channel**: “with aborts” means signing may loop; the number of retries can leak information unless you design for constant-time/constant-distribution behavior.
- **Non-canonical encoding**: if two different byte strings decode to the same signature object, verification code can become malleable or inconsistent across implementations.
- **Parameter mismatch in migration**: “it verifies” is not enough. Make sure the algorithm id, parameter level, and hash choices are consistent across your whole stack.

## Ship It

Save this lesson’s reusable review checklist and use it when you:

- review a PR that adds a PQ signature scheme,
- audit signing/verification code paths,
- write an integration test plan for migration.

Artifact: `outputs/sqisign-integration-review-checklist.md`

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that verification succeeds for the right message and fails for the wrong message.
2. Medium. In `code/main.py`, change `response_max_depth` and `max_tries`. Measure how `tries` changes and how often signing fails.
3. Hard. Read the SQIsign specification and map the toy transcript `(commitment, challenge, response)` to the real objects (curves, ideals/isogenies). Write a short “what to log, what not to log” checklist for a production signer.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Supersingular isogeny graph | “A graph of curves” | A huge structured graph where nodes are supersingular elliptic curves (up to isomorphism) and edges are small-degree isogenies. |
| Isogeny (in this lesson) | “A step” | A single edge in the toy graph; a chain of isogenies is a path. |
| Commitment | “First message” | The signer’s first transcript element; it must be unpredictable and bound into the hash challenge. |
| Fiat–Shamir transform | “Replace verifier with a hash” | Make the verifier’s challenge deterministic as `H(transcript, message)`. |
| Fiat–Shamir with aborts | “Retry until it works” | The signer repeats commitment generation until the derived challenge has a “good” property. |
| Response | “Proof” | Data that lets the verifier check the signer can link the public key curve to the challenge curve. |
| Endomorphism ring (intuition) | “Secret structure” | Extra algebraic knowledge about `E_A` that makes it feasible to compute the response isogeny. |

## Further Reading

- De Feo, Kohel, Leroux, Petit, Wesolowski, “SQISign: compact post-quantum signatures from quaternions and isogenies” (2020) — the original design and security intuition.
- SQIsign project site + specification (latest spec version) — the parameter sets, encoding rules, and implementation notes.
- “New algorithms for the Deuring correspondence: Towards practical and secure SQIsign signatures” (EUROCRYPT 2023) — algorithmic improvements that make real-world SQIsign more practical.
