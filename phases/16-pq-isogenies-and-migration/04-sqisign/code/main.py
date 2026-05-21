"""
Toy SQIsign-style signatures (commit-challenge-response on an isogeny graph).

This lesson is a *model* of the SQIsign shape:
  - Public key: a "curve" E_A (a node in a supersingular isogeny graph).
  - Signing: commit to E_1, derive a challenge isogeny E_1 -> E_2 from a hash,
    and respond with an isogeny E_A -> E_2.

In real SQIsign, producing the response efficiently relies on secret structure
(knowledge related to End(E_A)). Here we simulate that "trapdoor" by searching
for a short path (BFS) and using Fiat–Shamir-with-aborts (retrying commitments
until the challenge is solvable with a short response).

Run:
    python3 code/main.py
"""

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


def walk(graph: ToyIsogenyGraph, start: int, path_indices: list[int]) -> int:
    cur = int(start % graph.modulus)
    for idx in path_indices:
        if not (0 <= int(idx) < graph.degree):
            raise ValueError("path index out of range")
        cur = graph.neighbors(cur)[int(idx)]
    return cur


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


def main() -> None:
    graph = ToyIsogenyGraph(modulus=1_000_003, degree=3, salt="sqisign-demo")
    base_node = 100

    print("=== Step 1: A toy supersingular isogeny graph ===")
    print(f"modulus={graph.modulus} degree={graph.degree} base(E0)={base_node}")
    print(f"neighbors(E0)={graph.neighbors(base_node)}\n")

    print("=== Step 2: Keys are hidden walks from a fixed base curve ===")
    secret_seed = "demo-secret-seed"
    sk_path, pk_node = toy_sqisign_keygen(graph, base_node, secret_seed, secret_len=10)
    print(f"secret walk (length {len(sk_path)}) = {sk_path}")
    print(f"public key curve E_A (node id)    = {pk_node}\n")

    print("=== Step 3: Fiat–Shamir challenge from (pk, commitment, message) ===")
    message = "sign me"
    com_demo = walk(graph, base_node, derive_indices("commit", "demo", 6, graph.degree))
    chl_path = challenge_path_from_transcript(graph, pk_node, com_demo, message, challenge_len=5)
    chl_node = walk(graph, com_demo, chl_path)
    print(f"commitment curve E_1 = {com_demo}")
    print(f"challenge walk E_1->E_2 (len {len(chl_path)}) = {chl_path}")
    print(f"challenge curve E_2 = {chl_node}\n")

    print("=== Step 4: Sign = retry commitments until a short response exists ===")
    sig = toy_sqisign_sign(
        graph,
        base_node=base_node,
        pk_node=pk_node,
        secret_seed=secret_seed,
        message=message,
        commitment_len=6,
        challenge_len=5,
        response_max_depth=7,
        max_tries=500,
    )
    encoded = encode_signature(sig)
    print(f"signature (dict)  = {sig}")
    print(f"signature (text)  = {encoded}")

    ok = toy_sqisign_verify(
        graph,
        pk_node=pk_node,
        message=message,
        signature=sig,
        challenge_len=5,
        response_max_depth=7,
    )
    ok2 = toy_sqisign_verify(
        graph,
        pk_node=pk_node,
        message=message + "!",
        signature=sig,
        challenge_len=5,
        response_max_depth=7,
    )
    print(f"verify(message)   = {ok}")
    print(f"verify(wrong msg) = {ok2}")


if __name__ == "__main__":
    main()
