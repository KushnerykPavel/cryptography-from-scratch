import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

from main import (  # noqa: E402
    ToyIsogenyGraph,
    challenge_path_from_transcript,
    decode_signature,
    derive_indices,
    encode_signature,
    find_short_path_bfs,
    toy_sqisign_keygen,
    toy_sqisign_sign,
    toy_sqisign_verify,
    walk,
)


def _load_vectors():
    path = os.path.join(HERE, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _graph(g):
    return ToyIsogenyGraph(modulus=int(g["modulus"]), degree=int(g["degree"]), salt=str(g["salt"]))


def test_vectors():
    data = _load_vectors()
    for vec in data["vectors"]:
        op = vec["op"]

        if op == "derive_indices":
            got = derive_indices(vec["label"], vec["seed"], int(vec["count"]), int(vec["degree"]))
            assert got == vec["expected"]
            continue

        if op == "neighbors":
            graph = _graph(vec["graph"])
            got = graph.neighbors(int(vec["node"]))
            assert got == vec["expected"]
            continue

        if op == "walk":
            graph = _graph(vec["graph"])
            got = walk(graph, int(vec["start"]), [int(x) for x in vec["path"]])
            assert got == int(vec["expected"])
            continue

        if op == "challenge_path":
            graph = _graph(vec["graph"])
            got_path = challenge_path_from_transcript(
                graph,
                pk_node=int(vec["pk"]),
                com_node=int(vec["com"]),
                message=str(vec["message"]),
                challenge_len=int(vec["challenge_len"]),
            )
            got_node = walk(graph, int(vec["com"]), got_path)
            assert got_path == vec["expected"]["path"]
            assert got_node == int(vec["expected"]["node"])
            continue

        if op == "find_short_path_bfs":
            graph = _graph(vec["graph"])
            got = find_short_path_bfs(
                graph,
                start=int(vec["start"]),
                target=int(vec["target"]),
                max_depth=int(vec["max_depth"]),
            )
            assert got == vec["expected"]
            continue

        if op == "sign_verify":
            graph = _graph(vec["graph"])
            sk_path, pk_node = toy_sqisign_keygen(
                graph,
                base_node=int(vec["base"]),
                secret_seed=str(vec["secret_seed"]),
                secret_len=int(vec["secret_len"]),
            )
            assert sk_path == derive_indices("sk", str(vec["secret_seed"]), int(vec["secret_len"]), graph.degree)
            assert pk_node == int(vec["expected"]["pk"])

            sig = toy_sqisign_sign(
                graph,
                base_node=int(vec["base"]),
                pk_node=pk_node,
                secret_seed=str(vec["secret_seed"]),
                message=str(vec["message"]),
                commitment_len=int(vec["commitment_len"]),
                challenge_len=int(vec["challenge_len"]),
                response_max_depth=int(vec["response_max_depth"]),
                max_tries=int(vec["max_tries"]),
            )
            assert sig == vec["expected"]["signature"]

            ok = toy_sqisign_verify(
                graph,
                pk_node=pk_node,
                message=str(vec["message"]),
                signature=sig,
                challenge_len=int(vec["challenge_len"]),
                response_max_depth=int(vec["response_max_depth"]),
            )
            assert ok is True

            encoded = encode_signature(sig)
            assert encoded == vec["expected"]["encoded"]
            assert decode_signature(encoded) == {"com": sig["com"], "resp": sig["resp"]}
            continue

        raise ValueError(f"unknown op: {op}")


def test_walk_composition():
    graph = ToyIsogenyGraph(modulus=1_000_003, degree=3, salt="sqisign-demo")
    a = [0, 1, 2, 0]
    b = [2, 2, 1]
    start = 123
    left = walk(graph, start, a + b)
    mid = walk(graph, start, a)
    right = walk(graph, mid, b)
    assert left == right


def test_find_short_path_bfs_depth_cutoff():
    graph = ToyIsogenyGraph(modulus=1_000_003, degree=3, salt="sqisign-demo")
    start = 645893
    target = 668008
    assert find_short_path_bfs(graph, start, target, max_depth=6) is None
    assert find_short_path_bfs(graph, start, target, max_depth=7) == [1, 1, 2, 0, 2, 2, 1]


def test_verify_rejects_tampering():
    graph = ToyIsogenyGraph(modulus=1_000_003, degree=3, salt="sqisign-demo")
    _sk, pk = toy_sqisign_keygen(graph, base_node=100, secret_seed="demo-secret-seed", secret_len=10)
    sig = {"com": 543591, "resp": [1, 1, 2, 0, 2, 2, 1], "tries": 111}

    assert toy_sqisign_verify(graph, pk, "sign me", sig, challenge_len=5, response_max_depth=7) is True
    assert toy_sqisign_verify(graph, pk, "sign me!", sig, challenge_len=5, response_max_depth=7) is False

    sig2 = {"com": sig["com"], "resp": sig["resp"][:-1]}
    assert toy_sqisign_verify(graph, pk, "sign me", sig2, challenge_len=5, response_max_depth=7) is False

    sig3 = {"com": sig["com"], "resp": [9]}  # out-of-range edge index
    assert toy_sqisign_verify(graph, pk, "sign me", sig3, challenge_len=5, response_max_depth=7) is False


def test_decode_signature_rejects_invalid():
    try:
        decode_signature("nope")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"{name}: FAIL ({type(e).__name__}: {e})")
    if failures == 0:
        print("all tests pass")
        raise SystemExit(0)
    raise SystemExit(1)

