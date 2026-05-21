import json
import random
import sys
from pathlib import Path


LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as spx  # noqa: E402


def hb(x: str) -> bytes:
    return bytes.fromhex(x)


def call(vector):
    op = vector["op"]
    inputs = vector["inputs"]

    if op == "prf":
        return spx.prf(hb(inputs["seed"]), inputs["label"].encode("utf-8")).hex()

    if op == "expand":
        return spx.expand(hb(inputs["seed"]), inputs["label"].encode("utf-8"), inputs["out_len"]).hex()

    if op == "base_w":
        return spx.base_w(hb(inputs["data"]), inputs["w"], inputs["out_len"])

    if op == "merkle_root":
        pub_seed = hb(inputs["pub_seed"])
        a = hb(inputs["a"])
        leaves = [hb(x) for x in inputs["leaves"]]
        return spx.merkle_root(leaves, pub_seed, a).hex()

    if op == "merkle_compute_root":
        pub_seed = hb(inputs["pub_seed"])
        a = hb(inputs["a"])
        leaf = hb(inputs["leaf"])
        leaf_index = inputs["leaf_index"]
        auth_path = [hb(x) for x in inputs["auth_path"]]
        return spx.merkle_compute_root(leaf, leaf_index, auth_path, pub_seed, a).hex()

    if op == "wots_verify":
        message_digest = hb(inputs["message_digest"])
        sig = [hb(x) for x in inputs["sig"]]
        pkc = hb(inputs["pk_compressed"])
        pub_seed = hb(inputs["pub_seed"])
        a = hb(inputs["a"])
        return spx.wots_verify(message_digest, sig, pkc, pub_seed, a)

    if op == "xmss_verify":
        message = hb(inputs["message"])
        sig = spx.XMSSSignature(
            leaf_index=inputs["sig"]["leaf_index"],
            wots_sig=[hb(x) for x in inputs["sig"]["wots_sig"]],
            auth_path=[hb(x) for x in inputs["sig"]["auth_path"]],
        )
        pk = spx.XMSSPublicKey(
            root=hb(inputs["pk"]["root"]),
            pub_seed=hb(inputs["pk"]["pub_seed"]),
            height=inputs["pk"]["height"],
        )
        a = hb(inputs["a"])
        return spx.xmss_verify(message, sig, pk, a)

    if op == "sphincs_verify":
        message = hb(inputs["message"])
        sig = spx.SPHINCSSignature(
            subtree_index=inputs["sig"]["subtree_index"],
            bottom_sig=spx.XMSSSignature(
                leaf_index=inputs["sig"]["bottom_sig"]["leaf_index"],
                wots_sig=[hb(x) for x in inputs["sig"]["bottom_sig"]["wots_sig"]],
                auth_path=[hb(x) for x in inputs["sig"]["bottom_sig"]["auth_path"]],
            ),
            top_sig=spx.XMSSSignature(
                leaf_index=inputs["sig"]["top_sig"]["leaf_index"],
                wots_sig=[hb(x) for x in inputs["sig"]["top_sig"]["wots_sig"]],
                auth_path=[hb(x) for x in inputs["sig"]["top_sig"]["auth_path"]],
            ),
        )
        pk = spx.SPHINCSPublicKey(
            root=hb(inputs["pk"]["root"]),
            pub_seed=hb(inputs["pk"]["pub_seed"]),
            top_height=inputs["pk"]["top_height"],
            bottom_height=inputs["pk"]["bottom_height"],
        )
        a = hb(inputs["a"])
        return spx.sphincs_verify(message, sig, pk, a)

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        if "expected_error" in vector:
            try:
                call(vector)
            except ValueError as error:
                assert str(error) == vector["expected_error"]
            else:
                raise AssertionError(f"{vector['op']} did not raise")
            continue

        assert call(vector) == vector["expected"]


def test_merkle_roundtrip_random():
    rng = random.Random(0)
    pub_seed = bytes.fromhex("00" * 16)
    a = b"t"
    for height in range(1, 6):
        leaves = [spx.h("LEAF", spx._u32(i), out_len=spx.N) for i in range(1 << height)]
        tree = spx.merkle_tree(leaves, pub_seed, a)
        root = tree[-1][0]
        for _ in range(10):
            idx = rng.randrange(0, len(leaves))
            path = spx.merkle_auth_path(tree, idx)
            assert spx.merkle_compute_root(leaves[idx], idx, path, pub_seed, a) == root


def test_wots_signature_tamper_fails():
    sk_seed = bytes.fromhex("01" * 16)
    pub_seed = bytes.fromhex("02" * 16)
    a = spx.addr(0, 0, 999) + b"x"
    digest = spx.h("MSG", b"m", out_len=spx.N)
    pkc = spx.wots_pk_compress(spx.wots_gen_pk(sk_seed, pub_seed, a), pub_seed, a)
    sig = spx.wots_sign(digest, sk_seed, pub_seed, a)
    assert spx.wots_verify(digest, sig, pkc, pub_seed, a)
    bad_digest = bytes([digest[0] ^ 1]) + digest[1:]
    assert not spx.wots_verify(bad_digest, sig, pkc, pub_seed, a)


def test_xmss_wrong_message_fails():
    sk_seed = bytes.fromhex("11" * 16)
    pub_seed = bytes.fromhex("22" * 16)
    a = b"x"
    height = 3
    pk = spx.xmss_keygen(sk_seed, pub_seed, height, a)
    sig = spx.xmss_sign(b"m", sk_seed, pub_seed, height, leaf_index=0, a=a)
    assert spx.xmss_verify(b"m", sig, pk, a)
    assert not spx.xmss_verify(b"m2", sig, pk, a)


def test_rejects_bad_inputs():
    try:
        spx.base_w(b"\x00", 3, 1)
    except ValueError as error:
        assert str(error) == "w must be a power of two"
    else:
        raise AssertionError("expected base_w to reject w=3")

    try:
        spx.wots_pk_from_sig(b"\x00" * spx.N, [], b"\x00" * spx.N, b"a")
    except ValueError as error:
        assert str(error) == "bad wots signature length"
    else:
        raise AssertionError("expected wots_pk_from_sig to reject length")

    try:
        spx.xmss_sign(b"m", b"\x00" * 16, b"\x00" * 16, height=2, leaf_index=4, a=b"a")
    except ValueError as error:
        assert str(error) == "leaf_index out of range"
    else:
        raise AssertionError("expected xmss_sign to reject leaf_index")


if __name__ == "__main__":
    test_vectors()
    test_merkle_roundtrip_random()
    test_wots_signature_tamper_fails()
    test_xmss_wrong_message_fails()
    test_rejects_bad_inputs()
    print("all tests pass")

