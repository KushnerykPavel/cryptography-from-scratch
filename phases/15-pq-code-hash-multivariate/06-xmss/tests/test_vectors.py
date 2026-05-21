import json
import os
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as xmss  # noqa: E402


def _unhex(x: str) -> bytes:
    return bytes.fromhex(x)


def _load_vectors() -> dict:
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vectors() -> None:
    doc = _load_vectors()
    vectors = doc["vectors"]

    for v in vectors:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "wots_params":
            log_w, len1, len2, length = xmss.wots_params(n=inputs["n"], w=inputs["w"])
            assert expected == {"log_w": log_w, "len1": len1, "len2": len2, "length": length}
        elif op == "base_w":
            got = xmss.base_w(_unhex(inputs["x"]), inputs["w"], inputs["out_len"])
            assert got == expected
        elif op == "wots_message_digits":
            got = xmss.wots_message_digits(_unhex(inputs["digest"]), n=inputs["n"], w=inputs["w"])
            assert got == expected
        elif op == "wots_chain":
            got = xmss.wots_chain(
                _unhex(inputs["x"]),
                inputs["start"],
                inputs["steps"],
                n=inputs["n"],
                w=inputs["w"],
                pub_seed=_unhex(inputs["pub_seed"]),
                leaf_idx=inputs["leaf_idx"],
                chain_idx=inputs["chain_idx"],
            )
            assert got.hex() == expected
        elif op == "wots_ltree_leaf":
            pk = xmss.wots_gen_pk(
                _unhex(inputs["sk_seed"]),
                _unhex(inputs["pub_seed"]),
                n=inputs["n"],
                w=inputs["w"],
                leaf_idx=inputs["leaf_idx"],
            )
            leaf = xmss.ltree(pk, _unhex(inputs["pub_seed"]), n=inputs["n"], leaf_idx=inputs["leaf_idx"])
            assert leaf.hex() == expected
        elif op == "xmss_root":
            levels = xmss.xmss_build_tree(
                _unhex(inputs["sk_seed"]),
                _unhex(inputs["pub_seed"]),
                n=inputs["n"],
                w=inputs["w"],
                height=inputs["height"],
            )
            assert levels[-1][0].hex() == expected
        elif op == "xmss_sign_bytes":
            sk, pk = xmss.xmss_keygen(
                _unhex(inputs["sk_seed"]),
                _unhex(inputs["sk_prf"]),
                _unhex(inputs["pub_seed"]),
                n=inputs["n"],
                w=inputs["w"],
                height=inputs["height"],
            )
            msg = inputs["message"].encode("utf-8")
            sig = xmss.xmss_sign(sk, msg)
            sig_bytes = xmss.xmss_sig_to_bytes(sig, n=inputs["n"])

            assert sig.idx == expected["idx"]
            assert pk.root.hex() == expected["root"]
            assert sig_bytes.hex() == expected["signature"]
            assert xmss.xmss_verify(pk, msg, sig) is expected["verify"]
        else:
            raise AssertionError(f"unknown op: {op}")


def test_wots_chain_composition() -> None:
    n = 16
    w = 16
    pub_seed = xmss.hash_n(b"seed", n)
    x = xmss.hash_n(b"x", n)

    a = xmss.wots_chain(x, 0, 5, n=n, w=w, pub_seed=pub_seed, leaf_idx=1, chain_idx=2)
    b = xmss.wots_chain(a, 5, 3, n=n, w=w, pub_seed=pub_seed, leaf_idx=1, chain_idx=2)
    c = xmss.wots_chain(x, 0, 8, n=n, w=w, pub_seed=pub_seed, leaf_idx=1, chain_idx=2)
    assert b == c


def test_xmss_wrong_message_rejected() -> None:
    n = 16
    w = 16
    height = 4
    sk_seed = xmss.hash_n(b"lesson sk_seed", n)
    sk_prf = xmss.hash_n(b"lesson sk_prf", n)
    pub_seed = xmss.hash_n(b"lesson pub_seed", n)

    sk, pk = xmss.xmss_keygen(sk_seed, sk_prf, pub_seed, n=n, w=w, height=height)
    msg = b"m1"
    sig = xmss.xmss_sign(sk, msg)
    assert xmss.xmss_verify(pk, msg, sig) is True
    assert xmss.xmss_verify(pk, b"m2", sig) is False


def test_signature_bytes_roundtrip() -> None:
    n = 16
    w = 16
    height = 4
    sk_seed = xmss.hash_n(b"lesson sk_seed", n)
    sk_prf = xmss.hash_n(b"lesson sk_prf", n)
    pub_seed = xmss.hash_n(b"lesson pub_seed", n)

    sk, pk = xmss.xmss_keygen(sk_seed, sk_prf, pub_seed, n=n, w=w, height=height)
    msg = b"roundtrip"
    sig = xmss.xmss_sign(sk, msg)
    b = xmss.xmss_sig_to_bytes(sig, n=n)
    sig2 = xmss.xmss_sig_from_bytes(b, n=n, w=w, height=height)
    assert sig2 == sig
    assert xmss.xmss_verify(pk, msg, sig2) is True


def test_key_exhaustion_rejected() -> None:
    n = 16
    w = 16
    height = 2
    sk_seed = xmss.hash_n(b"sk_seed", n)
    sk_prf = xmss.hash_n(b"sk_prf", n)
    pub_seed = xmss.hash_n(b"pub_seed", n)
    sk, _ = xmss.xmss_keygen(sk_seed, sk_prf, pub_seed, n=n, w=w, height=height)
    for _ in range(2**height):
        xmss.xmss_sign(sk, b"x")
    try:
        xmss.xmss_sign(sk, b"overflow")
    except ValueError:
        return
    raise AssertionError("expected exhaustion to raise ValueError")


def test_wots_reuse_forgery_tiny() -> None:
    n = 2
    w = 16
    sk_seed = xmss.hash_n(b"demo sk_seed", n)
    pub_seed = xmss.hash_n(b"demo pub_seed", n)
    leaf_idx = 0

    digest_a = xmss.hash_n(b"message A", n)
    digest_b = xmss.hash_n(b"message B", n)

    sig_a = xmss.wots_sign(sk_seed, pub_seed, digest_a, n=n, w=w, leaf_idx=leaf_idx)
    sig_b = xmss.wots_sign(sk_seed, pub_seed, digest_b, n=n, w=w, leaf_idx=leaf_idx)

    digits_a = xmss.wots_message_digits(digest_a, n=n, w=w)
    digits_b = xmss.wots_message_digits(digest_b, n=n, w=w)
    mins = [min(x, y) for x, y in zip(digits_a, digits_b)]

    forged_digest = None
    forged_digits = None
    for x in range(1, 1 << (8 * n)):
        cand = xmss.int_to_bytes(x, n)
        d = xmss.wots_message_digits(cand, n=n, w=w)
        if all(di >= mi for di, mi in zip(d, mins)):
            forged_digest = cand
            forged_digits = d
            break
    assert forged_digest is not None
    assert forged_digits is not None

    forged_sig = []
    for i, target_d in enumerate(forged_digits):
        if digits_a[i] <= digits_b[i]:
            base_node = sig_a[i]
            base_d = digits_a[i]
        else:
            base_node = sig_b[i]
            base_d = digits_b[i]
        forged_sig.append(
            xmss.wots_chain(
                base_node,
                base_d,
                target_d - base_d,
                n=n,
                w=w,
                pub_seed=pub_seed,
                leaf_idx=leaf_idx,
                chain_idx=i,
            )
        )

    forged_pk = xmss.wots_pk_from_sig(forged_sig, pub_seed, forged_digest, n=n, w=w, leaf_idx=leaf_idx)
    real_pk = xmss.wots_gen_pk(sk_seed, pub_seed, n=n, w=w, leaf_idx=leaf_idx)
    assert forged_pk == real_pk


if __name__ == "__main__":
    test_vectors()
    test_wots_chain_composition()
    test_xmss_wrong_message_rejected()
    test_signature_bytes_roundtrip()
    test_key_exhaustion_rejected()
    test_wots_reuse_forgery_tiny()
    print("all tests pass")
