import json
import pathlib
import sys


THIS_DIR = pathlib.Path(__file__).resolve().parent
CODE_DIR = THIS_DIR.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as lab  # noqa: E402


def _params(p: int, q: int, g: int) -> lab.DLGroup:
    params = lab.DLGroup(p=p, q=q, g=g)
    lab.validate_group(params)
    return params


def _read_vectors() -> list[dict]:
    vectors_path = THIS_DIR / "vectors.json"
    with vectors_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload["vectors"]


def test_vectors():
    for case in _read_vectors():
        op = case["op"]
        inputs = case["inputs"]
        expected = case["expected"]

        if op == "encode_int":
            got = lab.encode_int(inputs["n"]).hex()
            assert got == expected["hex"]
            continue

        if op == "encode_bytes":
            got = lab.encode_bytes(inputs["text_utf8"].encode("utf-8")).hex()
            assert got == expected["hex"]
            continue

        if op == "decode_int":
            n, next_offset = lab.decode_int(bytes.fromhex(inputs["hex"]), 0)
            assert n == expected["n"]
            assert next_offset == expected["next_offset"]
            continue

        if op == "decode_bytes":
            b, next_offset = lab.decode_bytes(bytes.fromhex(inputs["hex"]), 0)
            assert b.decode("utf-8") == expected["text_utf8"]
            assert next_offset == expected["next_offset"]
            continue

        if op == "hash_to_scalar":
            parts = [bytes.fromhex(h) for h in inputs["parts_hex"]]
            got = lab.hash_to_scalar(inputs["domain"], parts, inputs["q"])
            assert got == expected["scalar"]
            continue

        if op == "public_key":
            params = _params(inputs["p"], inputs["q"], inputs["g"])
            got = lab.public_key(params, inputs["x"])
            assert got == expected["pk"]
            continue

        if op == "make_login_message":
            got = lab.make_login_message(inputs["user_id"], inputs["session_id"])
            assert got.decode("utf-8") == expected["message_utf8"]
            continue

        if op == "schnorr_prove":
            params = _params(inputs["p"], inputs["q"], inputs["g"])
            msg = inputs["message_utf8"].encode("utf-8")
            got = lab.schnorr_prove(params, inputs["x"], msg, inputs["nonce"])
            pk = lab.public_key(params, inputs["x"])
            c = lab._challenge(params, pk, got.R, msg)
            assert got.R == expected["R"]
            assert got.s == expected["s"]
            assert c == expected["challenge"]
            continue

        if op == "schnorr_verify":
            params = _params(inputs["p"], inputs["q"], inputs["g"])
            msg = inputs["message_utf8"].encode("utf-8")
            proof = lab.SchnorrProof(R=inputs["proof"]["R"], s=inputs["proof"]["s"])
            got = lab.schnorr_verify(params, inputs["pk"], msg, proof)
            assert got == expected["ok"]
            continue

        if op == "server_verify_login":
            params = _params(inputs["p"], inputs["q"], inputs["g"])
            server = lab.ZKLoginServer(params)
            server.register(inputs["user_id"], inputs["pk"])
            proof = lab.SchnorrProof(R=inputs["proof"]["R"], s=inputs["proof"]["s"])
            got = server.verify_login(inputs["user_id"], inputs["session_id"], proof)
            assert got == expected["token"]
            continue

        if op == "recover_secret_from_nonce_reuse":
            params = _params(inputs["p"], inputs["q"], inputs["g"])
            proof1 = lab.SchnorrProof(R=inputs["proof1"]["R"], s=inputs["proof1"]["s"])
            proof2 = lab.SchnorrProof(R=inputs["proof2"]["R"], s=inputs["proof2"]["s"])
            got = lab.recover_secret_from_nonce_reuse(
                params,
                proof1,
                inputs["proof1"]["challenge"],
                proof2,
                inputs["proof2"]["challenge"],
            )
            assert got == expected["recovered_x"]
            assert got == inputs["x_expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_encode_decode_roundtrip():
    data = [0, 1, 255, 256, 2039, 2**64 - 1]
    for n in data:
        enc = lab.encode_int(n)
        dec, off = lab.decode_int(enc, 0)
        assert dec == n
        assert off == len(enc)

    b = b"\x00\x01hello\xff"
    enc_b = lab.encode_bytes(b)
    dec_b, off = lab.decode_bytes(enc_b, 0)
    assert dec_b == b
    assert off == len(enc_b)


def test_hash_to_scalar_range_and_determinism():
    q = 1019
    parts = [lab.encode_bytes(b"one"), lab.encode_bytes(b"two")]
    a = lab.hash_to_scalar("domain", parts, q)
    b = lab.hash_to_scalar("domain", parts, q)
    c = lab.hash_to_scalar("domain2", parts, q)
    assert 0 <= a < q
    assert a == b
    assert a != c


def test_schnorr_verify_rejects_bad_inputs():
    params = _params(2039, 1019, 4)
    x = 123
    pk = lab.public_key(params, x)
    msg = lab.make_login_message("alice", "s1")
    proof = lab.schnorr_prove(params, x, msg, nonce=1)

    assert lab.schnorr_verify(params, pk, msg, proof) is True
    assert lab.schnorr_verify(params, pk, msg + b"x", proof) is False
    assert lab.schnorr_verify(params, 1, msg, proof) is False
    assert lab.schnorr_verify(params, params.p, msg, proof) is False
    assert lab.schnorr_verify(params, pk, msg, lab.SchnorrProof(R=proof.R, s=params.q)) is False


def test_server_replay_is_rejected():
    params = _params(2039, 1019, 4)
    server = lab.ZKLoginServer(params)
    x = 123
    pk = lab.public_key(params, x)
    server.register("alice", pk)

    msg = lab.make_login_message("alice", "session-1")
    proof = lab.schnorr_prove(params, x, msg, nonce=10)
    assert server.verify_login("alice", "session-1", proof) is not None
    assert server.verify_login("alice", "session-1", proof) is None


if __name__ == "__main__":
    test_vectors()
    test_encode_decode_roundtrip()
    test_hash_to_scalar_range_and_determinism()
    test_schnorr_verify_rejects_bad_inputs()
    test_server_replay_is_rejected()
    print("all tests pass")

