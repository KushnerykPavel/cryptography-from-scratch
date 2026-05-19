import json
import pathlib
import sys


THIS_DIR = pathlib.Path(__file__).resolve().parent
CODE_DIR = THIS_DIR.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as lesson  # noqa: E402


def _load_vectors():
    vectors_path = THIS_DIR / "vectors.json"
    with vectors_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


def test_vectors():
    vectors = _load_vectors()
    priv = lesson.DEMO_RSA_PRIVATE_KEY
    pub = priv.public()

    for idx, v in enumerate(vectors):
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "canonical_json_utf8":
            got = lesson.canonical_json(inputs["obj"]).decode("utf-8")
            assert got == expected["utf8"], (idx, op, got)
        elif op == "sha256_hex_utf8":
            got = lesson.sha256_hex(inputs["utf8"].encode("utf-8"))
            assert got == expected["hex"], (idx, op, got)
        elif op == "signature_base_string_utf8":
            got = lesson.signature_base_string(
                method=inputs["method"],
                path=inputs["path"],
                ts=int(inputs["ts"]),
                nonce=inputs["nonce"],
                payload=inputs["payload"],
            ).decode("utf-8")
            assert got == expected["utf8"], (idx, op, got)
        elif op == "rsa_sign_b64url":
            msg = inputs["message_utf8"].encode("utf-8")
            sig = lesson.rsa_sign_pkcs1_v1_5_sha256(priv, msg)
            got = lesson.b64url_encode(sig)
            assert got == expected["sig_b64url"], (idx, op, got)
        elif op == "rsa_verify_bool":
            msg = inputs["message_utf8"].encode("utf-8")
            sig = lesson.b64url_decode(inputs["sig_b64url"])
            got = lesson.rsa_verify_pkcs1_v1_5_sha256(pub, msg, sig)
            assert got == bool(expected["ok"]), (idx, op, got)
        else:
            raise AssertionError(f"unknown op: {op}")


def test_canonical_json_is_stable_for_key_order():
    a = {"amount": 1250, "to": "acct_123", "memo": "rent May"}
    b = {"memo": "rent May", "to": "acct_123", "amount": 1250}
    assert lesson.canonical_json(a) == lesson.canonical_json(b)


def test_b64url_roundtrip():
    samples = [b"", b"\x00", b"\x00\x01\x02", b"hello", bytes(range(0, 64))]
    for s in samples:
        assert lesson.b64url_decode(lesson.b64url_encode(s)) == s


def test_rsa_sign_verify_roundtrip():
    priv = lesson.DEMO_RSA_PRIVATE_KEY
    pub = priv.public()
    msgs = [
        b"x",
        b"POST\n/v1/sign\nexample",
        b"GET\n/v1/verify\n{\"a\":1}",
    ]
    for m in msgs:
        sig = lesson.rsa_sign_pkcs1_v1_5_sha256(priv, m)
        assert lesson.rsa_verify_pkcs1_v1_5_sha256(pub, m, sig) is True
        assert lesson.rsa_verify_pkcs1_v1_5_sha256(pub, m + b"!", sig) is False


def test_signed_request_rejects_tamper_and_replay():
    priv = lesson.DEMO_RSA_PRIVATE_KEY
    pub = priv.public()
    kid = "demo-kid-1"
    method = "POST"
    path = "/v1/sign"
    ts = 1716050000
    nonce = "n-0001"
    payload = {"amount": 1250, "to": "acct_123", "memo": "rent May"}

    signed = lesson.sign_request(
        private_key=priv,
        key_id=kid,
        method=method,
        path=path,
        ts=ts,
        nonce=nonce,
        payload=payload,
    )

    used_nonces = set()
    lesson.verify_signed_request(
        public_key=pub,
        expected_key_id=kid,
        method=method,
        path=path,
        signed=signed,
        now_ts=ts,
        max_skew_s=300,
        used_nonces=used_nonces,
    )

    try:
        lesson.verify_signed_request(
            public_key=pub,
            expected_key_id=kid,
            method=method,
            path=path,
            signed=signed,
            now_ts=ts,
            max_skew_s=300,
            used_nonces=used_nonces,
        )
        assert False, "expected replay detection"
    except ValueError as e:
        assert "replay" in str(e)

    tampered = dict(signed)
    tampered["payload"] = dict(payload)
    tampered["payload"]["amount"] = 9999
    try:
        lesson.verify_signed_request(
            public_key=pub,
            expected_key_id=kid,
            method=method,
            path=path,
            signed=tampered,
            now_ts=ts,
            max_skew_s=300,
            used_nonces=set(),
        )
        assert False, "expected signature failure"
    except ValueError as e:
        assert "invalid signature" in str(e)

    try:
        lesson.verify_signed_request(
            public_key=pub,
            expected_key_id=kid,
            method="GET",
            path=path,
            signed=signed,
            now_ts=ts,
            max_skew_s=300,
            used_nonces=set(),
        )
        assert False, "expected method binding failure"
    except ValueError as e:
        assert "invalid signature" in str(e)


def test_signed_request_rejects_old_timestamp():
    priv = lesson.DEMO_RSA_PRIVATE_KEY
    pub = priv.public()
    kid = "demo-kid-1"
    signed = lesson.sign_request(
        private_key=priv,
        key_id=kid,
        method="POST",
        path="/v1/sign",
        ts=1716050000,
        nonce="n-0002",
        payload={"a": 1},
    )
    try:
        lesson.verify_signed_request(
            public_key=pub,
            expected_key_id=kid,
            method="POST",
            path="/v1/sign",
            signed=signed,
            now_ts=1716050000 + 10_000,
            max_skew_s=300,
            used_nonces=set(),
        )
        assert False, "expected timestamp skew failure"
    except ValueError as e:
        assert "timestamp" in str(e)


def _run_all():
    test_vectors()
    test_canonical_json_is_stable_for_key_order()
    test_b64url_roundtrip()
    test_rsa_sign_verify_roundtrip()
    test_signed_request_rejects_tamper_and_replay()
    test_signed_request_rejects_old_timestamp()


if __name__ == "__main__":
    _run_all()
    print("all tests pass")

