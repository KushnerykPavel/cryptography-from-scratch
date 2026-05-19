import json
import random
import sys
from pathlib import Path


_CODE_DIR = Path(__file__).resolve().parent.parent / "code"
sys.path.insert(0, str(_CODE_DIR))
import main as tls  # noqa: E402


def _b(hex_str: str) -> bytes:
    if hex_str == "":
        return b""
    return bytes.fromhex(hex_str)


def test_vectors() -> None:
    vectors_path = Path(__file__).resolve().parent / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]

    for v in vectors:
        op = v["op"]

        if op == "hkdf_extract_sha256":
            got = tls.hkdf_extract_sha256(salt=_b(v["salt_hex"]), ikm=_b(v["ikm_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        if op == "hkdf_expand_sha256":
            got = tls.hkdf_expand_sha256(
                prk=_b(v["prk_hex"]), info=_b(v["info_hex"]), length=int(v["length"])
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "tls13_hkdf_label":
            got = tls.tls13_hkdf_label(
                length=int(v["length"]), label=v["label"], context=_b(v["context_hex"])
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "transcript_hash_sha256":
            msgs = [_b(x) for x in v["messages_hex"]]
            got = tls.transcript_hash_sha256(msgs)
            assert got.hex() == v["expected_hex"]
            continue

        if op == "tls13_key_schedule_sha256":
            t = v["transcript"]
            transcript = tls.TLS13ToyHandshake(
                client_hello=_b(t["client_hello_hex"]),
                server_hello=_b(t["server_hello_hex"]),
                encrypted_extensions=_b(t["encrypted_extensions_hex"]),
                server_certificate=_b(t["server_certificate_hex"]),
                server_certificate_verify=_b(t["server_certificate_verify_hex"]),
                server_finished=_b(t["server_finished_hex"]),
            )
            got = tls.tls13_key_schedule_sha256(
                shared_secret=_b(v["shared_secret_hex"]), transcript=transcript
            )
            assert {k: val.hex() for k, val in got.items()} == v["expected"]
            continue

        if op == "traffic_key_iv_sha256":
            key, iv = tls.traffic_key_iv_sha256(_b(v["traffic_secret_hex"]))
            assert key.hex() == v["expected_key_hex"]
            assert iv.hex() == v["expected_iv_hex"]
            continue

        if op == "finished_verify_data_sha256":
            got = tls.finished_verify_data_sha256(
                finished_key=_b(v["finished_key_hex"]),
                transcript_hash=_b(v["transcript_hash_hex"]),
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "update_traffic_secret_sha256":
            got = tls.update_traffic_secret_sha256(_b(v["traffic_secret_hex"]))
            assert got.hex() == v["expected_hex"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_properties() -> None:
    rng = random.Random(0)

    for n in [0, 1, 2, 3, 15, 16, 31, 32, 33, 64]:
        data = bytes(rng.randrange(256) for _ in range(n))
        assert tls.hex_to_bytes(tls.bytes_to_hex(data)) == data

    prk = bytes(rng.randrange(256) for _ in range(32))
    info = b"info"
    assert tls.hkdf_expand_sha256(prk=prk, info=info, length=0) == b""

    out32 = tls.hkdf_expand_sha256(prk=prk, info=info, length=32)
    out64 = tls.hkdf_expand_sha256(prk=prk, info=info, length=64)
    assert out64[:32] == out32

    too_big = 255 * 32 + 1
    try:
        tls.hkdf_expand_sha256(prk=prk, info=info, length=too_big)
        raise AssertionError("expected ValueError for too-large HKDF length")
    except ValueError:
        pass

    try:
        tls.tls13_hkdf_label(length=16, label="key", context=b"a" * 256)
        raise AssertionError("expected ValueError for too-long context")
    except ValueError:
        pass


def _run_all() -> None:
    test_vectors()
    test_properties()
    print("all tests pass")


if __name__ == "__main__":
    _run_all()
