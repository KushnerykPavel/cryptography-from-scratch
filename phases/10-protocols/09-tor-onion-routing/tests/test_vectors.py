import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as mt  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
    if s == "":
        return b""
    return bytes.fromhex(s)


def _assert_raises(exc_type, fn, /, **kwargs):
    if pytest is not None:
        with pytest.raises(exc_type):
            fn(**kwargs)
        return
    try:
        fn(**kwargs)
    except exc_type:
        return
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}") from e
    raise AssertionError(f"expected {exc_type.__name__} to be raised")


def _hop_from_json(obj: dict) -> mt.Hop:
    return mt.Hop(name=obj["name"], key=_hex_to_bytes(obj["key_hex"]))


def test_vectors() -> None:
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]

        if op == "sha256_hex":
            got = mt.sha256(_hex_to_bytes(inputs["data_hex"])).hex()
            assert got == v["expected_hex"]
            continue

        if op == "prg_stream_hex":
            got = mt.prg_stream(
                key=_hex_to_bytes(inputs["key_hex"]),
                nonce=_hex_to_bytes(inputs["nonce_hex"]),
                length=inputs["length"],
            ).hex()
            assert got == v["expected_hex"]
            continue

        if op == "seal_hex":
            got = mt.seal(
                key=_hex_to_bytes(inputs["key_hex"]),
                nonce=_hex_to_bytes(inputs["nonce_hex"]),
                plaintext=_hex_to_bytes(inputs["plaintext_hex"]),
                aad=_hex_to_bytes(inputs["aad_hex"]),
            ).hex()
            assert got == v["expected_hex"]
            continue

        if op == "open_sealed_hex":
            got = mt.open_sealed(
                key=_hex_to_bytes(inputs["key_hex"]),
                data=_hex_to_bytes(inputs["sealed_hex"]),
                aad=_hex_to_bytes(inputs["aad_hex"]),
            ).hex()
            assert got == v["expected_hex"]
            continue

        if op == "encode_exit_payload_utf8":
            got = mt.encode_exit_payload(
                dest=inputs["dest"],
                message=_hex_to_bytes(inputs["message_hex"]),
            ).decode("utf-8")
            assert got == v["expected_utf8"]
            continue

        if op == "encode_relay_payload_utf8":
            got = mt.encode_relay_payload(
                next_hop=inputs["next_hop"],
                inner_packet=_hex_to_bytes(inputs["inner_hex"]),
            ).decode("utf-8")
            assert got == v["expected_utf8"]
            continue

        if op == "build_onion_packet_hex":
            route = [_hop_from_json(h) for h in inputs["route"]]
            got = mt.build_onion_packet(
                route=route,
                dest=inputs["dest"],
                message=_hex_to_bytes(inputs["message_hex"]),
                packet_seed=_hex_to_bytes(inputs["packet_seed_hex"]),
            ).hex()
            assert got == v["expected_hex"]
            continue

        if op == "peel_one_layer":
            hop = _hop_from_json(inputs["hop"])
            next_hop, inner = mt.peel_one_layer(hop=hop, onion_packet=_hex_to_bytes(inputs["onion_packet_hex"]))
            assert next_hop == v["expected"]["next_hop"]
            assert inner.hex() == v["expected"]["inner_hex"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_aead_roundtrip_and_tamper_detection() -> None:
    key = mt.sha256(b"k")
    nonce = b"\x00" * mt.NONCE_LEN
    aad = b"hdr"
    pt = b"payload"
    sealed = mt.seal(key=key, nonce=nonce, plaintext=pt, aad=aad)
    assert mt.open_sealed(key=key, data=sealed, aad=aad) == pt

    tampered = bytearray(sealed)
    tampered[-1] ^= 1
    _assert_raises(ValueError, mt.open_sealed, key=key, data=bytes(tampered), aad=aad)


def test_onion_route_roundtrip() -> None:
    route = [
        mt.Hop(name="guard", key=mt.sha256(b"guard-key")),
        mt.Hop(name="middle", key=mt.sha256(b"middle-key")),
        mt.Hop(name="exit", key=mt.sha256(b"exit-key")),
    ]
    packet_seed = mt.sha256(b"packet-seed")
    msg = b"GET / HTTP/1.0\r\n\r\n"
    onion = mt.build_onion_packet(route=route, dest="example.com:80", message=msg, packet_seed=packet_seed)
    dest, out = mt.simulate_route(route=route, onion_packet=onion)
    assert dest == "example.com:80"
    assert out == msg


def test_wrong_hop_key_or_aad_rejected() -> None:
    route = [
        mt.Hop(name="guard", key=mt.sha256(b"guard-key")),
        mt.Hop(name="middle", key=mt.sha256(b"middle-key")),
        mt.Hop(name="exit", key=mt.sha256(b"exit-key")),
    ]
    packet_seed = mt.sha256(b"packet-seed")
    onion = mt.build_onion_packet(route=route, dest="d", message=b"m", packet_seed=packet_seed)

    _assert_raises(ValueError, mt.peel_one_layer, hop=mt.Hop(name="guard", key=mt.sha256(b"wrong")), onion_packet=onion)
    _assert_raises(ValueError, mt.peel_one_layer, hop=mt.Hop(name="wrongname", key=route[0].key), onion_packet=onion)


def test_nonce_length_validation() -> None:
    key = mt.sha256(b"k")
    _assert_raises(ValueError, mt.seal, key=key, nonce=b"\x00" * 15, plaintext=b"x", aad=b"")
    _assert_raises(ValueError, mt.prg_stream, key=key, nonce=b"\x00" * 15, length=1)


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

