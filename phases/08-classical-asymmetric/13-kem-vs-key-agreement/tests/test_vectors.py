import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as x  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hex_to_bytes(s: str) -> bytes:
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


def test_vectors() -> None:
    data = _load_vectors()
    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]

        if op == "hkdf_sha256":
            got = x.hkdf_sha256(
                ikm=_hex_to_bytes(inputs["ikm_hex"]),
                salt=_hex_to_bytes(inputs["salt_hex"]),
                info=_hex_to_bytes(inputs["info_hex"]),
                length=inputs["length"],
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "transcript_hash":
            got = x.transcript_hash([_hex_to_bytes(p) for p in inputs["parts_hex"]])
            assert got.hex() == v["expected_hex"]
            continue

        if op == "modexp":
            got = x.modexp(inputs["base"], inputs["exponent"], inputs["modulus"])
            assert got == v["expected"]
            continue

        if op == "dh_public_key":
            got = x.dh_public_key(group=x.TOY_GROUP, private_key=inputs["private_key"])
            assert got == v["expected"]
            continue

        if op == "dh_shared_secret":
            got = x.dh_shared_secret(
                group=x.TOY_GROUP,
                private_key=inputs["private_key"],
                peer_public_key=inputs["peer_public_key"],
            )
            assert got == v["expected"]
            continue

        if op == "ka_2msg_session_key":
            key_a, key_b, transcript = x.ka_2msg_session_key(
                group=x.TOY_GROUP,
                alice_private=inputs["alice_private"],
                bob_private=inputs["bob_private"],
                info=_hex_to_bytes(inputs["info_hex"]),
            )
            assert key_a == key_b
            assert key_a.hex() == v["expected"]["session_key_hex"]
            assert transcript.hex() == v["expected"]["transcript_hex"]
            continue

        if op == "dhkem_encap":
            enc, shared = x.dhkem_encap(
                group=x.TOY_GROUP,
                recipient_public_key=inputs["recipient_public_key"],
                sender_ephemeral_private=inputs["sender_ephemeral_private"],
                info=_hex_to_bytes(inputs["info_hex"]),
            )
            assert enc.hex() == v["expected"]["enc_hex"]
            assert shared.hex() == v["expected"]["shared_secret_hex"]
            continue

        if op == "dhkem_decap":
            got = x.dhkem_decap(
                group=x.TOY_GROUP,
                recipient_private_key=inputs["recipient_private_key"],
                enc=_hex_to_bytes(inputs["enc_hex"]),
                info=_hex_to_bytes(inputs["info_hex"]),
            )
            assert got.hex() == v["expected_hex"]
            continue

        if op == "mix_secrets":
            got = x.mix_secrets(
                secrets_list=[_hex_to_bytes(s) for s in inputs["secrets_hex"]],
                context=_hex_to_bytes(inputs["context_hex"]),
                length=32,
            )
            assert got.hex() == v["expected_hex"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_dh_commutes_in_toy_group() -> None:
    import random

    rng = random.Random(0)
    for _ in range(50):
        while True:
            a = rng.randrange(2, x.TOY_GROUP.p - 1)
            A = x.dh_public_key(group=x.TOY_GROUP, private_key=a)
            try:
                x.validate_dh_public_key(group=x.TOY_GROUP, public_key=A)
            except ValueError:
                continue
            break

        while True:
            b = rng.randrange(2, x.TOY_GROUP.p - 1)
            B = x.dh_public_key(group=x.TOY_GROUP, private_key=b)
            try:
                x.validate_dh_public_key(group=x.TOY_GROUP, public_key=B)
            except ValueError:
                continue
            break
        z1 = x.dh_shared_secret(group=x.TOY_GROUP, private_key=a, peer_public_key=B)
        z2 = x.dh_shared_secret(group=x.TOY_GROUP, private_key=b, peer_public_key=A)
        assert z1 == z2


def test_kem_roundtrip_randomized() -> None:
    import random

    rng = random.Random(1)
    for _ in range(50):
        while True:
            sk_r = rng.randrange(2, x.TOY_GROUP.p - 1)
            pk_r = x.dh_public_key(group=x.TOY_GROUP, private_key=sk_r)
            try:
                x.validate_dh_public_key(group=x.TOY_GROUP, public_key=pk_r)
            except ValueError:
                continue
            break

        while True:
            sk_e = rng.randrange(2, x.TOY_GROUP.p - 1)
            pk_e = x.dh_public_key(group=x.TOY_GROUP, private_key=sk_e)
            try:
                x.validate_dh_public_key(group=x.TOY_GROUP, public_key=pk_e)
            except ValueError:
                continue
            break
        info = rng.randbytes(8)

        enc, shared_sender = x.dhkem_encap(
            group=x.TOY_GROUP,
            recipient_public_key=pk_r,
            sender_ephemeral_private=sk_e,
            info=info,
        )
        shared_recipient = x.dhkem_decap(
            group=x.TOY_GROUP,
            recipient_private_key=sk_r,
            enc=enc,
            info=info,
        )
        assert shared_sender == shared_recipient
        assert len(shared_sender) == 32


def test_context_binding_changes_outputs() -> None:
    alice_private = 6
    bob_private = 15

    key1, _, _ = x.ka_2msg_session_key(
        group=x.TOY_GROUP, alice_private=alice_private, bob_private=bob_private, info=b"ctx1"
    )
    key2, _, _ = x.ka_2msg_session_key(
        group=x.TOY_GROUP, alice_private=alice_private, bob_private=bob_private, info=b"ctx2"
    )
    assert key1 != key2

    pk_r = x.dh_public_key(group=x.TOY_GROUP, private_key=bob_private)
    enc1, ss1 = x.dhkem_encap(
        group=x.TOY_GROUP,
        recipient_public_key=pk_r,
        sender_ephemeral_private=alice_private,
        info=b"ctx1",
    )
    enc2, ss2 = x.dhkem_encap(
        group=x.TOY_GROUP,
        recipient_public_key=pk_r,
        sender_ephemeral_private=alice_private,
        info=b"ctx2",
    )
    assert enc1 == enc2
    assert ss1 != ss2


def test_rejects_bad_inputs() -> None:
    _assert_raises(ValueError, x.hkdf_sha256, ikm=b"a", salt=b"b", info=b"c", length=0)

    _assert_raises(ValueError, x.dh_public_key, group=x.TOY_GROUP, private_key=1)
    _assert_raises(ValueError, x.validate_dh_public_key, group=x.TOY_GROUP, public_key=1)
    _assert_raises(ValueError, x.deserialize_group_element, group=x.TOY_GROUP, data=b"")
    _assert_raises(ValueError, x.deserialize_group_element, group=x.TOY_GROUP, data=b"\x00\x01")
    _assert_raises(ValueError, x.mix_secrets, secrets_list=[b"a"], context=b"c", length=0)


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")
