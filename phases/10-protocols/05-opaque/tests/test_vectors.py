import json
import sys
from pathlib import Path

try:
    import pytest  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    pytest = None


THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR.parent / "code"))

import main as opaque  # noqa: E402


def _load_vectors() -> dict:
    path = THIS_DIR / "vectors.json"
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _hx(s: str) -> bytes:
    return bytes.fromhex(s)


def _hi(s: str) -> int:
    return int(s, 16)


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
    g = opaque.rfc3526_group14_subgroup_qr()
    data = _load_vectors()

    for v in data["vectors"]:
        op = v["op"]
        inputs = v["inputs"]
        expected = v["expected"]

        if op == "modinv":
            got = opaque.modinv(inputs["a"], inputs["modulus"])
            assert got == expected
            continue

        if op == "derive_dh_keypair_from_seed":
            sk, pk = opaque.derive_dh_keypair_from_seed(_hx(inputs["seed_hex"]), g)
            assert f"{sk:x}" == expected["sk_hex"]
            assert f"{pk:x}" == expected["pk_hex"]
            continue

        if op == "hash_to_group":
            elem = opaque.hash_to_group(inputs["password_utf8"].encode("utf-8"), g)
            assert f"{elem:x}" == expected["elem_hex"]
            continue

        if op == "oprf_flow":
            pw = inputs["password_utf8"].encode("utf-8")
            blind = inputs["blind"]
            key = inputs["oprf_key"]
            blinded = opaque.oprf_blind(pw, blind, g)
            evaluated = opaque.oprf_evaluate(blinded, key, g)
            output = opaque.oprf_finalize(pw, blind, evaluated, g)
            assert f"{blinded:x}" == expected["blinded_hex"]
            assert f"{evaluated:x}" == expected["evaluated_hex"]
            assert output.hex() == expected["oprf_output_hex"]
            continue

        if op == "stretch_password":
            rp = opaque.stretch_password(_hx(inputs["oprf_output_hex"]), iters=inputs["iters"])
            assert rp.hex() == expected["randomized_password_hex"]
            continue

        if op == "store_and_recover_envelope":
            randomized_password = _hx(inputs["randomized_password_hex"])
            server_pk = _hi(inputs["server_public_key_hex"])
            env, client_pk, masking_key, export_key = opaque.store_envelope(
                randomized_password=randomized_password,
                server_public_key=server_pk,
                server_identity=inputs["server_identity_utf8"].encode("utf-8"),
                client_identity=inputs["client_identity_utf8"].encode("utf-8"),
                envelope_nonce=_hx(inputs["envelope_nonce_hex"]),
                group=g,
            )
            assert f"{client_pk:x}" == expected["client_public_key_hex"]
            assert masking_key.hex() == expected["masking_key_hex"]
            assert export_key.hex() == expected["export_key_hex"]
            assert env.auth_tag.hex() == expected["envelope_auth_tag_hex"]

            client_sk, cleartext, export_key2 = opaque.recover_envelope(
                randomized_password=randomized_password,
                server_public_key=server_pk,
                envelope=env,
                server_identity=inputs["server_identity_utf8"].encode("utf-8"),
                client_identity=inputs["client_identity_utf8"].encode("utf-8"),
                group=g,
            )
            assert f"{client_sk:x}" == expected["client_private_key_hex"]
            assert opaque.sha256(cleartext).hex() == expected["cleartext_sha256_hex"]
            assert export_key2.hex() == expected["export_key_hex"]
            continue

        if op == "opaque_3dh_ake":
            pw = inputs["password_utf8"].encode("utf-8")
            cid = inputs["client_identity_utf8"].encode("utf-8")
            sid = inputs["server_identity_utf8"].encode("utf-8")
            blind = inputs["blind"]
            oprf_key = inputs["oprf_key"]

            server_sk, server_pk = opaque.derive_dh_keypair_from_seed(_hx(inputs["server_key_seed_hex"]), g)
            record, _ = opaque.register_user(
                password=pw,
                client_identity=cid,
                server_identity=sid,
                blind=blind,
                envelope_nonce=_hx(inputs["envelope_nonce_hex"]),
                server_public_key=server_pk,
                oprf_key=oprf_key,
                group=g,
            )

            client_state = opaque.client_start(
                password=pw,
                client_identity=cid,
                blind=blind,
                client_nonce=_hx(inputs["client_nonce_hex"]),
                client_keyshare_seed=_hx(inputs["client_keyshare_seed_hex"]),
                group=g,
            )
            server_state, ke2 = opaque.server_respond(
                client_identity=cid,
                server_identity=sid,
                server_private_key=server_sk,
                server_public_key=server_pk,
                oprf_key=oprf_key,
                record=record,
                ke1=client_state.ke1,
                masking_nonce=_hx(inputs["masking_nonce_hex"]),
                server_nonce=_hx(inputs["server_nonce_hex"]),
                server_keyshare_seed=_hx(inputs["server_keyshare_seed_hex"]),
                group=g,
            )
            assert ke2.auth_response.server_mac.hex() == expected["server_mac_hex"]

            ke3, client_session, _ = opaque.client_finalize(state=client_state, server_identity=sid, ke2=ke2, group=g)
            assert ke3.client_mac.hex() == expected["client_mac_hex"]
            server_session = opaque.server_finalize(server_state=server_state, ke3=ke3)
            assert client_session == server_session
            assert client_session.hex() == expected["session_key_hex"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_oprf_finalize_independent_of_blind() -> None:
    g = opaque.rfc3526_group14_subgroup_qr()
    pw = b"password"
    oprf_key = 12345
    blinds = [7, 123, 999_999]
    outs: list[bytes] = []
    for b in blinds:
        blinded = opaque.oprf_blind(pw, b, g)
        evaluated = opaque.oprf_evaluate(blinded, oprf_key, g)
        outs.append(opaque.oprf_finalize(pw, b, evaluated, g))
    assert outs[0] == outs[1] == outs[2]


def test_envelope_recovery_rejects_wrong_password() -> None:
    g = opaque.rfc3526_group14_subgroup_qr()
    server_sk, server_pk = opaque.derive_dh_keypair_from_seed(b"\x11" * 32, g)
    record, _ = opaque.register_user(
        password=b"correct horse battery staple",
        client_identity=b"alice",
        server_identity=b"example.com",
        blind=123456789,
        envelope_nonce=b"\x22" * 32,
        server_public_key=server_pk,
        oprf_key=42424242,
        group=g,
    )
    evaluated = opaque.oprf_evaluate(opaque.oprf_blind(b"tr0ub4dor&3", 123456789, g), 42424242, g)
    oprf_output = opaque.oprf_finalize(b"tr0ub4dor&3", 123456789, evaluated, g)
    randomized_password = opaque.stretch_password(oprf_output)
    _assert_raises(
        ValueError,
        opaque.recover_envelope,
        randomized_password=randomized_password,
        server_public_key=server_pk,
        envelope=record.envelope,
        server_identity=b"example.com",
        client_identity=b"alice",
        group=g,
    )


def test_ake_rejects_wrong_password() -> None:
    g = opaque.rfc3526_group14_subgroup_qr()
    password = b"correct horse battery staple"
    wrong = b"tr0ub4dor&3"
    cid = b"alice"
    sid = b"example.com"
    blind = 123456789
    oprf_key = 42424242

    server_sk, server_pk = opaque.derive_dh_keypair_from_seed(b"\x11" * 32, g)
    record, _ = opaque.register_user(
        password=password,
        client_identity=cid,
        server_identity=sid,
        blind=blind,
        envelope_nonce=b"\x22" * 32,
        server_public_key=server_pk,
        oprf_key=oprf_key,
        group=g,
    )

    client_state = opaque.client_start(
        password=password,
        client_identity=cid,
        blind=blind,
        client_nonce=b"\x33" * 32,
        client_keyshare_seed=b"\x44" * 32,
        group=g,
    )
    server_state, ke2 = opaque.server_respond(
        client_identity=cid,
        server_identity=sid,
        server_private_key=server_sk,
        server_public_key=server_pk,
        oprf_key=oprf_key,
        record=record,
        ke1=client_state.ke1,
        masking_nonce=b"\x55" * 32,
        server_nonce=b"\x66" * 32,
        server_keyshare_seed=b"\x77" * 32,
        group=g,
    )

    bad_state = opaque.client_start(
        password=wrong,
        client_identity=cid,
        blind=blind,
        client_nonce=b"\x33" * 32,
        client_keyshare_seed=b"\x44" * 32,
        group=g,
    )
    _assert_raises(ValueError, opaque.client_finalize, state=bad_state, server_identity=sid, ke2=ke2, group=g)
    _assert_raises(ValueError, opaque.server_finalize, server_state=server_state, ke3=opaque.KE3(client_mac=b"\x00" * 32))


if __name__ == "__main__":
    if pytest is not None:
        raise SystemExit(pytest.main([__file__]))

    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in sorted(tests, key=lambda f: f.__name__):
        t()
    print("all tests pass")

