import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "code"))
from main import (  # noqa: E402
    PolicyError,
    derive_hybrid_session_key,
    enforce_kex_policy,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    kex_has_pq,
    parse_hybrid_name,
    server_select_kex,
    toy_dh_keypair,
    toy_dh_shared,
    toy_kem_decapsulate,
    toy_kem_encapsulate,
    toy_kem_keygen,
    transcript_hash,
)


def _b_ascii(s: str) -> bytes:
    return s.encode("utf-8")


def _b_hex(h: str) -> bytes:
    return bytes.fromhex(h)


def test_vectors():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "vectors.json")) as f:
        data = json.load(f)

    for v in data["vectors"]:
        op = v["op"]
        if op == "hkdf_extract":
            got = hkdf_extract(_b_ascii(v["salt_ascii"]), _b_ascii(v["ikm_ascii"]))
            assert got.hex() == v["expected_hex"]
        elif op == "hkdf_expand":
            got = hkdf_expand(_b_hex(v["prk_hex"]), _b_ascii(v["info_ascii"]), int(v["length"]))
            assert got.hex() == v["expected_hex"]
        elif op == "hkdf":
            got = hkdf(
                _b_ascii(v["salt_ascii"]),
                _b_ascii(v["ikm_ascii"]),
                _b_ascii(v["info_ascii"]),
                int(v["length"]),
            )
            assert got.hex() == v["expected_hex"]
        elif op == "transcript_hash":
            messages = [_b_ascii(m) for m in v["messages_ascii"]]
            got = transcript_hash(messages)
            assert got.hex() == v["expected_hex"]
        elif op == "parse_hybrid_name":
            got = parse_hybrid_name(v["name"])
            if v["expected_parts"] is None:
                assert got is None
            else:
                assert list(got) == v["expected_parts"]
        elif op == "kex_has_pq":
            assert bool(kex_has_pq(v["name"])) is bool(v["expected"])
        elif op == "server_select_kex":
            got = server_select_kex(v["client_offered"], v["server_preference"])
            assert got == v["expected"]
        elif op == "enforce_kex_policy":
            if "expected_error" in v:
                try:
                    enforce_kex_policy(v["selected"], bool(v["require_pq"]))
                except PolicyError:
                    pass
                else:
                    raise AssertionError("expected PolicyError")
            else:
                enforce_kex_policy(v["selected"], bool(v["require_pq"]))
                assert v["expected"] == "ok"
        elif op == "toy_kem_roundtrip":
            pk, sk = toy_kem_keygen(_b_ascii(v["keygen_seed_ascii"]))
            ct, ss_c = toy_kem_encapsulate(pk, _b_ascii(v["encap_seed_ascii"]))
            ss_s = toy_kem_decapsulate(sk, ct)
            assert ct.hex() == v["expected_ct_hex"]
            assert ss_c.hex() == v["expected_ss_hex"]
            assert ss_s == ss_c
        elif op == "toy_dh_shared":
            p = int(v["p"])
            g = int(v["g"])
            c_priv, c_pub = toy_dh_keypair(p, g, _b_ascii(v["client_seed_ascii"]))
            s_priv, s_pub = toy_dh_keypair(p, g, _b_ascii(v["server_seed_ascii"]))
            shared_c = toy_dh_shared(p, c_priv, s_pub)
            shared_s = toy_dh_shared(p, s_priv, c_pub)
            assert shared_c.hex() == v["expected_shared_hex"]
            assert shared_c == shared_s
        elif op == "derive_hybrid_session_key":
            got = derive_hybrid_session_key(
                classical_shared=_b_hex(v["classical_hex"]),
                pq_shared=_b_hex(v["pq_hex"]),
                transcript=_b_hex(v["transcript_hex"]),
                info=_b_ascii(v["info_ascii"]),
                length=int(v["length"]),
            )
            assert got.hex() == v["expected_hex"]
        else:
            raise AssertionError(f"unknown op {op}")


def test_hkdf_expand_rejects_length_out_of_range():
    prk = b"\x11" * 32
    try:
        hkdf_expand(prk, b"info", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative length")

    try:
        hkdf_expand(prk, b"info", 255 * 32 + 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for too-large length")


def test_transcript_hash_is_boundary_sensitive():
    a = transcript_hash([b"ab"])
    b = transcript_hash([b"a", b"b"])
    assert a != b


def test_server_select_kex_rejects_no_overlap():
    try:
        server_select_kex(["A"], ["B"])
    except PolicyError:
        pass
    else:
        raise AssertionError("expected PolicyError for no overlap")


def test_parse_hybrid_name_rejects_bad_syntax():
    assert parse_hybrid_name("HYBRID()") is None
    assert parse_hybrid_name("HYBRID(X25519)") is None
    assert parse_hybrid_name("HYBRID(X25519,)") is None
    assert parse_hybrid_name("HYBRID(,PQC-MLKEM-768)") is None


if __name__ == "__main__":
    test_vectors()
    test_hkdf_expand_rejects_length_out_of_range()
    test_transcript_hash_is_boundary_sensitive()
    test_server_select_kex_rejects_no_overlap()
    test_parse_hybrid_name_rejects_bad_syntax()
    print("all tests pass")

