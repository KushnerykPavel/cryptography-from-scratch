import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CODE_DIR = ROOT.parent / "code"
sys.path.insert(0, str(CODE_DIR))

import main as m


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def test_vectors():
    vectors_path = ROOT / "vectors.json"
    data = json.loads(vectors_path.read_text(encoding="utf-8"))
    for case in data["vectors"]:
        op = case["op"]

        if op == "x25519_public":
            priv = _b(case["private_hex"])
            expected = _b(case["expected_public_hex"])
            assert m.x25519_public_key(priv) == expected
            continue

        if op == "x25519_dh":
            priv = _b(case["private_hex"])
            peer_pub = _b(case["peer_public_hex"])
            expected = _b(case["expected_shared_hex"])
            assert m.x25519(priv, peer_pub) == expected
            continue

        if op == "hkdf_sha256":
            salt = _b(case["salt_hex"])
            ikm = _b(case["ikm_hex"])
            info = _b(case["info_hex"])
            length = case["length"]
            expected = _b(case["expected_okm_hex"])
            assert m.hkdf_sha256(salt, ikm, info, length) == expected
            continue

        if op == "x3dh_no_opk":
            ik_a_priv = _b(case["ik_a_priv_hex"])
            ek_a_priv = _b(case["ek_a_priv_hex"])
            ik_b_priv = _b(case["ik_b_priv_hex"])
            spk_b_priv = _b(case["spk_b_priv_hex"])

            ik_a_pub = m.x25519_public_key(ik_a_priv)
            ek_a_pub = m.x25519_public_key(ek_a_priv)
            ik_b_pub = m.x25519_public_key(ik_b_priv)
            spk_b_pub = m.x25519_public_key(spk_b_priv)

            sk_a, ad_a = m.x3dh_initiator(ik_a_priv, ek_a_priv, ik_b_pub, spk_b_pub, opk_b_pub=None)
            sk_b, ad_b = m.x3dh_responder(ik_b_priv, spk_b_priv, ik_a_pub, ek_a_pub, opk_b_priv=None)
            assert sk_a == sk_b
            assert ad_a == ad_b

            assert sk_a == _b(case["expected_sk_hex"])
            assert ad_a == _b(case["expected_ad_hex"])
            continue

        if op == "kdf_ck":
            ck = _b(case["ck_hex"])
            next_ck, mk = m.kdf_ck(ck)
            assert next_ck == _b(case["expected_next_ck_hex"])
            assert mk == _b(case["expected_mk_hex"])
            continue

        if op == "double_ratchet_encrypt_once":
            sk = _b(case["sk_hex"])
            bob_ratchet_priv = _b(case["bob_ratchet_priv_hex"])
            bob_ratchet_pub = m.x25519_public_key(bob_ratchet_priv)
            alice_seed = _b(case["alice_seed_hex"])
            bob_seed = _b(case["bob_seed_hex"])
            ad = _b(case["ad_hex"])
            plaintext = _b(case["plaintext_hex"])

            alice_state = m.dr_init_alice(sk, bob_ratchet_pub=bob_ratchet_pub, seed=alice_seed)
            bob_state = m.dr_init_bob(sk, bob_ratchet_priv=bob_ratchet_priv, bob_ratchet_pub=bob_ratchet_pub)

            header, ct, tag = m.dr_encrypt(alice_state, plaintext, ad)
            assert header == _b(case["expected_header_hex"])
            assert ct == _b(case["expected_ciphertext_hex"])
            assert tag == _b(case["expected_tag_hex"])

            recovered = m.dr_decrypt(bob_state, header, ct, tag, ad, seed=bob_seed)
            assert recovered == plaintext
            continue

        if op == "safety_number":
            ik_a_pub = _b(case["ik_a_pub_hex"])
            ik_b_pub = _b(case["ik_b_pub_hex"])
            assert m.safety_number(ik_a_pub, ik_b_pub) == case["expected"]
            continue

        raise AssertionError(f"unknown op: {op}")


def test_x25519_dh_symmetric_for_deterministic_seeds():
    seeds = [b"A", b"B", b"C", b"D"]
    for i in range(len(seeds) - 1):
        a_priv = m.x25519_private_key_from_seed(b"priv:" + seeds[i])
        b_priv = m.x25519_private_key_from_seed(b"priv:" + seeds[i + 1])
        a_pub = m.x25519_public_key(a_priv)
        b_pub = m.x25519_public_key(b_priv)
        assert m.x25519(a_priv, b_pub) == m.x25519(b_priv, a_pub)


def test_aead_rejects_tampering():
    mk = bytes(range(32))
    ad = b"ad"
    ct, tag = m.aead_encrypt(mk, b"hello", ad)
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    try:
        m.aead_decrypt(mk, ct, bad, ad)
        assert False, "expected authentication failure"
    except ValueError as e:
        assert "authentication failed" in str(e)


def test_double_ratchet_out_of_order_roundtrip():
    sk = m.x25519_private_key_from_seed(b"sk")[:32]
    bob_ratchet_priv = m.x25519_private_key_from_seed(b"bob ratchet")
    bob_ratchet_pub = m.x25519_public_key(bob_ratchet_priv)
    ad = b"session-ad"

    alice_state = m.dr_init_alice(sk, bob_ratchet_pub=bob_ratchet_pub, seed=b"alice0")
    bob_state = m.dr_init_bob(sk, bob_ratchet_priv=bob_ratchet_priv, bob_ratchet_pub=bob_ratchet_pub)

    msgs = [b"m0", b"m1", b"m2"]
    packets = [m.dr_encrypt(alice_state, msg, ad) for msg in msgs]

    order = [0, 2, 1]
    out = []
    for idx in order:
        header, ct, tag = packets[idx]
        out.append(m.dr_decrypt(bob_state, header, ct, tag, ad, seed=b"bob1"))

    assert sorted(out) == sorted(msgs)


def test_prekey_bundle_consumes_opk():
    server = m.MiniSignalServer()
    bob = m.MiniSignalClient("bob", server, seed=b"BobTest")
    bob.publish_prekeys()

    b1 = server.fetch_prekey_bundle("bob")
    b2 = server.fetch_prekey_bundle("bob")
    assert (b1.opk_id is None) == (b1.opk_pub is None)
    assert (b2.opk_id is None) == (b2.opk_pub is None)
    assert b1.opk_id != b2.opk_id


def test_tofu_rejects_identity_change():
    server = m.MiniSignalServer()
    alice = m.MiniSignalClient("alice", server, seed=b"AliceTOFU")
    bob1 = m.MiniSignalClient("bob", server, seed=b"BobTOFU/1")
    bob2 = m.MiniSignalClient("bob", server, seed=b"BobTOFU/2")

    alice.publish_prekeys()
    bob1.publish_prekeys()

    _ = alice.initiate_session("bob", b"hi", seed=b"S0")
    bob2.publish_prekeys()  # overwrite bundle with a different identity key
    try:
        alice.initiate_session("bob", b"hi again", seed=b"S1")
        assert False, "expected identity key change to be rejected"
    except ValueError as e:
        assert "identity key changed" in str(e)


def _run_all():
    test_vectors()
    test_x25519_dh_symmetric_for_deterministic_seeds()
    test_aead_rejects_tampering()
    test_double_ratchet_out_of_order_roundtrip()
    test_prekey_bundle_consumes_opk()
    test_tofu_rejects_identity_change()
    print("all tests pass")


if __name__ == "__main__":
    _run_all()

