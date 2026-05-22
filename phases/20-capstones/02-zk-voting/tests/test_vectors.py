import json
import os
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as zk  # noqa: E402


def test_vectors():
    """Run all deterministic vectors from vectors.json."""
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "elgamal_keygen":
            h = pow(zk.G, vec["x"], zk.P)
            assert h == vec["expected_h"], f"keygen vector failed: got {h}"

        elif op == "elgamal_encrypt":
            ct, _ = zk.elgamal_encrypt(vec["vote"], vec["pk"], r=vec["r"])
            assert ct.c1 == vec["expected_c1"], f"encrypt c1 failed: {ct.c1} != {vec['expected_c1']}"
            assert ct.c2 == vec["expected_c2"], f"encrypt c2 failed: {ct.c2} != {vec['expected_c2']}"

        elif op == "elgamal_decrypt":
            ct = zk.Ciphertext(vec["c1"], vec["c2"])
            result = zk.elgamal_decrypt(ct, vec["sk"], max_tally=10)
            assert result == vec["expected_vote"], f"decrypt failed: got {result}"

        elif op == "homomorphic_tally":
            cts = [zk.Ciphertext(c["c1"], c["c2"]) for c in vec["ciphertexts"]]
            tally_ct = zk.homomorphic_tally(cts)
            assert tally_ct.c1 == vec["expected_tally_c1"], (
                f"tally c1 failed: {tally_ct.c1} != {vec['expected_tally_c1']}"
            )
            assert tally_ct.c2 == vec["expected_tally_c2"], (
                f"tally c2 failed: {tally_ct.c2} != {vec['expected_tally_c2']}"
            )
            result = zk.elgamal_decrypt(tally_ct, vec["sk"], max_tally=len(cts))
            assert result == vec["expected_tally_value"], f"tally value failed: got {result}"

        elif op == "verify_vote_proof":
            ct = zk.Ciphertext(vec["c1"], vec["c2"])
            p = vec["proof"]
            proof = zk.OrProof(
                a0=p["a0"], b0=p["b0"],
                a1=p["a1"], b1=p["b1"],
                c0=p["c0"], c1=p["c1_branch"],
                z0=p["z0"], z1=p["z1"],
            )
            result = zk.verify_vote_proof(ct, proof, vec["pk"])
            assert result == vec["expected_valid"], (
                f"verify_vote_proof failed for '{vec['note']}': got {result}"
            )

        else:
            raise ValueError(f"unknown op in vectors.json: {op}")


def test_elgamal_encrypt_rejects_invalid_vote():
    """elgamal_encrypt must raise ValueError for votes outside {0, 1}."""
    sk, pk = 7, pow(zk.G, 7, zk.P)
    try:
        zk.elgamal_encrypt(2, pk)
        raise AssertionError("expected ValueError for vote=2")
    except ValueError:
        pass
    try:
        zk.elgamal_encrypt(-1, pk)
        raise AssertionError("expected ValueError for vote=-1")
    except ValueError:
        pass


def test_elgamal_roundtrip_both_votes():
    """Encrypt then decrypt 0 and 1 must recover original vote."""
    sk, pk = 42, pow(zk.G, 42, zk.P)
    for vote in (0, 1):
        ct, _ = zk.elgamal_encrypt(vote, pk)
        result = zk.elgamal_decrypt(ct, sk, max_tally=2)
        assert result == vote, f"roundtrip failed for vote={vote}: got {result}"


def test_homomorphic_tally_sum():
    """Tally of votes [0, 0, 1] must equal 1; tally of [1, 1, 1] must equal 3."""
    sk, pk = 13, pow(zk.G, 13, zk.P)

    def enc(v, r):
        ct, _ = zk.elgamal_encrypt(v, pk, r=r)
        return ct

    # 0+0+1 = 1
    tally1 = zk.homomorphic_tally([enc(0, 5), enc(0, 7), enc(1, 11)])
    assert zk.elgamal_decrypt(tally1, sk, max_tally=3) == 1

    # 1+1+1 = 3 — need max_tally=3
    tally3 = zk.homomorphic_tally([enc(1, 3), enc(1, 17), enc(1, 19)])
    assert zk.elgamal_decrypt(tally3, sk, max_tally=3) == 3


def test_prove_and_verify_vote_0():
    """prove_vote / verify_vote_proof round-trips for vote=0."""
    sk, pk = 37, pow(zk.G, 37, zk.P)
    ct, r = zk.elgamal_encrypt(0, pk)
    proof = zk.prove_vote(ct, 0, r, pk)
    assert zk.verify_vote_proof(ct, proof, pk), "valid proof for vote=0 rejected"


def test_prove_and_verify_vote_1():
    """prove_vote / verify_vote_proof round-trips for vote=1."""
    sk, pk = 37, pow(zk.G, 37, zk.P)
    ct, r = zk.elgamal_encrypt(1, pk)
    proof = zk.prove_vote(ct, 1, r, pk)
    assert zk.verify_vote_proof(ct, proof, pk), "valid proof for vote=1 rejected"


def test_tampered_proof_rejected():
    """A valid proof for vote=0 must not verify against a ciphertext encrypting vote=2."""
    sk, pk = 37, pow(zk.G, 37, zk.P)
    # Make a valid proof for vote=0
    ct0, r0 = zk.elgamal_encrypt(0, pk)
    proof0 = zk.prove_vote(ct0, 0, r0, pk)

    # Craft a ciphertext for vote=2 (bypasses the guard in elgamal_encrypt)
    bad_r = 3
    bad_c1 = pow(zk.G, bad_r, zk.P)
    bad_c2 = (pow(pk, bad_r, zk.P) * pow(zk.G, 2, zk.P)) % zk.P
    bad_ct = zk.Ciphertext(bad_c1, bad_c2)

    assert not zk.verify_vote_proof(bad_ct, proof0, pk), (
        "tampered ballot (vote=2) was incorrectly accepted"
    )


def test_verify_board_all_valid():
    """verify_board returns True for a board of properly-voted ballots."""
    sk, pk = 23, pow(zk.G, 23, zk.P)
    board = []
    for vote in (1, 0, 1):
        zk.submit_ballot(board, "voter", vote, pk)
    assert zk.verify_board(board, pk)


def test_verify_board_rejects_tampered_entry():
    """verify_board returns False when one ballot has a mismatched ciphertext."""
    sk, pk = 23, pow(zk.G, 23, zk.P)
    board = []
    zk.submit_ballot(board, "alice", 1, pk)
    zk.submit_ballot(board, "bob", 0, pk)

    # Swap the ciphertext of bob's entry with a fresh ciphertext
    extra_ct, _ = zk.elgamal_encrypt(1, pk)
    board[1] = zk.BallotEntry(voter_id="bob", ct=extra_ct, proof=board[1].proof)

    assert not zk.verify_board(board, pk), (
        "tampered board entry was not rejected"
    )


if __name__ == "__main__":
    tests = [
        test_vectors,
        test_elgamal_encrypt_rejects_invalid_vote,
        test_elgamal_roundtrip_both_votes,
        test_homomorphic_tally_sum,
        test_prove_and_verify_vote_0,
        test_prove_and_verify_vote_1,
        test_tampered_proof_rejected,
        test_verify_board_all_valid,
        test_verify_board_rejects_tampered_entry,
    ]
    for t in tests:
        t()
    print("all tests pass")
