import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as tw  # noqa: E402


def call(vector):
    op = vector["op"]
    prime = vector["prime"]

    if op == "shamir_split_reconstruct":
        shares = tw.shamir_split(vector["secret"], vector["t"], vector["n"], prime)
        rec = tw.shamir_reconstruct(shares[: vector["t"]], prime)
        return {"shares": shares, "secret": rec}

    if op == "shamir_reconstruct":
        shares = [tuple(s) for s in vector["shares"]]
        return tw.shamir_reconstruct(shares, prime)

    if op == "dkg_round1":
        coeffs, comms = tw.dkg_round1(vector["party_id"], vector["n"], vector["t"], prime)
        return {"coeffs": coeffs, "commitments": comms}

    if op == "dkg_round2":
        other_shares = [tuple(s) for s in vector["other_shares"]]
        return tw.dkg_round2(vector["party_id"], other_shares, prime)

    if op == "threshold_sign_round1":
        nonce, commitment = tw.threshold_sign_round1(vector["party_id"], prime)
        return {"nonce": nonce, "commitment": commitment}

    if op == "threshold_sign_verify":
        signing_parties = vector["signing_parties"]
        sk_shares = vector["sk_shares"]
        message = bytes.fromhex(vector["message_hex"])

        nonces = {}
        nonce_commitments = {}
        for pid in signing_parties:
            ns, nc = tw.threshold_sign_round1(pid, prime)
            nonces[pid] = ns
            nonce_commitments[pid] = nc

        agg_nonce = 1
        for nc in nonce_commitments.values():
            agg_nonce = agg_nonce * nc % prime

        partial_sigs = []
        for pid in signing_parties:
            ps = tw.threshold_sign_round2(
                pid, sk_shares[pid - 1], nonces[pid], agg_nonce, message, prime
            )
            partial_sigs.append(ps)

        agg_sig = tw.threshold_aggregate_sigs(partial_sigs, prime)

        signing_pk = 1
        for pid in signing_parties:
            signing_pk = signing_pk * pow(tw._TW_G, sk_shares[pid - 1], prime) % prime

        valid = tw.threshold_verify(signing_pk, agg_nonce, message, agg_sig, prime)
        return {
            "agg_nonce": agg_nonce,
            "partial_sigs": partial_sigs,
            "agg_sig": agg_sig,
            "signing_pk": signing_pk,
            "valid": valid,
        }

    if op == "threshold_verify":
        message = bytes.fromhex(vector["message_hex"])
        return tw.threshold_verify(
            vector["agg_pk"], vector["agg_nonce"], message, vector["sig"], prime
        )

    raise AssertionError(f"unknown op: {op}")


def test_vectors():
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    for vector in vectors:
        op = vector["op"]
        result = call(vector)

        if op == "shamir_split_reconstruct":
            assert result["shares"] == [tuple(s) for s in vector["expected_shares"]], (
                f"[{vector['label']}] shares mismatch"
            )
            assert result["secret"] == vector["expected_secret"], (
                f"[{vector['label']}] reconstructed secret mismatch"
            )

        elif op == "shamir_reconstruct":
            assert result == vector["expected"], (
                f"[{vector['label']}] reconstruct={result}, expected={vector['expected']}"
            )

        elif op == "dkg_round1":
            assert result["coeffs"] == vector["expected_coeffs"], (
                f"[{vector['label']}] coeffs mismatch"
            )
            assert result["commitments"] == vector["expected_commitments"], (
                f"[{vector['label']}] commitments mismatch"
            )

        elif op == "dkg_round2":
            assert result == vector["expected_sk_share"], (
                f"[{vector['label']}] sk_share={result}, expected={vector['expected_sk_share']}"
            )

        elif op == "threshold_sign_round1":
            assert result["nonce"] == vector["expected_nonce"], (
                f"[{vector['label']}] nonce mismatch"
            )
            assert result["commitment"] == vector["expected_commitment"], (
                f"[{vector['label']}] commitment mismatch"
            )

        elif op == "threshold_sign_verify":
            assert result["agg_nonce"] == vector["expected_agg_nonce"]
            assert result["partial_sigs"] == vector["expected_partial_sigs"]
            assert result["agg_sig"] == vector["expected_agg_sig"]
            assert result["signing_pk"] == vector["expected_signing_pk"]
            assert result["valid"] == vector["expected_valid"]

        elif op == "threshold_verify":
            assert result == vector["expected"], (
                f"[{vector['label']}] verify={result}, expected={vector['expected']}"
            )


def test_shamir_any_t_subset():
    """Any t-subset of n shares reconstructs the secret."""
    prime = tw._TW_N
    secret = 42
    t, n = 3, 5
    shares = tw.shamir_split(secret, t, n, prime)
    # test all C(5,3) = 10 subsets
    from itertools import combinations
    for subset in combinations(shares, t):
        rec = tw.shamir_reconstruct(list(subset), prime)
        assert rec == secret, f"subset {subset} gave {rec}"


def test_shamir_below_threshold_fails():
    """Fewer than t shares must NOT reconstruct the secret (with high probability)."""
    prime = tw._TW_N
    secret = 9999
    t, n = 3, 5
    shares = tw.shamir_split(secret, t, n, prime)
    # Only 2 shares (below threshold of 3) should give a wrong answer
    rec = tw.shamir_reconstruct(shares[:2], prime)
    assert rec != secret, "below-threshold reconstruction should not equal secret"


def test_threshold_sign_wrong_message():
    """A valid signature should not verify under a different message."""
    prime = tw._TW_N
    ORDER = tw._TW_ORDER
    # Build minimal sk_shares for 2 parties
    sk_shares = [100, 200]
    signing_parties = [1, 2]
    nonces = {}
    nonce_comms = {}
    for pid in signing_parties:
        ns, nc = tw.threshold_sign_round1(pid, prime)
        nonces[pid] = ns
        nonce_comms[pid] = nc

    agg_nonce = 1
    for nc in nonce_comms.values():
        agg_nonce = agg_nonce * nc % prime

    message = b"correct message"
    partial_sigs = [
        tw.threshold_sign_round2(pid, sk_shares[pid - 1], nonces[pid], agg_nonce, message, prime)
        for pid in signing_parties
    ]
    agg_sig = tw.threshold_aggregate_sigs(partial_sigs, prime)

    signing_pk = 1
    for pid in signing_parties:
        signing_pk = signing_pk * pow(tw._TW_G, sk_shares[pid - 1], prime) % prime

    assert tw.threshold_verify(signing_pk, agg_nonce, message, agg_sig, prime)
    assert not tw.threshold_verify(signing_pk, agg_nonce, b"wrong message", agg_sig, prime)


def test_dkg_final_pubkey():
    """dkg_final_pubkey returns product of all commitment[0] values."""
    prime = tw._TW_N
    all_comms = []
    for pid in range(1, 4):
        _, comms = tw.dkg_round1(pid, 3, 2, prime)
        all_comms.append(comms)
    pk = tw.dkg_final_pubkey(all_comms, prime)
    expected = 1
    for comms in all_comms:
        expected = expected * comms[0] % prime
    assert pk == expected


if __name__ == "__main__":
    test_vectors()
    test_shamir_any_t_subset()
    test_shamir_below_threshold_fails()
    test_threshold_sign_wrong_message()
    test_dkg_final_pubkey()
    print("all tests pass")
