import json
import os
import random
import sys

HERE = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(HERE, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as tw  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


# ---------------------------------------------------------------------------
# Vector tests (deterministic, fixed seeds)
# ---------------------------------------------------------------------------

def test_vectors():
    with open(os.path.join(HERE, "vectors.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["vectors"]:
        op = vec["op"]

        if op == "shamir_share":
            got = tw.share_secret(vec["secret"], vec["t"], vec["n"], rng_seed=vec["rng_seed"])
            expected = [tuple(s) for s in vec["expected_shares"]]
            assert got == expected, f"shamir_share mismatch: {got} != {expected}"

        elif op == "shamir_reconstruct":
            shares = [tuple(s) for s in vec["shares"]]
            got = tw.reconstruct_secret(shares)
            assert got == vec["expected_secret"], (
                f"shamir_reconstruct mismatch: {got} != {vec['expected_secret']}"
            )

        elif op == "schnorr_sign_verify":
            msg = _b(vec["msg_hex"])
            R, s = tw.schnorr_sign(vec["private_key"], msg, k_seed=vec["k_seed"])
            assert R == vec["expected_R"], f"schnorr R mismatch: {R} != {vec['expected_R']}"
            assert s == vec["expected_s"], f"schnorr s mismatch: {s} != {vec['expected_s']}"
            ok = tw.schnorr_verify(vec["public_key"], msg, R, s)
            assert ok == vec["verify_ok"], f"schnorr verify mismatch"

        elif op == "dkg":
            result = tw.dkg_simulate(vec["t"], vec["n"], rng_seed=vec["rng_seed"])
            assert result.aggregate_pubkey == vec["expected_pubkey"], (
                f"dkg pubkey mismatch: {result.aggregate_pubkey} != {vec['expected_pubkey']}"
            )
            expected_shares = [tuple(s) for s in vec["expected_agg_shares"]]
            assert result.aggregate_shares == expected_shares, (
                f"dkg shares mismatch: {result.aggregate_shares} != {expected_shares}"
            )

        elif op == "threshold_sign":
            dkg = tw.dkg_simulate(vec["t"], vec["n"], rng_seed=vec["dkg_seed"])
            msg = _b(vec["msg_hex"])
            R, s = tw.threshold_sign(
                msg,
                vec["signer_indices"],
                dkg.aggregate_shares,
                dkg.aggregate_pubkey,
                rng_seed=vec["sign_seed"],
            )
            assert R == vec["expected_R"], f"threshold R mismatch: {R} != {vec['expected_R']}"
            assert s == vec["expected_s"], f"threshold s mismatch: {s} != {vec['expected_s']}"
            ok = tw.schnorr_verify(dkg.aggregate_pubkey, msg, R, s)
            assert ok == vec["verify_ok"], "threshold verify failed"

        else:
            raise ValueError(f"unknown op in vectors.json: {op}")


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

def test_shamir_any_t_subset_reconstructs():
    """Any subset of exactly t shares reconstructs the secret."""
    import itertools
    secret = 77
    t, n = 3, 6
    shares = tw.share_secret(secret, t, n, rng_seed=999)
    for combo in itertools.combinations(shares, t):
        rec = tw.reconstruct_secret(list(combo))
        assert rec == secret, f"reconstruction failed for subset {combo}"


def test_shamir_fewer_than_t_does_not_reconstruct():
    """Fewer than t shares produce a wrong answer with overwhelming probability."""
    secret = 200
    t, n = 4, 6
    shares = tw.share_secret(secret, t, n, rng_seed=888)
    # Try all (t-1)-subsets — none should equal the secret
    import itertools
    for combo in itertools.combinations(shares, t - 1):
        rec = tw.reconstruct_secret(list(combo))
        assert rec != secret, f"unexpected reconstruction with only {t-1} shares"


def test_schnorr_roundtrip_random():
    """Random Schnorr keys/messages verify correctly."""
    rng = random.Random(42)
    for _ in range(20):
        x = rng.randrange(1, tw.Q)
        X = pow(tw.G, x, tw.P)
        msg = bytes(rng.randrange(256) for _ in range(16))
        k_seed = rng.randrange(10000)
        R, s = tw.schnorr_sign(x, msg, k_seed=k_seed)
        assert tw.schnorr_verify(X, msg, R, s)


def test_schnorr_wrong_key_fails():
    """Signature does not verify under a different public key."""
    x = 300
    X_correct = pow(tw.G, x, tw.P)
    X_wrong = pow(tw.G, x + 1, tw.P)
    msg = b"legit transaction"
    R, s = tw.schnorr_sign(x, msg, k_seed=7)
    assert tw.schnorr_verify(X_correct, msg, R, s)
    assert not tw.schnorr_verify(X_wrong, msg, R, s)


def test_threshold_sign_all_t_subsets_verify():
    """Threshold signing works for multiple distinct t-subsets."""
    import itertools
    t, n = 2, 4
    dkg = tw.dkg_simulate(t, n, rng_seed=55)
    msg = b"pay rent"
    indices = list(range(1, n + 1))
    seed = 0
    for combo in itertools.combinations(indices, t):
        R, s = tw.threshold_sign(msg, list(combo), dkg.aggregate_shares, dkg.aggregate_pubkey, rng_seed=seed)
        ok = tw.schnorr_verify(dkg.aggregate_pubkey, msg, R, s)
        assert ok, f"threshold sign failed for signers {combo}"
        seed += 1


def test_dkg_pubkey_consistency():
    """Aggregate pubkey from DKG equals g^(reconstructed_secret)."""
    t, n = 3, 5
    dkg = tw.dkg_simulate(t, n, rng_seed=123)
    agg_secret = tw.reconstruct_secret(dkg.aggregate_shares[:t])
    assert pow(tw.G, agg_secret, tw.P) == dkg.aggregate_pubkey


def test_threshold_sign_tampered_message_fails():
    """A threshold signature does not verify against a different message."""
    t, n = 3, 5
    dkg = tw.dkg_simulate(t, n, rng_seed=77)
    msg = b"original transaction"
    R, s = tw.threshold_sign(msg, [1, 2, 3], dkg.aggregate_shares, dkg.aggregate_pubkey, rng_seed=10)
    assert tw.schnorr_verify(dkg.aggregate_pubkey, msg, R, s)
    assert not tw.schnorr_verify(dkg.aggregate_pubkey, b"tampered transaction", R, s)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_vectors,
        test_shamir_any_t_subset_reconstructs,
        test_shamir_fewer_than_t_does_not_reconstruct,
        test_schnorr_roundtrip_random,
        test_schnorr_wrong_key_fails,
        test_threshold_sign_all_t_subsets_verify,
        test_dkg_pubkey_consistency,
        test_threshold_sign_tampered_message_fails,
    ]
    for t in tests:
        t()
    print("all tests pass")
