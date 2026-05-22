import json
import sys
from pathlib import Path

LESSON = Path(__file__).resolve().parents[1]
VECTORS_PATH = LESSON / "tests" / "vectors.json"

sys.path.insert(0, str(LESSON / "code"))
import main as vdf  # noqa: E402


def call(vector: dict):
    op = vector["op"]

    if op == "vdf_eval":
        return vdf.vdf_eval(vector["x"], vector["T"], vector["N"])

    if op == "vdf_challenge":
        return vdf.vdf_challenge(vector["x"], vector["y"], vector["T"])

    if op == "vdf_verify":
        return vdf.vdf_verify(
            vector["x"], vector["T"], vector["y"], vector["pi"], vector["N"]
        )

    raise AssertionError(f"unknown op: {op}")


def test_vectors() -> None:
    data = json.loads(VECTORS_PATH.read_text())
    for vec in data["vectors"]:
        op = vec["op"]
        result = call(vec)

        if op == "vdf_eval":
            assert result == vec["expected_y"], (
                f"vdf_eval mismatch for x={vec['x']}, T={vec['T']}: "
                f"got {result}, want {vec['expected_y']}"
            )
        elif op == "vdf_challenge":
            assert result == vec["expected_l"], (
                f"vdf_challenge mismatch for x={vec['x']}, T={vec['T']}: "
                f"got {result}, want {vec['expected_l']}"
            )
        elif op == "vdf_verify":
            assert result == vec["expected"], (
                f"vdf_verify mismatch for x={vec['x']}, T={vec['T']}: "
                f"got {result}, want {vec['expected']}"
            )


def test_eval_with_proof_roundtrip() -> None:
    """eval_with_proof output matches vdf_eval and proof verifies."""
    N = vdf.vdf_setup()
    for x, T in [(2, 10), (3, 8), (5, 12), (7, 16)]:
        y_direct = vdf.vdf_eval(x, T, N)
        y_proof, pi = vdf.vdf_eval_with_proof(x, T, N)
        assert y_direct == y_proof, f"y mismatch x={x} T={T}"
        assert vdf.vdf_verify(x, T, y_proof, pi, N), f"proof failed x={x} T={T}"


def test_verify_rejects_wrong_pi() -> None:
    """A wrong proof pi should cause verification to fail."""
    N = vdf.vdf_setup()
    x, T = 3, 10
    y, pi = vdf.vdf_eval_with_proof(x, T, N)
    assert not vdf.vdf_verify(x, T, y, pi + 1, N), "should reject pi+1"
    assert not vdf.vdf_verify(x, T, y, pi - 1, N), "should reject pi-1"


def test_verify_rejects_wrong_y() -> None:
    """A tampered y should cause verification to fail."""
    N = vdf.vdf_setup()
    x, T = 5, 10
    y, pi = vdf.vdf_eval_with_proof(x, T, N)
    assert not vdf.vdf_verify(x, T, y + 1, pi, N), "should reject y+1"
    assert not vdf.vdf_verify(x, T, y * 2 % N, pi, N), "should reject 2y"


def test_time_lock_roundtrip() -> None:
    """Encrypt then solve VDF and decrypt recovers the plaintext."""
    N = vdf.vdf_setup()
    T = 12
    plaintext = b"secret message!"
    enc_x, enc_T, ciphertext = vdf.vdf_time_lock_encrypt(plaintext, T, N)
    assert enc_T == T
    assert ciphertext != plaintext
    solved_y = vdf.vdf_eval(enc_x, enc_T, N)
    recovered = vdf.vdf_time_lock_decrypt(solved_y, ciphertext)
    assert recovered == plaintext, f"got {recovered!r}"


def test_time_lock_wrong_y_fails() -> None:
    """Using wrong y to decrypt produces garbage (not the original message)."""
    N = vdf.vdf_setup()
    T = 10
    plaintext = b"hello"
    enc_x, enc_T, ciphertext = vdf.vdf_time_lock_encrypt(plaintext, T, N)
    wrong_y = vdf.vdf_eval(enc_x + 1, enc_T, N)
    wrong_result = vdf.vdf_time_lock_decrypt(wrong_y, ciphertext)
    assert wrong_result != plaintext, "wrong y should not decrypt correctly"


if __name__ == "__main__":
    test_vectors()
    test_eval_with_proof_roundtrip()
    test_verify_rejects_wrong_pi()
    test_verify_rejects_wrong_y()
    test_time_lock_roundtrip()
    test_time_lock_wrong_y_fails()
    print("all tests pass")
