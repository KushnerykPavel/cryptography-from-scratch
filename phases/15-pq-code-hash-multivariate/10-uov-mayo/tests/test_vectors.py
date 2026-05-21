import json
import os
import random
import sys


THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.normpath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as lesson  # noqa: E402


def _load_vectors():
    path = os.path.join(THIS_DIR, "vectors.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "vectors" not in data or not isinstance(data["vectors"], list):
        raise ValueError("vectors.json must contain a list at key 'vectors'")
    return data["vectors"]


def _run_vector(vec):
    op = vec["op"]

    if op == "inv_modp":
        got = lesson.inv_modp(vec["a"], vec["p"])
        assert got == vec["expected"]
        return

    if op == "solve_linear_system_modp":
        got = lesson.solve_linear_system_modp(vec["matrix"], vec["rhs"], vec["p"])
        assert got == vec["expected"]
        return

    if op == "hash_to_field_vec":
        got = lesson.hash_to_field_vec(
            bytes.fromhex(vec["message_hex"]),
            vec["p"],
            vec["length"],
            domain=vec["domain"].encode("ascii"),
        )
        assert got == vec["expected"]
        return

    if op == "ov_eval_random":
        ov_map = lesson.ov_map_random(
            p=vec["p"],
            v=vec["v"],
            o=vec["o"],
            m=vec["m"],
            rng=random.Random(vec["map_seed"]),
        )
        got = lesson.ov_eval(ov_map, vec["x"])
        assert got == vec["expected"]
        return

    if op == "ov_polar_random":
        ov_map = lesson.ov_map_random(
            p=vec["p"],
            v=vec["v"],
            o=vec["o"],
            m=vec["m"],
            rng=random.Random(vec["map_seed"]),
        )
        got = lesson.ov_polar(ov_map, vec["x"], vec["y"])
        assert got == vec["expected"]
        return

    if op == "uov_sign":
        keypair = lesson.uov_keygen(
            seed=vec["key_seed"],
            p=vec["p"],
            v=vec["v"],
            o=vec["o"],
        )
        message = bytes.fromhex(vec["message_hex"])
        signature = lesson.uov_sign(keypair, message, rng_seed=vec["rng_seed"])
        assert signature == vec["expected"]
        assert lesson.uov_verify(keypair, message, signature)
        return

    if op == "mayo_sign":
        ov_map = lesson.ov_map_random(
            p=vec["p"],
            v=vec["v"],
            o=vec["o"],
            m=vec["m"],
            rng=random.Random(vec["map_seed"]),
        )
        message = bytes.fromhex(vec["message_hex"])
        signature = lesson.mayo_sign(
            ov_map, message, k=vec["k"], rng_seed=vec["rng_seed"], max_attempts=2048
        )
        assert signature == vec["expected"]
        assert lesson.mayo_verify(ov_map, message, k=vec["k"], signature_flat=signature)
        return

    raise ValueError(f"unknown op: {op}")


def test_vectors():
    for vec in _load_vectors():
        _run_vector(vec)


def test_solve_linear_system_roundtrip():
    rng = random.Random(0)
    p = 31
    for _ in range(20):
        n = 4
        while True:
            matrix = [[rng.randrange(p) for _ in range(n)] for _ in range(n)]
            inv = lesson.mat_inverse(matrix, p)
            if inv is not None:
                break
        x = [rng.randrange(p) for _ in range(n)]
        rhs = lesson.mat_vec_mul(matrix, x, p)
        got = lesson.solve_linear_system_modp(matrix, rhs, p)
        assert got == x


def test_ov_polar_is_bilinear():
    p = 31
    ov_map = lesson.ov_map_random(p=p, v=3, o=2, m=3, rng=random.Random(123))
    x = [1, 2, 3, 4, 5]
    y1 = [6, 7, 8, 9, 10]
    y2 = [10, 9, 8, 7, 6]

    left = lesson.ov_polar(ov_map, x, lesson.vec_add(y1, y2, p))
    right = lesson.vec_add(lesson.ov_polar(ov_map, x, y1), lesson.ov_polar(ov_map, x, y2), p)
    assert left == right


def test_uov_rejects_modified_signature():
    kp = lesson.uov_keygen(seed=2026, p=31, v=4, o=3)
    message = b"attack at dawn"
    sig = lesson.uov_sign(kp, message, rng_seed=424242)
    assert lesson.uov_verify(kp, message, sig)

    tampered = sig[:]
    tampered[0] = (tampered[0] + 1) % kp.p
    assert not lesson.uov_verify(kp, message, tampered)


def test_mayo_rejects_wrong_length():
    ov_map = lesson.ov_map_random(p=31, v=4, o=2, m=4, rng=random.Random(9001))
    message = b"attack at dawn"
    sig = lesson.mayo_sign(ov_map, message, k=3, rng_seed=777, max_attempts=2048)
    assert lesson.mayo_verify(ov_map, message, k=3, signature_flat=sig)

    assert not lesson.mayo_verify(ov_map, message, k=3, signature_flat=sig[:-1])


if __name__ == "__main__":
    test_vectors()
    test_solve_linear_system_roundtrip()
    test_ov_polar_is_bilinear()
    test_uov_rejects_modified_signature()
    test_mayo_rejects_wrong_length()
    print("all tests pass")

