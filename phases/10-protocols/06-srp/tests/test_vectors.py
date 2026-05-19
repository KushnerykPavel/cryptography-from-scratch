import json
import os
import random
import sys

THIS_DIR = os.path.dirname(__file__)
CODE_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "code"))
sys.path.insert(0, CODE_DIR)

import main as srp  # noqa: E402


def _i(hex_str: str) -> int:
    return int(hex_str, 16)


def _b(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _load_vectors() -> dict:
    with open(os.path.join(THIS_DIR, "vectors.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def _run_vector(vec: dict) -> None:
    op = vec["op"]
    inputs = vec["inputs"]
    expected = vec["expected"]

    if op == "compute_k":
        N = _i(inputs["N_hex"])
        g = int(inputs["g"])
        got = srp.compute_k(N, g)
        assert got == _i(expected["k_hex"])
        return

    if op == "compute_x":
        got = srp.compute_x(_b(inputs["salt_hex"]), inputs["username"], inputs["password"])
        assert got == _i(expected["x_hex"])
        return

    if op == "compute_v":
        N = _i(inputs["N_hex"])
        g = int(inputs["g"])
        x = _i(inputs["x_hex"])
        got = srp.compute_v(N, g, x)
        assert got == _i(expected["v_hex"])
        return

    if op == "compute_A":
        N = _i(inputs["N_hex"])
        g = int(inputs["g"])
        a = _i(inputs["a_hex"])
        got = srp.compute_A(N, g, a)
        assert got == _i(expected["A_hex"])
        return

    if op == "compute_B":
        N = _i(inputs["N_hex"])
        g = int(inputs["g"])
        k = _i(inputs["k_hex"])
        v = _i(inputs["v_hex"])
        b = _i(inputs["b_hex"])
        got = srp.compute_B(N, g, k, v, b)
        assert got == _i(expected["B_hex"])
        return

    if op == "compute_u":
        N = _i(inputs["N_hex"])
        A = _i(inputs["A_hex"])
        B = _i(inputs["B_hex"])
        got = srp.compute_u(N, A, B)
        assert got == _i(expected["u_hex"])
        return

    if op == "handshake":
        N = _i(inputs["N_hex"])
        g = int(inputs["g"])
        salt = _b(inputs["salt_hex"])
        username = inputs["username"]
        password = inputs["password"]
        a = _i(inputs["a_hex"])
        b = _i(inputs["b_hex"])

        k = srp.compute_k(N, g)
        x = srp.compute_x(salt, username, password)
        v = srp.compute_v(N, g, x)
        A = srp.compute_A(N, g, a)
        B = srp.compute_B(N, g, k, v, b)
        u = srp.compute_u(N, A, B)
        S_c = srp.client_compute_S(N, g, k, x, a, B, u)
        S_s = srp.server_compute_S(N, v, A, u, b)
        assert S_c == S_s
        K = srp.derive_K(N, S_c)
        M1 = srp.compute_M1(N, g, username, salt, A, B, K)
        M2 = srp.compute_M2(N, A, M1, K)

        assert k == _i(expected["k_hex"])
        assert x == _i(expected["x_hex"])
        assert v == _i(expected["v_hex"])
        assert A == _i(expected["A_hex"])
        assert B == _i(expected["B_hex"])
        assert u == _i(expected["u_hex"])
        assert S_c == _i(expected["S_hex"])
        assert K.hex() == expected["K_hex"]
        assert M1.hex() == expected["M1_hex"]
        assert M2.hex() == expected["M2_hex"]
        return

    raise AssertionError(f"unknown vector op: {op}")


def test_vectors() -> None:
    data = _load_vectors()
    for vec in data["vectors"]:
        _run_vector(vec)


def test_end_to_end_multiple_cases() -> None:
    N, g = srp.group_1024()
    rng = random.Random(0)

    for i in range(5):
        username = f"user{i}"
        password = f"pw{i}-x"
        salt = bytes([i]) * 16

        record = srp.register_user(N, g, username, password, salt)
        a = rng.randrange(2, N - 2)
        b = rng.randrange(2, N - 2)

        ch, A = srp.client_start(N, g, username, a)
        sh = srp.server_start(N, g, record, A, b)
        client = srp.client_finish(N, g, ch.username, password, a, sh.salt, A, sh.B)
        server = srp.server_finish(N, g, record, A, sh.B, b, client.M1)

        assert client.K == server.K
        assert srp.compute_M2(N, A, client.M1, client.K) == server.M2


def test_wrong_password_rejected() -> None:
    N, g = srp.group_1024()
    username = "alice"
    password = "pw"
    salt = b"0" * 16
    record = srp.register_user(N, g, username, password, salt)

    a = 12345
    b = 67890
    ch, A = srp.client_start(N, g, username, a)
    sh = srp.server_start(N, g, record, A, b)

    bad = srp.client_finish(N, g, ch.username, "wrong", a, sh.salt, A, sh.B)
    try:
        _ = srp.server_finish(N, g, record, A, sh.B, b, bad.M1)
        raise AssertionError("expected ValueError for wrong password")
    except ValueError:
        pass


def test_reject_A_or_B_mod_N_zero() -> None:
    N, g = srp.group_1024()
    record = srp.RegistrationRecord(username="u", salt=b"1" * 16, v=2)

    try:
        _ = srp.server_start(N, g, record, 0, 5)
        raise AssertionError("expected ValueError for A==0")
    except ValueError:
        pass

    try:
        _ = srp.client_finish(N, g, "u", "p", 5, record.salt, 1, 0)
        raise AssertionError("expected ValueError for B==0")
    except ValueError:
        pass


if __name__ == "__main__":
    test_vectors()
    test_end_to_end_multiple_cases()
    test_wrong_password_rejected()
    test_reject_A_or_B_mod_N_zero()
    print("all tests pass")

