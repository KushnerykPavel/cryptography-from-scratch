from __future__ import annotations

import hmac
import secrets
import time


def leaky_prefix_match_len(expected: bytes, provided: bytes) -> int:
    n = min(len(expected), len(provided))
    for i in range(n):
        if expected[i] != provided[i]:
            return i
    return n


def leaky_equals(expected: bytes, provided: bytes) -> bool:
    if len(expected) != len(provided):
        return False
    return leaky_prefix_match_len(expected, provided) == len(expected)


def ct_eq_bytes(a: bytes, b: bytes) -> bool:
    la = len(a)
    lb = len(b)
    max_len = la if la >= lb else lb

    diff = la ^ lb
    for i in range(max_len):
        ai = a[i] if i < la else 0
        bi = b[i] if i < lb else 0
        diff |= ai ^ bi
    return diff == 0


def stdlib_compare_digest(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def recover_secret_from_prefix_oracle(prefix_oracle, *, secret_len: int) -> bytes:
    guess = bytearray(b"\x00" * secret_len)
    for i in range(secret_len):
        best_score = -1
        best_byte = 0
        for b in range(256):
            guess[i] = b
            score = prefix_oracle(bytes(guess))
            if score > best_score:
                best_score = score
                best_byte = b
                if best_score >= i + 1:
                    break
        guess[i] = best_byte
    return bytes(guess)


def _ns_per_call(fn, *args, iters: int = 50_000) -> int:
    start = time.perf_counter_ns()
    for _ in range(iters):
        fn(*args)
    end = time.perf_counter_ns()
    return (end - start) // iters


def main():
    print("constant-time thinking (educational)")
    print()

    secret = secrets.token_bytes(8)

    def oracle(guess: bytes) -> int:
        return leaky_prefix_match_len(secret, guess)

    recovered = recover_secret_from_prefix_oracle(oracle, secret_len=len(secret))
    print("leaky prefix-oracle demo:")
    print(f"  secret:    {secret.hex()}")
    print(f"  recovered: {recovered.hex()}")
    print(f"  success:   {recovered == secret}")
    print()

    equal = secret
    diff_first = bytes([secret[0] ^ 1]) + secret[1:]
    diff_last = secret[:-1] + bytes([secret[-1] ^ 1])

    print("naive vs constant-time-style comparison (nanoseconds per call, lower is faster):")
    print(f"  leaky_equals(equal):      {_ns_per_call(leaky_equals, secret, equal)}")
    print(f"  leaky_equals(diff_first): {_ns_per_call(leaky_equals, secret, diff_first)}")
    print(f"  leaky_equals(diff_last):  {_ns_per_call(leaky_equals, secret, diff_last)}")
    print(f"  ct_eq_bytes(equal):       {_ns_per_call(ct_eq_bytes, secret, equal)}")
    print(f"  ct_eq_bytes(diff_first):  {_ns_per_call(ct_eq_bytes, secret, diff_first)}")
    print(f"  ct_eq_bytes(diff_last):   {_ns_per_call(ct_eq_bytes, secret, diff_last)}")
    print(f"  compare_digest(equal):    {_ns_per_call(stdlib_compare_digest, secret, equal)}")
    print(f"  compare_digest(diff1):    {_ns_per_call(stdlib_compare_digest, secret, diff_first)}")
    print(f"  compare_digest(diffN):    {_ns_per_call(stdlib_compare_digest, secret, diff_last)}")
    print()

    a = b"abcd"
    b = b"abce"
    assert leaky_equals(a, a) is True
    assert leaky_equals(a, b) is False
    assert ct_eq_bytes(a, a) is True
    assert ct_eq_bytes(a, b) is False
    assert stdlib_compare_digest(a, a) is True
    assert stdlib_compare_digest(a, b) is False


if __name__ == "__main__":
    main()
