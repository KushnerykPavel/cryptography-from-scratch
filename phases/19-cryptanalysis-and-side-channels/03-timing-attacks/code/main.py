"""
Timing-attack demo (educational).

Run:
  python3 code/main.py

This lesson shows how early-exit comparisons leak secret prefixes via timing,
then shows a constant-time comparison and a simple simulated timing attack that
recovers a secret token one byte at a time.
"""

from __future__ import annotations

from typing import Callable, Iterable, Tuple


def insecure_prefix_compare(a: bytes, b: bytes) -> Tuple[bool, int]:
    n = min(len(a), len(b))
    steps = 0
    for i in range(n):
        steps += 1
        if a[i] != b[i]:
            return False, steps
    steps += 1
    return len(a) == len(b), steps


def constant_time_compare(a: bytes, b: bytes) -> Tuple[bool, int]:
    steps = 0
    if len(a) != len(b):
        n = max(len(a), len(b))
        aa = a.ljust(n, b"\x00")
        bb = b.ljust(n, b"\x00")
    else:
        aa, bb = a, b
    diff = 0
    for x, y in zip(aa, bb):
        steps += 1
        diff |= x ^ y
    return diff == 0 and (len(a) == len(b)), steps


def make_timing_oracle(secret: bytes, compare_fn: Callable[[bytes, bytes], Tuple[bool, int]]) -> Callable[[bytes], int]:
    def oracle(guess: bytes) -> int:
        _, steps = compare_fn(secret, guess)
        return steps

    return oracle


def recover_secret_from_timing_oracle(
    oracle: Callable[[bytes], int], length: int, alphabet: Iterable[int]
) -> bytes:
    guess = bytearray(b"\x00" * length)
    for i in range(length):
        best_b = None
        best_score = -1
        for b in alphabet:
            guess[i] = b
            score = oracle(bytes(guess))
            if score > best_score:
                best_score = score
                best_b = b
        if best_b is None:
            raise RuntimeError("no candidate byte found")
        guess[i] = best_b
    return bytes(guess)


def main():
    secret = b"SECRET_TOKEN"

    print("=== Step 1: Early-exit comparisons leak prefix length ===")
    g1 = b"SXXXX"
    g2 = b"SEXXX"
    ok1, t1 = insecure_prefix_compare(secret[:5], g1)
    ok2, t2 = insecure_prefix_compare(secret[:5], g2)
    print("guess1_ok:", ok1, "steps:", t1)
    print("guess2_ok:", ok2, "steps:", t2)

    print("=== Step 2: Constant-time comparisons remove the signal ===")
    ok1c, t1c = constant_time_compare(secret[:5], g1)
    ok2c, t2c = constant_time_compare(secret[:5], g2)
    print("guess1_ok:", ok1c, "steps:", t1c)
    print("guess2_ok:", ok2c, "steps:", t2c)

    print("=== Step 3: Recover a secret with a timing oracle (simulated) ===")
    alphabet = list(range(ord("A"), ord("Z") + 1)) + [ord("_")]
    oracle = make_timing_oracle(secret, insecure_prefix_compare)
    recovered = recover_secret_from_timing_oracle(oracle, len(secret), alphabet)
    print("recovered:", recovered)


if __name__ == "__main__":
    main()
