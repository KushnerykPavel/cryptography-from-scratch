"""
BLAKE2 & BLAKE3 — runnable lesson script.

Run:
  python3 code/main.py

This script demonstrates:
- BLAKE2s hashing and keyed hashing via the Python stdlib (`hashlib`)
- the RFC 7693 BLAKE2s self-test digest ("hash of hashes")
- a from-scratch (stdlib-only) BLAKE3 implementation: hash, XOF, keyed_hash, derive_key
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


def _hex(b: bytes) -> str:
    return b.hex()


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _ror32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _words_from_le_bytes_32(b: bytes, count: int) -> list[int]:
    needed = count * 4
    if len(b) < needed:
        b = b + b"\x00" * (needed - len(b))
    return list(struct.unpack("<" + ("I" * count), b[:needed]))


def _le_bytes_from_words_32(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", _u32(w)) for w in words)


def blake2s_256(data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=32).digest()


def _rfc7693_selftest_seq(length: int, seed: int) -> bytes:
    a = _u32(0xDEAD4BAD * seed)
    b = 1
    out = bytearray()
    for _ in range(length):
        t = _u32(a + b)
        a = b
        b = t
        out.append((t >> 24) & 0xFF)
    return bytes(out)


def blake2s_rfc7693_selftest_digest() -> bytes:
    md_lens = [16, 20, 28, 32]
    in_lens = [0, 3, 64, 65, 255, 1024]

    ctx = hashlib.blake2s(digest_size=32)
    for outlen in md_lens:
        for inlen in in_lens:
            msg = _rfc7693_selftest_seq(inlen, seed=inlen)
            ctx.update(hashlib.blake2s(msg, digest_size=outlen).digest())

            key = _rfc7693_selftest_seq(outlen, seed=outlen)
            ctx.update(hashlib.blake2s(msg, digest_size=outlen, key=key).digest())
    return ctx.digest()


BLOCK_LEN = 64
CHUNK_LEN = 1024
OUT_LEN = 32

IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

MSG_SCHEDULE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
]


def _blake3_g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = _u32(state[a] + state[b] + mx)
    state[d] = _ror32(state[d] ^ state[a], 16)
    state[c] = _u32(state[c] + state[d])
    state[b] = _ror32(state[b] ^ state[c], 12)
    state[a] = _u32(state[a] + state[b] + my)
    state[d] = _ror32(state[d] ^ state[a], 8)
    state[c] = _u32(state[c] + state[d])
    state[b] = _ror32(state[b] ^ state[c], 7)


def _blake3_round(state: list[int], msg: list[int], schedule: list[int]) -> None:
    _blake3_g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]])
    _blake3_g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]])
    _blake3_g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]])
    _blake3_g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]])

    _blake3_g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]])
    _blake3_g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]])
    _blake3_g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]])
    _blake3_g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]])


def blake3_compress(
    chaining_value_words: list[int],
    block_words: list[int],
    block_len: int,
    counter: int,
    flags: int,
) -> list[int]:
    state = list(chaining_value_words) + IV[:4] + [
        _u32(counter),
        _u32(counter >> 32),
        _u32(block_len),
        _u32(flags),
    ]

    for schedule in MSG_SCHEDULE:
        _blake3_round(state, block_words, schedule)

    for i in range(8):
        state[i] = _u32(state[i] ^ state[i + 8])
        state[i + 8] = _u32(state[i + 8] ^ chaining_value_words[i])
    return state


@dataclass(frozen=True)
class _Blake3Output:
    input_cv_words: list[int]
    block_bytes: bytes
    block_len: int
    counter: int
    flags: int

    def _block_words(self) -> list[int]:
        return _words_from_le_bytes_32(self.block_bytes, 16)

    def chaining_value_words(self) -> list[int]:
        words = blake3_compress(
            self.input_cv_words,
            self._block_words(),
            self.block_len,
            self.counter,
            self.flags,
        )
        return words[:8]

    def root_output_bytes(self, out_len: int) -> bytes:
        if out_len < 0:
            raise ValueError("out_len must be non-negative")
        out = bytearray()
        output_block_counter = 0
        block_words = self._block_words()
        while len(out) < out_len:
            words = blake3_compress(
                self.input_cv_words,
                block_words,
                self.block_len,
                output_block_counter,
                self.flags | ROOT,
            )
            out.extend(_le_bytes_from_words_32(words))
            output_block_counter += 1
        return bytes(out[:out_len])


class _Blake3ChunkState:
    def __init__(self, key_words: list[int], chunk_counter: int, flags: int):
        self._key_words = key_words
        self._chunk_counter = chunk_counter
        self._flags = flags
        self._cv_words = list(key_words)
        self._block = bytearray(b"\x00" * BLOCK_LEN)
        self._block_len = 0
        self._blocks_compressed = 0

    def length(self) -> int:
        return self._blocks_compressed * BLOCK_LEN + self._block_len

    def _start_flag(self) -> int:
        return CHUNK_START if self._blocks_compressed == 0 else 0

    def update(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            if self._block_len == BLOCK_LEN:
                block_words = _words_from_le_bytes_32(bytes(self._block), 16)
                words = blake3_compress(
                    self._cv_words,
                    block_words,
                    BLOCK_LEN,
                    self._chunk_counter,
                    self._flags | self._start_flag(),
                )
                self._cv_words = words[:8]
                self._blocks_compressed += 1
                self._block_len = 0
                self._block[:] = b"\x00" * BLOCK_LEN

            want = BLOCK_LEN - self._block_len
            take = min(want, len(data) - offset)
            self._block[self._block_len : self._block_len + take] = data[offset : offset + take]
            self._block_len += take
            offset += take

    def output(self) -> _Blake3Output:
        output_flags = self._flags | self._start_flag() | CHUNK_END
        return _Blake3Output(
            input_cv_words=list(self._cv_words),
            block_bytes=bytes(self._block),
            block_len=self._block_len,
            counter=self._chunk_counter,
            flags=output_flags,
        )


def _blake3_parent_output(left_cv_words: list[int], right_cv_words: list[int], key_words: list[int], flags: int) -> _Blake3Output:
    block_words = list(left_cv_words) + list(right_cv_words)
    return _Blake3Output(
        input_cv_words=list(key_words),
        block_bytes=_le_bytes_from_words_32(block_words),
        block_len=BLOCK_LEN,
        counter=0,
        flags=flags | PARENT,
    )


def _blake3_add_chunk_cv(cv_stack: list[list[int]], new_cv_words: list[int], total_chunks: int, key_words: list[int], flags: int) -> None:
    chunk_counter = total_chunks
    while (chunk_counter & 1) == 0:
        left_cv_words = cv_stack.pop()
        new_cv_words = _blake3_parent_output(left_cv_words, new_cv_words, key_words, flags).chaining_value_words()
        chunk_counter >>= 1
    cv_stack.append(new_cv_words)


def blake3_hash(data: bytes, out_len: int = OUT_LEN) -> bytes:
    return blake3_hash_xof(data, out_len=out_len)


def blake3_hash_xof(data: bytes, out_len: int = OUT_LEN) -> bytes:
    key_words = list(IV)
    flags = 0
    return _blake3_hash_xof(key_words, flags, data, out_len)


def blake3_keyed_hash(key: bytes, data: bytes, out_len: int = OUT_LEN) -> bytes:
    if len(key) != OUT_LEN:
        raise ValueError("BLAKE3 keyed_hash key must be 32 bytes")
    key_words = _words_from_le_bytes_32(key, 8)
    flags = KEYED_HASH
    return _blake3_hash_xof(key_words, flags, data, out_len)


def blake3_derive_key(context: str, key_material: bytes, out_len: int = OUT_LEN) -> bytes:
    context_key = _blake3_hash_xof(list(IV), DERIVE_KEY_CONTEXT, context.encode("utf-8"), OUT_LEN)
    key_words = _words_from_le_bytes_32(context_key, 8)
    return _blake3_hash_xof(key_words, DERIVE_KEY_MATERIAL, key_material, out_len)


def _blake3_hash_xof(key_words: list[int], flags: int, data: bytes, out_len: int) -> bytes:
    cv_stack: list[list[int]] = []
    chunk_state = _Blake3ChunkState(key_words, chunk_counter=0, flags=flags)

    offset = 0
    while offset < len(data):
        if chunk_state.length() == CHUNK_LEN:
            chunk_cv = chunk_state.output().chaining_value_words()
            total_chunks = chunk_state._chunk_counter + 1
            _blake3_add_chunk_cv(cv_stack, chunk_cv, total_chunks, key_words, flags)
            chunk_state = _Blake3ChunkState(key_words, chunk_counter=total_chunks, flags=flags)

        want = CHUNK_LEN - chunk_state.length()
        take = min(want, len(data) - offset)
        chunk_state.update(data[offset : offset + take])
        offset += take

    output = chunk_state.output()
    parent_nodes_remaining = len(cv_stack)
    while parent_nodes_remaining > 0:
        parent_nodes_remaining -= 1
        left_parent_cv = cv_stack[parent_nodes_remaining]
        output = _blake3_parent_output(left_parent_cv, output.chaining_value_words(), key_words, flags)

    return output.root_output_bytes(out_len)


def blake3_test_input(length: int) -> bytes:
    return bytes((i % 251) for i in range(length))


def _print_step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    _print_step_header(1, "BLAKE2s in the stdlib (RFC 7693 vectors + self-test)")
    msg = b"abc"
    digest = blake2s_256(msg)
    print("blake2s_256('abc') =", _hex(digest))
    print("blake2s_rfc7693_selftest_digest() =", _hex(blake2s_rfc7693_selftest_digest()))
    print()

    _print_step_header(2, "BLAKE3 compression + hash mode (from scratch)")
    print("blake3_hash('abc') =", _hex(blake3_hash(b"abc", out_len=32)))
    print("blake3_hash_xof('abc', 64) =", _hex(blake3_hash_xof(b"abc", out_len=64)))
    print()

    _print_step_header(3, "BLAKE3 tree hashing (chunking) + official test inputs")
    pattern_0 = blake3_test_input(0)
    pattern_1024 = blake3_test_input(1024)
    print("blake3_hash(pattern[0], 32) =", _hex(blake3_hash(pattern_0, out_len=32)))
    print("blake3_hash(pattern[1024], 32) =", _hex(blake3_hash(pattern_1024, out_len=32)))
    print()

    _print_step_header(4, "BLAKE3 keyed_hash and derive_key (domain separation)")
    key = b"whats the Elvish word for friend"
    print("blake3_keyed_hash(key, pattern[1024], 32) =", _hex(blake3_keyed_hash(key, pattern_1024, out_len=32)))
    ctx = "BLAKE3 2019-12-27 16:29:52 test vectors context"
    print("blake3_derive_key(ctx, pattern[1024], 32) =", _hex(blake3_derive_key(ctx, pattern_1024, out_len=32)))


if __name__ == "__main__":
    main()
