"""
Cache side-channel demo (educational, simulated).

Run:
  python3 code/main.py

This lesson simulates a tiny direct-mapped cache and demonstrates a
Prime+Probe-style attack against a victim that performs a secret-dependent table
lookup.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class CacheLine:
    tag: Optional[int] = None


class DirectMappedCache:
    def __init__(self, num_sets: int):
        if num_sets <= 0:
            raise ValueError("num_sets must be positive")
        self.num_sets = num_sets
        self.lines = [CacheLine() for _ in range(num_sets)]

    def _set_index(self, addr: int) -> int:
        return addr % self.num_sets

    def access(self, addr: int) -> int:
        set_idx = self._set_index(addr)
        tag = addr // self.num_sets
        line = self.lines[set_idx]
        if line.tag == tag:
            return 1
        line.tag = tag
        return 10

    def flush(self) -> None:
        for line in self.lines:
            line.tag = None


def victim_secret_lookup(cache: DirectMappedCache, table_base: int, secret_index: int) -> int:
    addr = table_base + secret_index
    return cache.access(addr)


def prime(cache: DirectMappedCache, addresses: List[int]) -> None:
    for a in addresses:
        _ = cache.access(a)


def probe(cache: DirectMappedCache, addresses: List[int]) -> List[Tuple[int, int]]:
    out = []
    for a in addresses:
        out.append((a, cache.access(a)))
    return out


def recover_secret_prime_probe(cache_sets: int, secret_index: int) -> int:
    cache = DirectMappedCache(cache_sets)
    table_base = cache_sets
    attacker_addrs = [i for i in range(cache_sets)]

    cache.flush()
    prime(cache, attacker_addrs)
    _ = victim_secret_lookup(cache, table_base, secret_index)
    timings = probe(cache, attacker_addrs)

    worst_addr, worst_time = max(timings, key=lambda t: t[1])
    if worst_time < 10:
        raise RuntimeError("no eviction observed")
    return worst_addr


def main():
    print("=== Step 1: A toy direct-mapped cache model ===")
    cache = DirectMappedCache(num_sets=16)
    t1 = cache.access(0)
    t2 = cache.access(0)
    t3 = cache.access(16)
    print("miss_then_hit:", t1, t2)
    print("conflict_miss:", t3)

    print("=== Step 2: A victim with a secret-dependent lookup ===")
    secret = 7
    cache.flush()
    _ = victim_secret_lookup(cache, table_base=16, secret_index=secret)
    print("victim_accessed_index:", secret)

    print("=== Step 3: Prime+Probe recovers the secret (simulated) ===")
    recovered = recover_secret_prime_probe(cache_sets=16, secret_index=secret)
    print("recovered_secret_index:", recovered)


if __name__ == "__main__":
    main()
