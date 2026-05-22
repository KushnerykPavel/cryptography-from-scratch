# Cache Attacks — Prime+Probe (Simulated)

> If secrets choose memory addresses, caches can tell on you.

**Type:** Build
**Languages:** Python
**Prerequisites:** Timing-side-channel intuition; basic cache vocabulary (hit, miss, eviction)
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain how cache hits/misses create a timing side channel
- Compute a toy cache hit/miss timing model
- Implement a victim that performs a secret-dependent table lookup
- Distinguish Prime+Probe from Flush+Reload at a conceptual level
- Apply a Prime+Probe-style workflow to recover a toy secret

## The Problem

Fast implementations often use lookup tables: S-boxes, precomputed window tables, or dispatch tables. On modern CPUs, caches make recently used memory faster to access. If a secret controls which table entries are accessed, runtime can leak information about the secret.

In multi-tenant or shared-hardware scenarios, an attacker can infer cache activity by carefully measuring memory access times. With enough signal and engineering, that can reveal key-dependent indices and sometimes full keys.

This lesson uses a toy cache simulator so you can see the mechanics without relying on a specific CPU, OS, or exploit primitive.

## The Concept

Prime+Probe works by measuring evictions:

1. **Prime:** attacker fills cache sets with their own data.
2. **Victim:** victim touches addresses depending on a secret.
3. **Probe:** attacker re-accesses their data and measures which accesses got slower.

Slow probes point to cache sets the victim used.

## Build It

### Step 1: A toy direct-mapped cache model
```python
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
```
This returns `1` for a hit and `10` for a miss. In reality, caches have associativity, replacement policies, prefetching, and noise. Here we only need “hit vs miss”.

### Step 2: A victim with a secret-dependent lookup
```python
def victim_secret_lookup(cache: DirectMappedCache, table_base: int, secret_index: int) -> int:
    addr = table_base + secret_index
    return cache.access(addr)
```
If `secret_index` depends on a key, then the victim’s cache footprint depends on the key.

### Step 3: Prime+Probe recovers the secret (simulated)
```python
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
```
The attacker identifies the slowest probe (a miss), which corresponds to the set the victim evicted by accessing the secret-dependent index.

Run it:
python3 code/main.py

## Use It

- Prefer hardened constant-time implementations for table-driven primitives.
- For shared hardware: consider side-channel threat models (co-resident attacker).
- Use libraries that explicitly claim side-channel resistance for your threat model.

## Pitfalls

- Assuming “remote attacker” implies “no timing side channels”.
- Using table lookups where the index depends on secret bits.
- Believing “random delays” remove cache/timing signals (often average out).
- Forgetting that hypervisors/containers can share caches.
- Ignoring side-channel considerations in performance tuning.

## Ship It

Save a cache side-channel threat model template: `outputs/cache-side-channel-threat-model.md`.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that Prime+Probe recovers the secret index.
2. Medium. Change the cache to `num_sets=8` and show that different indices collide (same set).
3. Hard. Make the victim touch two indices and extend the attacker to recover both.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Hit / miss | “fast / slow access” | Whether data was already cached or had to be loaded |
| Eviction | “kicked out” | A new access replaces a previous cache line in a set |
| Prime+Probe | “fill and measure” | Attacker fills cache, victim evicts, attacker measures |
| Flush+Reload | “flush shared line” | Attacker flushes a shared line and times victim’s reload (shared memory required) |

## Further Reading

- Osvik, Shamir, Tromer, “Cache Attacks and Countermeasures: the Case of AES” (2006) — classic cache timing attacks on AES tables
- Yarom & Falkner, “Flush+Reload: A High Resolution, Low Noise, L3 Cache Side-Channel Attack” (2014) — shared-memory cache attack technique
