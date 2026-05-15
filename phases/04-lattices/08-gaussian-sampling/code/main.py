from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext

SCALE_64 = 1 << 64


def _dec(x: float | str | Decimal) -> Decimal:
    if isinstance(x, Decimal):
        return x
    if isinstance(x, float):
        return Decimal(str(x))
    return Decimal(x)


def _dec_floor(x: Decimal) -> int:
    return int(x.to_integral_value(rounding=ROUND_FLOOR))


def _dec_ceil(x: Decimal) -> int:
    return int(x.to_integral_value(rounding=ROUND_CEILING))


class Sha256CtrRng:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) == 0:
            raise ValueError("seed must be non-empty")
        self._seed = bytes(seed)
        self._ctr = 0
        self._buf = b""
        self._pos = 0

    def _refill(self) -> None:
        h = hashlib.sha256()
        h.update(self._seed)
        h.update(self._ctr.to_bytes(8, "big"))
        self._ctr += 1
        self._buf = h.digest()
        self._pos = 0

    def random_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._buf):
                self._refill()
            take = min(n - len(out), len(self._buf) - self._pos)
            out += self._buf[self._pos : self._pos + take]
            self._pos += take
        return bytes(out)

    def uint64(self) -> int:
        return int.from_bytes(self.random_bytes(8), "big")

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        k = n.bit_length()
        while True:
            x = self._randbits(k)
            if x < n:
                return x

    def _randbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("k must be non-negative")
        nbytes = (k + 7) // 8
        x = int.from_bytes(self.random_bytes(nbytes), "big")
        if k % 8:
            x &= (1 << k) - 1
        return x


@dataclass(frozen=True)
class DiscreteGaussianCDF:
    values: tuple[int, ...]
    cdf_ends: tuple[int, ...]
    sigma: Decimal
    center: Decimal
    tail: int

    def sample(self, rng: Sha256CtrRng) -> int:
        u = rng.uint64()
        i = bisect.bisect_right(self.cdf_ends, u)
        return self.values[i]


def build_discrete_gaussian_cdf(
    *,
    sigma: float | str | Decimal,
    center: float | str | Decimal = 0,
    tail: int | None = None,
    precision: int = 80,
) -> DiscreteGaussianCDF:
    sig = _dec(sigma)
    cen = _dec(center)
    if sig <= 0:
        raise ValueError("sigma must be positive")
    if precision < 50:
        raise ValueError("precision must be at least 50")

    if tail is None:
        with localcontext() as ctx:
            ctx.prec = precision
            tail = int((sig * 10).to_integral_value(rounding=ROUND_CEILING))
            tail = max(tail, 6)
    if tail <= 0:
        raise ValueError("tail must be positive")

    with localcontext() as ctx:
        ctx.prec = precision

        start = _dec_floor(cen - Decimal(tail))
        end = _dec_ceil(cen + Decimal(tail))
        xs = list(range(start, end + 1))

        two_sigma2 = Decimal(2) * sig * sig
        ws: list[Decimal] = []
        for x in xs:
            dx = Decimal(x) - cen
            w = (-(dx * dx) / two_sigma2).exp()
            ws.append(w)

        total = sum(ws)
        if total <= 0:
            raise ValueError("failed to normalize distribution")

        floors: list[int] = []
        fracs: list[tuple[Decimal, int]] = []
        for i, w in enumerate(ws):
            scaled = (w / total) * Decimal(SCALE_64)
            f = int(scaled)
            floors.append(f)
            fracs.append((scaled - Decimal(f), i))

        s = sum(floors)
        if s > SCALE_64:
            raise ValueError("normalization overflow")
        rem = SCALE_64 - s
        if rem > len(xs):
            raise ValueError("normalization failed (excess remainder)")

        fracs.sort(key=lambda t: (t[0], -xs[t[1]]), reverse=True)
        for _, i in fracs[:rem]:
            floors[i] += 1

        if sum(floors) != SCALE_64:
            raise ValueError("normalization failed (rounding mismatch)")

        cdf: list[int] = []
        acc = 0
        for f in floors:
            acc += f
            cdf.append(acc)
        if cdf[-1] != SCALE_64:
            raise ValueError("normalization failed (cdf mismatch)")

    return DiscreteGaussianCDF(
        values=tuple(xs),
        cdf_ends=tuple(cdf),
        sigma=sig,
        center=cen,
        tail=tail,
    )


def sample_discrete_gaussian(
    *,
    rng: Sha256CtrRng,
    sigma: float | str | Decimal,
    center: float | str | Decimal = 0,
    tail: int | None = None,
) -> int:
    sampler = build_discrete_gaussian_cdf(sigma=sigma, center=center, tail=tail)
    return sampler.sample(rng)


def sample_discrete_gaussian_vector(
    *,
    rng: Sha256CtrRng,
    dim: int,
    sigma: float | str | Decimal,
    center: float | str | Decimal = 0,
    tail: int | None = None,
) -> tuple[int, ...]:
    if dim <= 0:
        raise ValueError("dim must be positive")
    sampler = build_discrete_gaussian_cdf(sigma=sigma, center=center, tail=tail)
    return tuple(sampler.sample(rng) for _ in range(dim))


def main() -> None:
    rng = Sha256CtrRng(b"04-lattices/08-gaussian-sampling")
    sampler = build_discrete_gaussian_cdf(sigma="2.0", center="0", tail=16)

    samples = [sampler.sample(rng) for _ in range(24)]
    print("Discrete Gaussian sampling over Z (educational, not constant-time)")
    print(f"sigma={sampler.sigma} tail={sampler.tail} support=[{sampler.values[0]}, {sampler.values[-1]}]")
    print(f"first 24 samples: {samples}")


if __name__ == "__main__":
    main()
