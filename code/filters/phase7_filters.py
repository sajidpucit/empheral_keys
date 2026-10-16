"""
Phase 7: Filter Module
=======================
Standalone library for:
  - Bloom filter (primary, Phase 5 spec)
  - Cuckoo filter (optional extension)
  - XOR filter (optional extension)
  - HyperLogLog cardinality estimator (optional extension)
  - Unified FilterFactory interface
  - Compact serialisation / deserialisation for BLE transport

All filters expose:
    add(item: bytes) -> None
    might_contain(item: bytes) -> bool
    to_bytes() -> bytes           (serialise)
    from_bytes(data, **kw)        (class method, deserialise)
    bit_count() / estimated_size() -> int
    intersect(other) -> same type

Design goals:
    - Pure Python, no C extensions required
    - Each filter fits within 4 kB RAM (BLE-constrained devices)
    - Integer arithmetic only (no floats in hot path)
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple


# ================================================================== #
#  Abstract base                                                     #
# ================================================================== #

class AbstractFilter(ABC):
    """Common interface for all probabilistic filter types."""

    @abstractmethod
    def add(self, item: bytes) -> None: ...

    @abstractmethod
    def might_contain(self, item: bytes) -> bool: ...

    @abstractmethod
    def to_bytes(self) -> bytes: ...

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes, **kwargs) -> "AbstractFilter": ...

    @abstractmethod
    def bit_count(self) -> int: ...

    @abstractmethod
    def estimated_fill_ratio(self) -> float: ...

    def intersect(self, other: "AbstractFilter") -> "AbstractFilter":
        raise NotImplementedError("intersect() not supported for this filter type")

    @property
    @abstractmethod
    def type_tag(self) -> bytes:
        """1-byte tag used in the wire format header."""
        ...


# ================================================================== #
#  Bloom Filter                                                      #
# ================================================================== #

BLOOM_TAG = b"\x01"


class BloomFilter(AbstractFilter):
    """
    Classic Bloom filter.

    m = 8192 bits (1 kB) and k = 5 hash functions gives:
        FPR ≈ (1 - e^(-kn/m))^k ≈ 1.2% for n = 200 elements.
    Fully within the 4 kB RAM budget.
    """

    type_tag = BLOOM_TAG

    def __init__(self, m: int = 8192, k: int = 5):
        if m % 8 != 0:
            raise ValueError("m must be divisible by 8")
        self.m = m
        self.k = k
        self._bits = bytearray(m // 8)

    # ----- bit helpers -----

    def _set(self, pos: int) -> None:
        idx, bit = divmod(pos, 8)
        self._bits[idx] |= 1 << bit

    def _get(self, pos: int) -> bool:
        idx, bit = divmod(pos, 8)
        return bool(self._bits[idx] & (1 << bit))

    def _positions(self, item: bytes) -> List[int]:
        """k bit positions derived via HMAC-SHA256 with different keys."""
        positions = []
        for i in range(self.k):
            digest = hmac.new(bytes([i]), item, hashlib.sha256).digest()
            val = struct.unpack(">Q", digest[:8])[0]
            positions.append(int(val % self.m))
        return positions

    # ----- public API -----

    def add(self, item: bytes) -> None:
        for pos in self._positions(item):
            self._set(pos)

    def might_contain(self, item: bytes) -> bool:
        return all(self._get(pos) for pos in self._positions(item))

    def bit_count(self) -> int:
        return sum(bin(b).count("1") for b in self._bits)

    def estimated_fill_ratio(self) -> float:
        return self.bit_count() / self.m

    def to_bytes(self) -> bytes:
        return bytes(self._bits)

    @classmethod
    def from_bytes(cls, data: bytes, k: int = 5, **_) -> "BloomFilter":
        bf = cls(m=len(data) * 8, k=k)
        bf._bits = bytearray(data)
        return bf

    def intersect(self, other: "BloomFilter") -> "BloomFilter":
        """Bitwise AND – approximate set intersection."""
        if self.m != other.m or self.k != other.k:
            raise ValueError("Filter parameters must match for intersection")
        result = BloomFilter(m=self.m, k=self.k)
        result._bits = bytearray(a & b for a, b in zip(self._bits, other._bits))
        return result

    def union(self, other: "BloomFilter") -> "BloomFilter":
        """Bitwise OR – approximate set union."""
        if self.m != other.m or self.k != other.k:
            raise ValueError("Filter parameters must match for union")
        result = BloomFilter(m=self.m, k=self.k)
        result._bits = bytearray(a | b for a, b in zip(self._bits, other._bits))
        return result

    @staticmethod
    def optimal_parameters(n: int, fpr: float = 0.01) -> Tuple[int, int]:
        """
        Compute optimal (m, k) for n expected items and target FPR.
        m rounded up to nearest multiple of 8.
        """
        m_exact = -n * math.log(fpr) / (math.log(2) ** 2)
        m = int(math.ceil(m_exact / 8)) * 8
        k = max(1, round((m / n) * math.log(2)))
        return m, k

    def __repr__(self) -> str:
        return (f"BloomFilter(m={self.m}, k={self.k}, "
                f"bits_set={self.bit_count()}, "
                f"fill={self.estimated_fill_ratio():.3f})")


# ================================================================== #
#  Cuckoo Filter                                                     #
# ================================================================== #

CUCKOO_TAG = b"\x02"
CUCKOO_EMPTY = 0


class CuckooFilter(AbstractFilter):
    """
    Cuckoo filter – supports deletion; better space efficiency at low FPR.

    Parameters
    ----------
    capacity : number of items the filter is designed for
    bucket_size : fingerprints per bucket (default 4)
    fingerprint_bits : bits per fingerprint (default 16)
    max_kicks : max cuckoo kicks before failure (default 500)
    """

    type_tag = CUCKOO_TAG

    def __init__(self,
                 capacity: int = 200,
                 bucket_size: int = 4,
                 fingerprint_bits: int = 16,
                 max_kicks: int = 500):
        self.capacity = capacity
        self.bucket_size = bucket_size
        self.fingerprint_bits = fingerprint_bits
        self.max_kicks = max_kicks
        self.num_buckets = self._next_power_of_2(
            max(1, capacity // bucket_size)
        )
        self.fp_mask = (1 << fingerprint_bits) - 1
        # flat array: num_buckets * bucket_size entries, each 2 bytes
        self._table = [CUCKOO_EMPTY] * (self.num_buckets * bucket_size)
        self._count = 0

    @staticmethod
    def _next_power_of_2(n: int) -> int:
        return 1 if n <= 1 else 2 ** math.ceil(math.log2(n))

    def _fingerprint(self, item: bytes) -> int:
        """Non-zero 'fingerprint_bits'-bit fingerprint of item."""
        h = hashlib.sha256(item).digest()
        fp = struct.unpack(">H", h[:2])[0] & self.fp_mask
        return fp if fp != 0 else 1

    def _bucket_index(self, item: bytes) -> int:
        h = hashlib.sha256(b"bucket" + item).digest()
        return struct.unpack(">I", h[:4])[0] % self.num_buckets

    def _alt_index(self, index: int, fp: int) -> int:
        fp_hash = hashlib.sha256(struct.pack(">H", fp)).digest()
        h = struct.unpack(">I", fp_hash[:4])[0]
        return (index ^ h) % self.num_buckets

    def _slot(self, bucket: int, pos: int) -> int:
        return bucket * self.bucket_size + pos

    def _bucket_slots(self, bucket: int) -> List[int]:
        start = bucket * self.bucket_size
        return list(range(start, start + self.bucket_size))

    def _insert_to_bucket(self, bucket: int, fp: int) -> bool:
        for s in self._bucket_slots(bucket):
            if self._table[s] == CUCKOO_EMPTY:
                self._table[s] = fp
                self._count += 1
                return True
        return False

    def add(self, item: bytes) -> bool:
        """Insert item. Returns False if the filter is too full (rare)."""
        fp = self._fingerprint(item)
        i1 = self._bucket_index(item)
        i2 = self._alt_index(i1, fp)
        if self._insert_to_bucket(i1, fp):
            return True
        if self._insert_to_bucket(i2, fp):
            return True
        # Cuckoo kick
        i = i1
        for _ in range(self.max_kicks):
            s = self._bucket_slots(i)[0]  # evict first slot
            evicted_fp = self._table[s]
            self._table[s] = fp
            fp = evicted_fp
            i = self._alt_index(i, fp)
            if self._insert_to_bucket(i, fp):
                return True
        return False  # filter too full

    def might_contain(self, item: bytes) -> bool:
        fp = self._fingerprint(item)
        i1 = self._bucket_index(item)
        i2 = self._alt_index(i1, fp)
        for bucket in (i1, i2):
            if fp in [self._table[s] for s in self._bucket_slots(bucket)]:
                return True
        return False

    def remove(self, item: bytes) -> bool:
        """Delete an item. Returns True if found and removed."""
        fp = self._fingerprint(item)
        i1 = self._bucket_index(item)
        i2 = self._alt_index(i1, fp)
        for bucket in (i1, i2):
            for s in self._bucket_slots(bucket):
                if self._table[s] == fp:
                    self._table[s] = CUCKOO_EMPTY
                    self._count -= 1
                    return True
        return False

    def bit_count(self) -> int:
        return sum(1 for v in self._table if v != CUCKOO_EMPTY)

    def estimated_fill_ratio(self) -> float:
        return self._count / (self.num_buckets * self.bucket_size)

    def to_bytes(self) -> bytes:
        """Pack each fingerprint as 2-byte big-endian int."""
        header = struct.pack(">IHHH",
                             self.num_buckets,
                             self.bucket_size,
                             self.fingerprint_bits,
                             self.max_kicks)
        body = struct.pack(f">{len(self._table)}H", *self._table)
        return header + body

    @classmethod
    def from_bytes(cls, data: bytes, **_) -> "CuckooFilter":
        header_size = struct.calcsize(">IHHH")
        num_buckets, bucket_size, fp_bits, max_kicks = struct.unpack(
            ">IHHH", data[:header_size]
        )
        cf = cls(capacity=num_buckets * bucket_size,
                 bucket_size=bucket_size,
                 fingerprint_bits=fp_bits,
                 max_kicks=max_kicks)
        cf.num_buckets = num_buckets
        body = data[header_size:]
        cf._table = list(struct.unpack(f">{len(body)//2}H", body))
        cf._count = sum(1 for v in cf._table if v != CUCKOO_EMPTY)
        return cf

    def __repr__(self) -> str:
        return (f"CuckooFilter(buckets={self.num_buckets}, "
                f"bucket_size={self.bucket_size}, "
                f"count={self._count}, "
                f"fill={self.estimated_fill_ratio():.3f})")


# ================================================================== #
#  XOR Filter (lightweight, read-only after construction)           #
# ================================================================== #

XOR_TAG = b"\x03"


class XORFilter(AbstractFilter):
    """
    XOR filter – very space-efficient, but immutable after construction.
    ~1.23 bits per element at FPR ≈ 1/256.

    Implementation follows the construction from
    Graf & Lemire (2020), "Xor Filters: Faster and Smaller Than
    Bloom and Cuckoo Filters".
    """

    type_tag = XOR_TAG
    HASHING_CONST = 0x517CC1B727220A95  # arbitrary 64-bit constant

    def __init__(self):
        self._fingerprints: Optional[bytearray] = None
        self._size: int = 0
        self._seed: int = 0
        self._built = False

    # ----- hash helpers -----

    def _hash64(self, item: bytes, seed: int) -> int:
        """Combine SHA-256 of item with seed to get a 64-bit hash."""
        digest = hashlib.sha256(item + struct.pack(">Q", seed)).digest()
        return struct.unpack(">Q", digest[:8])[0]

    def _h0(self, h: int) -> int:
        return h % (self._size // 3)

    def _h1(self, h: int) -> int:
        return self._size // 3 + (h >> 21) % (self._size // 3)

    def _h2(self, h: int) -> int:
        return 2 * (self._size // 3) + (h >> 42) % (self._size // 3)

    def _fingerprint(self, h: int) -> int:
        return (h ^ (h >> 32)) & 0xFF

    # ----- construction -----

    def build(self, items: List[bytes], seed: int = 42) -> bool:
        """
        Build the XOR filter from a list of items.
        Returns True on success. May fail if size estimation is off.
        """
        n = len(items)
        # Size: c * n where c ≈ 1.23; round to multiple of 3
        c = 1.23
        size = int(math.ceil(c * n / 3)) * 3
        size = max(size, 3)
        self._size = size
        self._seed = seed
        self._fingerprints = bytearray(size)

        hashes = [self._hash64(item, seed) for item in items]

        # Simplified peeling construction
        xor_sets = [0] * size
        count = [0] * size
        for h in hashes:
            for idx in (self._h0(h), self._h1(h), self._h2(h)):
                xor_sets[idx] ^= h
                count[idx] += 1

        # Iterative peeling
        queue = [i for i in range(size) if count[i] == 1]
        order = []
        while queue:
            i = queue.pop()
            if count[i] != 1:
                continue
            h = xor_sets[i]
            order.append((i, h))
            for j in (self._h0(h), self._h1(h), self._h2(h)):
                xor_sets[j] ^= h
                count[j] -= 1
                if count[j] == 1:
                    queue.append(j)

        if len(order) != n:
            return False   # construction failed; retry with different seed

        # Assign fingerprints in reverse peel order
        for i, h in reversed(order):
            fp_xor = 0
            for j in (self._h0(h), self._h1(h), self._h2(h)):
                if j != i:
                    fp_xor ^= self._fingerprints[j]
            self._fingerprints[i] = self._fingerprint(h) ^ fp_xor

        self._built = True
        return True

    def add(self, item: bytes) -> None:
        raise NotImplementedError(
            "XOR filter is immutable. Use build() with all items.")

    def might_contain(self, item: bytes) -> bool:
        if not self._built:
            raise RuntimeError("Call build() first")
        h = self._hash64(item, self._seed)
        fp = self._fingerprint(h)
        return (self._fingerprints[self._h0(h)]
                ^ self._fingerprints[self._h1(h)]
                ^ self._fingerprints[self._h2(h)]) == fp

    def bit_count(self) -> int:
        return sum(bin(b).count("1") for b in (self._fingerprints or b""))

    def estimated_fill_ratio(self) -> float:
        return self.bit_count() / (self._size * 8) if self._size else 0.0

    def to_bytes(self) -> bytes:
        header = struct.pack(">IQ", self._size, self._seed)
        return header + bytes(self._fingerprints or b"")

    @classmethod
    def from_bytes(cls, data: bytes, **_) -> "XORFilter":
        header_size = struct.calcsize(">IQ")
        size, seed = struct.unpack(">IQ", data[:header_size])
        xf = cls()
        xf._size = size
        xf._seed = seed
        xf._fingerprints = bytearray(data[header_size:])
        xf._built = True
        return xf

    def __repr__(self) -> str:
        return (f"XORFilter(size={self._size}, "
                f"built={self._built})")


# ================================================================== #
#  HyperLogLog (cardinality estimator, for diagnostics)             #
# ================================================================== #

class HyperLogLog:
    """
    HyperLogLog cardinality estimator.
    Used to estimate the number of unique frames observed,
    not for key generation.

    Precision b = 12 → ~1.04/sqrt(2^12) ≈ 1.6% error.
    Memory: 2^b bytes = 4 kB.
    """

    def __init__(self, b: int = 12):
        if not (4 <= b <= 16):
            raise ValueError("b must be in [4, 16]")
        self.b = b
        self.m = 1 << b              # 2^b buckets
        self._M = bytearray(self.m)  # max leading zeros per bucket

    def _hash(self, item: bytes) -> int:
        return struct.unpack(">Q", hashlib.sha256(item).digest()[:8])[0]

    @staticmethod
    def _clz(val: int, width: int = 64) -> int:
        """Count leading zeros in a 'width'-bit integer."""
        if val == 0:
            return width
        count = 0
        mask = 1 << (width - 1)
        while not (val & mask):
            count += 1
            mask >>= 1
        return count

    def add(self, item: bytes) -> None:
        h = self._hash(item)
        j = h >> (64 - self.b)           # top b bits → bucket index
        w = h << self.b & ((1 << 64) - 1)  # remaining bits
        self._M[j] = max(self._M[j], self._clz(w, 64 - self.b) + 1)

    def estimate(self) -> int:
        """Return estimated cardinality."""
        alpha_m = 0.7213 / (1 + 1.079 / self.m)
        Z = sum(2.0 ** (-r) for r in self._M)
        E = alpha_m * self.m * self.m / Z
        # Small range correction
        if E <= 2.5 * self.m:
            V = self._M.count(0)
            if V > 0:
                E = self.m * math.log(self.m / V)
        return int(round(E))

    def __repr__(self) -> str:
        return f"HyperLogLog(b={self.b}, m={self.m}, est≈{self.estimate()})"


# ================================================================== #
#  Filter Factory                                                    #
# ================================================================== #

class FilterFactory:
    """
    Create the correct filter type from a config string.
    Centralises all parameter choices.
    """

    TYPES = {"bloom": BloomFilter, "cuckoo": CuckooFilter, "xor": XORFilter}

    @staticmethod
    def create(filter_type: str = "bloom", **kwargs) -> AbstractFilter:
        cls = FilterFactory.TYPES.get(filter_type.lower())
        if cls is None:
            raise ValueError(
                f"Unknown filter type '{filter_type}'. "
                f"Choose from: {list(FilterFactory.TYPES)}"
            )
        if filter_type == "bloom":
            m = kwargs.get("m", 8192)
            k = kwargs.get("k", 5)
            return BloomFilter(m=m, k=k)
        elif filter_type == "cuckoo":
            return CuckooFilter(
                capacity=kwargs.get("capacity", 200),
                bucket_size=kwargs.get("bucket_size", 4),
                fingerprint_bits=kwargs.get("fingerprint_bits", 16),
                max_kicks=kwargs.get("max_kicks", 500),
            )
        elif filter_type == "xor":
            return XORFilter()
        raise ValueError("Unreachable")

    @staticmethod
    def from_bytes(data: bytes, filter_type: str, **kwargs) -> AbstractFilter:
        cls = FilterFactory.TYPES.get(filter_type.lower())
        if cls is None:
            raise ValueError(f"Unknown filter type '{filter_type}'")
        return cls.from_bytes(data, **kwargs)


# ================================================================== #
#  Quick self-test                                                   #
# ================================================================== #

if __name__ == "__main__":
    import random

    print("=== Filter Module Self-Test ===\n")
    rng = random.Random(99)
    items = [rng.randbytes(14) for _ in range(100)]
    non_items = [rng.randbytes(14) for _ in range(100)]

    for ft in ["bloom", "cuckoo"]:
        f = FilterFactory.create(ft)
        for it in items:
            f.add(it)
        tp = sum(1 for it in items if f.might_contain(it))
        fp = sum(1 for ni in non_items if f.might_contain(ni))
        print(f"  {ft.upper():10} TP={tp}/100  FP={fp}/100  "
              f"fill={f.estimated_fill_ratio():.3f}  "
              f"bytes={len(f.to_bytes())}")

    # XOR filter
    xf = XORFilter()
    ok = xf.build(items)
    if ok:
        tp = sum(1 for it in items if xf.might_contain(it))
        fp = sum(1 for ni in non_items if xf.might_contain(ni))
        print(f"  {'XOR':10} TP={tp}/100  FP={fp}/100  bytes={len(xf.to_bytes())}")

    # Bloom intersection
    print("\n  Bloom intersection test:")
    bf_a = BloomFilter()
    bf_b = BloomFilter()
    shared = items[:60]
    only_a = items[60:80]
    only_b = items[80:100]
    for it in shared + only_a:
        bf_a.add(it)
    for it in shared + only_b:
        bf_b.add(it)
    inter = bf_a.intersect(bf_b)
    hits = sum(1 for it in shared if inter.might_contain(it))
    print(f"    Intersection hits on shared items: {hits}/60")
    print(f"    Intersection set bits: {inter.bit_count()}")

    # HyperLogLog
    hll = HyperLogLog()
    for it in items:
        hll.add(it)
    print(f"\n  HyperLogLog estimate: {hll.estimate()} (true=100)")
