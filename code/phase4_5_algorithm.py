"""
Phase 4: Map the Article onto the Proposed System
Phase 5: Design the Detailed Algorithm
=========================================================
- Entity alignment: Ephemeral Secrets → Bluetooth system
- Communication phase alignment table
- Adaptation table (Original mechanism → Adapted version)
- Full algorithmic description in Python (adapted to BLE constraints)
- Frame selection rules, feature extraction spec
- Filter construction, exchange, intersection, key extraction pseudocode
- Key derivation function selection and configuration
- Key refresh strategy

This module is the authoritative algorithmic specification.
All implementation modules (phase7_*.py) follow the interfaces defined here.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ================================================================== #
#  PHASE 4 – Mapping table                                          #
# ================================================================== #

ENTITY_ALIGNMENT = [
    {
        "original (Ephemeral Secrets)": "Wi-Fi STA (IEEE 802.11)",
        "adapted (this work)": "BLE peripheral / central (Bluetooth 5.x)",
        "notes": "Protocol roles are symmetric; either node may initiate.",
    },
    {
        "original (Ephemeral Secrets)": "Shared ad hoc WLAN",
        "adapted (this work)": "BLE advertisement channels 37/38/39",
        "notes": "Same broadcast medium; both nodes hear the same frames.",
    },
    {
        "original (Ephemeral Secrets)": "Monitor-mode NIC",
        "adapted (this work)": "BLE sniffer firmware (e.g., nRF Sniffer)",
        "notes": "Captures raw BLE PDUs including AdvInd, AdvNonConnInd, etc.",
    },
    {
        "original (Ephemeral Secrets)": "802.11 management frames",
        "adapted (this work)": "BLE advertisement PDUs",
        "notes": "AdvInd and AdvNonConnInd PDUs are analogous to beacons.",
    },
    {
        "original (Ephemeral Secrets)": "Sequence number + timestamp",
        "adapted (this work)": "Access address + PDU hash + arrival timestamp",
        "notes": "BLE lacks explicit sequence numbers; arrival order is used.",
    },
    {
        "original (Ephemeral Secrets)": "Passive eavesdropper (Wi-Fi NIC)",
        "adapted (this work)": "BLE scanner outside proximity zone",
        "notes": "Same passive-only threat model for base security analysis.",
    },
]

PROTOCOL_PHASE_ALIGNMENT = [
    {
        "article_phase": "Frame capture window",
        "adapted_phase": "BLE advertisement collection window",
        "adaptation": (
            "Use BLE sniff mode on all three advertisement channels. "
            "Window size N = 100–500 PDUs or T = 30 s, whichever comes first."
        ),
    },
    {
        "article_phase": "Feature extraction",
        "adapted_phase": "BLE PDU field extraction",
        "adaptation": (
            "Extract: PDU type byte, advertiser address (6 B), "
            "advertising data hash (SHA-256 first 4 B), RSSI (1 B), "
            "arrival time mod 2^16 (2 B). Total: 14 bytes per frame."
        ),
    },
    {
        "article_phase": "Bloom filter construction",
        "adapted_phase": "BLE-optimised Bloom filter build",
        "adaptation": (
            "Filter size m = 8192 bits (1 kB). k = 5 independent hash "
            "functions (HMAC-SHA256 with different IV bytes). "
            "Fits entirely in 1 kB RAM."
        ),
    },
    {
        "article_phase": "Filter exchange (Wi-Fi unicast)",
        "adapted_phase": "BLE GATT write with integrity tag",
        "adaptation": (
            "Serialise filter as 1024-byte array + 4-byte CRC32. "
            "Split across ≤ 8 BLE packets (ATT MTU 247 B). "
            "HMAC-SHA256(addr_A XOR addr_B, filter_bytes) truncated to 8 B "
            "provides integrity without pre-shared key."
        ),
    },
    {
        "article_phase": "Intersection computation",
        "adapted_phase": "Bitwise AND of two 1 kB arrays",
        "adaptation": (
            "Use 64-bit integer chunks for efficiency on 32-bit MCU "
            "(128 iterations of 64-bit AND). Count set bits with "
            "Hamming weight accumulator."
        ),
    },
    {
        "article_phase": "Key derivation (hash concatenation)",
        "adapted_phase": "HKDF-SHA256 with structured IKM",
        "adaptation": (
            "IKM = raw intersection bit string. "
            "Salt = HMAC-SHA256(addr_A || addr_B, session_nonce). "
            "Info = b'ble-skg-v1'. Output length = 32 bytes."
        ),
    },
    {
        "article_phase": "Key verification (implicit)",
        "adapted_phase": "Explicit HMAC challenge-response",
        "adaptation": (
            "Node A sends HMAC-SHA256(K, nonce_A). "
            "Node B verifies and replies with HMAC-SHA256(K, nonce_B). "
            "Both sides must verify before using K."
        ),
    },
]


# ================================================================== #
#  PHASE 5 – Detailed Algorithm Implementation                       #
# ================================================================== #


# ---------------------------------------------------------- #
#  5.1  Frame feature extraction                             #
# ---------------------------------------------------------- #

@dataclass
class BLEFrame:
    """
    Represents a single captured BLE advertisement PDU.
    Fields align with the feature extraction specification.
    """
    pdu_type: int            # 1 byte: AdvInd=0, AdvNonConn=2, etc.
    advertiser_addr: bytes   # 6 bytes (MAC address, big-endian)
    payload: bytes           # raw advertising data
    rssi_dbm: int            # received signal strength (signed byte)
    arrival_time_us: int     # microsecond timestamp (monotonic clock)

    def feature_bytes(self) -> bytes:
        """
        Convert frame into a 14-byte feature vector used as Bloom filter input.

        Layout:
          [0]      pdu_type      (1 B)
          [1-6]    advertiser_addr (6 B)
          [7-10]   SHA-256 of payload, first 4 bytes (4 B)
          [11]     rssi_dbm as unsigned byte (1 B)
          [12-13]  arrival_time_us mod 65536, big-endian (2 B)
        """
        payload_hash4 = hashlib.sha256(self.payload).digest()[:4]
        rssi_byte = self.rssi_dbm & 0xFF
        time_mod = self.arrival_time_us % 65536
        return (
            struct.pack("B", self.pdu_type)
            + self.advertiser_addr
            + payload_hash4
            + struct.pack("B", rssi_byte)
            + struct.pack(">H", time_mod)
        )


def select_frames(frames: List[BLEFrame]) -> List[BLEFrame]:
    """
    Phase 5 – Frame selection rules.

    Keep frames that are:
    - AdvInd (0x00) or AdvNonConnInd (0x02) PDU types
    - From unique advertiser addresses (dedup within window)
    - With valid 6-byte advertiser addresses (not all-zeros or all-FF)
    - RSSI above noise floor threshold (> -90 dBm)

    Returns the filtered list, capped at window_size.
    """
    RSSI_FLOOR = -90
    ALLOWED_PDU_TYPES = {0x00, 0x02}
    INVALID_ADDRS = {bytes(6), bytes([0xFF] * 6)}

    seen_addrs: set = set()
    selected: List[BLEFrame] = []

    for f in frames:
        if f.pdu_type not in ALLOWED_PDU_TYPES:
            continue
        if f.rssi_dbm < RSSI_FLOOR:
            continue
        if f.advertiser_addr in INVALID_ADDRS:
            continue
        addr_key = f.advertiser_addr
        if addr_key in seen_addrs:
            # allow each address once per window for determinism
            continue
        seen_addrs.add(addr_key)
        selected.append(f)

    return selected


# ---------------------------------------------------------- #
#  5.2  Bloom Filter                                         #
# ---------------------------------------------------------- #

class BloomFilter:
    """
    Phase 5 – Filter construction and serialisation.

    Parameters
    ----------
    m : int
        Number of bits (must be a multiple of 8). Default 8192 (1 kB).
    k : int
        Number of independent hash functions. Default 5.

    Hash generation:
        H_i(x) = HMAC-SHA256(key=bytes([i]), msg=x) interpreted as uint64,
        then modulo m. This gives k cheap, independent, uniform hash values.
    """

    def __init__(self, m: int = 8192, k: int = 5):
        if m % 8 != 0:
            raise ValueError("m must be a multiple of 8")
        self.m = m
        self.k = k
        self._bits = bytearray(m // 8)  # packed bit array

    # ---------- bit-level helpers ---------- #

    def _set_bit(self, pos: int) -> None:
        byte_idx, bit_idx = divmod(pos, 8)
        self._bits[byte_idx] |= (1 << bit_idx)

    def _get_bit(self, pos: int) -> bool:
        byte_idx, bit_idx = divmod(pos, 8)
        return bool(self._bits[byte_idx] & (1 << bit_idx))

    def _hash_positions(self, item: bytes) -> List[int]:
        """Return k bit positions for item."""
        positions = []
        for i in range(self.k):
            digest = hmac.new(bytes([i]), item, hashlib.sha256).digest()
            val = struct.unpack(">Q", digest[:8])[0]  # first 8 bytes as uint64
            positions.append(val % self.m)
        return positions

    # ---------- public API ---------- #

    def add(self, item: bytes) -> None:
        """Insert item (raw bytes) into the filter."""
        for pos in self._hash_positions(item):
            self._set_bit(pos)

    def might_contain(self, item: bytes) -> bool:
        """Return True if item might be in the set (may false-positive)."""
        return all(self._get_bit(pos) for pos in self._hash_positions(item))

    def bit_count(self) -> int:
        """Return the number of set bits (popcount)."""
        return sum(bin(b).count("1") for b in self._bits)

    def estimated_fill_ratio(self) -> float:
        return self.bit_count() / self.m

    def to_bytes(self) -> bytes:
        """Serialise the filter to a compact byte string (m/8 bytes)."""
        return bytes(self._bits)

    @classmethod
    def from_bytes(cls, data: bytes, k: int = 5) -> "BloomFilter":
        """Deserialise a filter from bytes."""
        m = len(data) * 8
        bf = cls(m=m, k=k)
        bf._bits = bytearray(data)
        return bf

    def intersect(self, other: "BloomFilter") -> "BloomFilter":
        """
        Compute bitwise AND with another filter (same m, k).
        Returns a new BloomFilter representing the intersection approximation.
        """
        if self.m != other.m or self.k != other.k:
            raise ValueError("Filters must have identical parameters")
        result = BloomFilter(m=self.m, k=self.k)
        result._bits = bytearray(
            a & b for a, b in zip(self._bits, other._bits)
        )
        return result

    def __repr__(self) -> str:
        return (f"BloomFilter(m={self.m}, k={self.k}, "
                f"set_bits={self.bit_count()}, "
                f"fill={self.estimated_fill_ratio():.3f})")


def build_filter_from_frames(frames: List[BLEFrame],
                              m: int = 8192,
                              k: int = 5) -> BloomFilter:
    """
    Phase 5 – Filter construction step.
    Given a list of selected BLE frames, build the Bloom filter.
    """
    bf = BloomFilter(m=m, k=k)
    for frame in frames:
        bf.add(frame.feature_bytes())
    return bf


# ---------------------------------------------------------- #
#  5.3  Filter Exchange Message Format                       #
# ---------------------------------------------------------- #

PROTOCOL_VERSION = 1
FILTER_MSG_MAGIC = b"BLESKG"   # 6-byte magic number


@dataclass
class FilterMessage:
    """
    Wire format for transmitting a Bloom filter over BLE GATT.

    Binary layout (big-endian):
      6B  magic = "BLESKG"
      1B  version
      2B  filter_m (bits)
      1B  filter_k
      NB  filter_data  (m/8 bytes)
      8B  hmac_tag     (HMAC-SHA256 of header+filter, truncated to 8 bytes)
    """
    filter_data: bytes
    filter_m: int
    filter_k: int
    hmac_tag: bytes = field(default_factory=lambda: bytes(8))

    HEADER_FMT = ">6sBHB"   # magic, version, m, k
    HEADER_SIZE = struct.calcsize(HEADER_FMT)  # = 10
    TAG_SIZE = 8

    def serialise(self) -> bytes:
        header = struct.pack(
            self.HEADER_FMT,
            FILTER_MSG_MAGIC,
            PROTOCOL_VERSION,
            self.filter_m,
            self.filter_k,
        )
        return header + self.filter_data + self.hmac_tag

    @classmethod
    def deserialise(cls, data: bytes) -> "FilterMessage":
        header = data[:cls.HEADER_SIZE]
        magic, version, m, k = struct.unpack(cls.HEADER_FMT, header)
        if magic != FILTER_MSG_MAGIC:
            raise ValueError(f"Bad magic: {magic!r}")
        if version != PROTOCOL_VERSION:
            raise ValueError(f"Unknown protocol version: {version}")
        filter_end = cls.HEADER_SIZE + m // 8
        filter_data = data[cls.HEADER_SIZE:filter_end]
        tag = data[filter_end:filter_end + cls.TAG_SIZE]
        return cls(filter_data=filter_data, filter_m=m, filter_k=k, hmac_tag=tag)

    def compute_hmac(self, key: bytes) -> bytes:
        """Compute 8-byte HMAC-SHA256 over header + filter_data."""
        header = struct.pack(
            self.HEADER_FMT,
            FILTER_MSG_MAGIC, PROTOCOL_VERSION, self.filter_m, self.filter_k
        )
        mac = hmac.new(key, header + self.filter_data, hashlib.sha256).digest()
        return mac[:self.TAG_SIZE]

    def sign(self, key: bytes) -> None:
        """Set hmac_tag in-place."""
        self.hmac_tag = self.compute_hmac(key)

    def verify(self, key: bytes) -> bool:
        """Verify hmac_tag using constant-time comparison."""
        expected = self.compute_hmac(key)
        return hmac.compare_digest(self.hmac_tag, expected)


# ---------------------------------------------------------- #
#  5.4  Intersection and Raw Key Extraction                  #
# ---------------------------------------------------------- #

def extract_raw_key_bits(intersection_filter: BloomFilter,
                          min_bits: int = 64) -> Optional[bytes]:
    """
    Phase 5 – Intersection and key extraction.

    Collect the positions of all set bits in the intersection filter.
    Concatenate the (LSB-first) bit positions as a byte string for HKDF input.

    Returns None if fewer than min_bits set bits exist (session discarded).
    """
    set_positions = []
    bits_data = intersection_filter._bits
    for byte_idx, byte_val in enumerate(bits_data):
        for bit_idx in range(8):
            if byte_val & (1 << bit_idx):
                set_positions.append(byte_idx * 8 + bit_idx)

    if len(set_positions) < min_bits:
        return None   # insufficient entropy – discard session

    # Encode positions as 2-byte big-endian integers
    ikm = b"".join(struct.pack(">H", pos) for pos in set_positions)
    return ikm


# ---------------------------------------------------------- #
#  5.5  Key Derivation Function (HKDF-SHA256)                #
# ---------------------------------------------------------- #

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract step: PRK = HMAC-SHA256(salt, IKM)."""
    return _hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand step: output keying material of given length."""
    hash_len = 32  # SHA-256
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = _hmac_sha256(prk, t_prev + info + bytes([i]))
        okm += t_prev
    return okm[:length]


def derive_key(ikm: bytes,
               addr_a: bytes,
               addr_b: bytes,
               session_nonce: bytes,
               key_length: int = 32,
               info: bytes = b"ble-skg-v1") -> bytes:
    """
    Phase 5 – Key derivation.

    Parameters
    ----------
    ikm            : raw intersection bit string from extract_raw_key_bits()
    addr_a, addr_b : 6-byte device addresses
    session_nonce  : fresh random bytes for this session
    key_length     : desired output key length in bytes (default 32 = 256 bit)
    info           : protocol version label

    Returns 'key_length' bytes of derived key material.
    """
    # Salt = HMAC-SHA256(addr_A || addr_B, session_nonce)
    salt = _hmac_sha256(addr_a + addr_b, session_nonce)
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, key_length)


# ---------------------------------------------------------- #
#  5.6  Key Refresh Strategy                                 #
# ---------------------------------------------------------- #

@dataclass
class KeyRefreshPolicy:
    """
    Phase 5 – Key refresh configuration.
    All parameters should be loaded from config.yaml in production.
    """
    frames_per_session: int = 100      # frames to collect before attempting SKG
    refresh_interval_sec: float = 60.0 # rotate key at least every N seconds
    max_mismatch_retries: int = 3      # retry limit before discarding
    discard_threshold: float = 0.30   # minimum intersection ratio
    min_intersection_bits: int = 64   # absolute minimum set bits in intersection


@dataclass
class SessionState:
    """
    Tracks the state of one SKG session (one key generation attempt).
    """
    session_id: bytes = field(default_factory=lambda: os.urandom(8))
    start_time: float = field(default_factory=time.monotonic)
    frames_collected: int = 0
    retry_count: int = 0
    key: Optional[bytes] = None
    key_derived_at: float = 0.0
    status: str = "collecting"  # collecting | exchanging | derived | failed

    def is_expired(self, policy: KeyRefreshPolicy) -> bool:
        if self.key_derived_at == 0.0:
            return False
        return (time.monotonic() - self.key_derived_at) > policy.refresh_interval_sec

    def should_discard(self, intersection_ratio: float,
                       policy: KeyRefreshPolicy) -> bool:
        return (intersection_ratio < policy.discard_threshold
                or self.retry_count >= policy.max_mismatch_retries)


# ---------------------------------------------------------- #
#  5.7  Full Protocol (Pseudocode in Python)                 #
# ---------------------------------------------------------- #

def run_skg_session(
    local_frames: List[BLEFrame],
    remote_filter_bytes: bytes,
    addr_local: bytes,
    addr_remote: bytes,
    session_nonce: bytes,
    policy: KeyRefreshPolicy = None,
    m: int = 8192,
    k: int = 5,
    key_length: int = 32,
) -> Tuple[Optional[bytes], dict]:
    """
    Execute one complete SKG session on the local node.

    Parameters
    ----------
    local_frames        : frames captured locally this session
    remote_filter_bytes : serialised BloomFilter received from remote node
    addr_local          : 6-byte local BLE device address
    addr_remote         : 6-byte remote BLE device address
    session_nonce       : shared random nonce (exchanged in plaintext)
    policy              : KeyRefreshPolicy instance

    Returns
    -------
    (key, stats) where key is 'key_length' bytes or None on failure,
    and stats is a dictionary of metrics for Phase 8 logging.
    """
    if policy is None:
        policy = KeyRefreshPolicy()

    stats: dict = {
        "session_nonce_hex": session_nonce.hex(),
        "frames_before_selection": len(local_frames),
    }

    # Step 1: Frame selection
    selected = select_frames(local_frames)
    stats["frames_after_selection"] = len(selected)

    # Step 2: Build local filter
    local_filter = build_filter_from_frames(selected, m=m, k=k)
    stats["local_filter_set_bits"] = local_filter.bit_count()
    stats["local_filter_fill_ratio"] = local_filter.estimated_fill_ratio()

    # Step 3: Parse remote filter
    remote_filter = BloomFilter.from_bytes(remote_filter_bytes, k=k)
    stats["remote_filter_set_bits"] = remote_filter.bit_count()

    # Step 4: Intersection
    intersection = local_filter.intersect(remote_filter)
    intersection_bits = intersection.bit_count()
    intersection_ratio = intersection_bits / m if m > 0 else 0
    stats["intersection_bits"] = intersection_bits
    stats["intersection_ratio"] = round(intersection_ratio, 4)

    # Step 5: Discard check
    if intersection.should_discard(intersection_ratio, policy) if hasattr(
            intersection, "should_discard") else (
            intersection_ratio < policy.discard_threshold or
            intersection_bits < policy.min_intersection_bits):
        stats["result"] = "discarded_low_intersection"
        return None, stats

    # Step 6: Extract IKM
    ikm = extract_raw_key_bits(intersection, min_bits=policy.min_intersection_bits)
    if ikm is None:
        stats["result"] = "discarded_insufficient_bits"
        return None, stats
    stats["ikm_length_bytes"] = len(ikm)

    # Step 7: Derive key
    key = derive_key(ikm, addr_local, addr_remote, session_nonce,
                     key_length=key_length)
    stats["key_length_bytes"] = len(key)
    stats["result"] = "success"

    return key, stats


# ================================================================== #
#  Print adaptation table (for documentation/Phase 9)               #
# ================================================================== #

def print_adaptation_table() -> None:
    print("\nProtocol Phase Adaptation Table")
    print("=" * 72)
    fmt = "{:<28} {:<28} {}"
    print(fmt.format("Original Mechanism", "Adapted Version", "Notes"))
    print("-" * 72)
    for row in PROTOCOL_PHASE_ALIGNMENT:
        print(fmt.format(
            row["article_phase"][:27],
            row["adapted_phase"][:27],
            row["adaptation"][:40],
        ))
    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 4 & 5 – Algorithm specification and demo")
    parser.add_argument("--table", action="store_true",
                        help="Print protocol adaptation table")
    parser.add_argument("--demo", action="store_true",
                        help="Run a self-contained algorithm demo")
    args = parser.parse_args()

    if args.table or not args.demo:
        print_adaptation_table()

    if args.demo:
        print("=== Algorithm Demo (Simulated Session) ===\n")

        # Simulate two nodes capturing overlapping frames
        def make_frames(n, seed=0):
            import random
            rng = random.Random(seed)
            frames = []
            for i in range(n):
                frames.append(BLEFrame(
                    pdu_type=rng.choice([0x00, 0x02]),
                    advertiser_addr=rng.randbytes(6),
                    payload=rng.randbytes(rng.randint(4, 31)),
                    rssi_dbm=rng.randint(-80, -40),
                    arrival_time_us=i * 1000 + rng.randint(0, 500),
                ))
            return frames

        frames_a = make_frames(80, seed=42)
        frames_b = make_frames(80, seed=42)   # same seed = identical frames
        # Introduce 20 % packet loss on each side
        import random
        frames_a = [f for f in frames_a if random.random() > 0.10]
        frames_b = [f for f in frames_b if random.random() > 0.10]

        addr_a = bytes.fromhex("AABBCCDDEEFF")
        addr_b = bytes.fromhex("112233445566")
        nonce = os.urandom(16)

        # Alice builds and serialises her filter
        sel_a = select_frames(frames_a)
        bf_a = build_filter_from_frames(sel_a)

        # Bob runs the session with Alice's filter
        key, stats = run_skg_session(
            local_frames=frames_b,
            remote_filter_bytes=bf_a.to_bytes(),
            addr_local=addr_b,
            addr_remote=addr_a,
            session_nonce=nonce,
        )

        for k2, v in stats.items():
            print(f"  {k2:<35} {v}")
        if key:
            print(f"\n  Derived key (hex): {key.hex()}")
        else:
            print("\n  Session failed – no key derived.")
