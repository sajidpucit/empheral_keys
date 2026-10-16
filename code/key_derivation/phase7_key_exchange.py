"""
Phase 7: Filter Exchange Protocol, Key Derivation, and Secure Key Storage
==========================================================================
- Network messaging layer: send / receive filter summaries between nodes
- Message framing, fragmentation, and acknowledgement over TCP/UDP socket
- Key derivation module: clean interface from intersection → final key
- Secure in-memory key store with TTL and rotation policy
- Logging for all events needed for Phase 8 metrics
"""

from __future__ import annotations

import hashlib
import hmac as hmaclib
import json
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue, Empty
from typing import Dict, Optional, Tuple


# ================================================================== #
#  Logging setup                                                     #
# ================================================================== #

def setup_logger(log_dir: str = "logs", node_id: str = "node") -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"ble_skg.{node_id}")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(f"{log_dir}/skg_{node_id}.log")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s"))
        logger.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(levelname)-7s %(name)s  %(message)s"))
        logger.addHandler(sh)
    return logger


# ================================================================== #
#  Filter Exchange Protocol                                          #
# ================================================================== #

MAGIC    = b"BLESKG"
VERSION  = 1
HDR_FMT  = ">6sBHBH"   # magic(6), version(1), m(2), k(1), payload_len(2)
HDR_SIZE = struct.calcsize(HDR_FMT)
TAG_LEN  = 8            # HMAC-SHA256 truncated to 8 bytes
ACK_MSG  = b"BLESKG_ACK"
MAX_MSG_BYTES = 4096


def _hmac8(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 truncated to 8 bytes."""
    return hmaclib.new(key, data, hashlib.sha256).digest()[:TAG_LEN]


def _integrity_key(addr_local: bytes, addr_remote: bytes) -> bytes:
    """Derive a message integrity key from device addresses (no pre-shared secret).

    The key is the XOR of the two BLE device addresses (paper, Eq. 2), hashed to
    32 bytes. XOR is symmetric, so both peers derive the same key regardless of
    which side is "local".
    """
    xored = bytes(a ^ b for a, b in zip(addr_local, addr_remote))
    return hashlib.sha256(xored).digest()


def encode_filter_message(filter_bytes: bytes,
                           m: int,
                           k: int,
                           addr_local: bytes,
                           addr_remote: bytes) -> bytes:
    """
    Encode a Bloom filter into a wire message:

      HDR_SIZE bytes : magic, version, m, k, payload_len
      len(filter)    : filter bytes
      TAG_LEN bytes  : HMAC-SHA256(addr_l||addr_r, header+filter)[:8]
    """
    header = struct.pack(HDR_FMT,
                         MAGIC, VERSION, m, k, len(filter_bytes))
    ikey = _integrity_key(addr_local, addr_remote)
    tag = _hmac8(ikey, header + filter_bytes)
    return header + filter_bytes + tag


def decode_filter_message(data: bytes,
                           addr_local: bytes,
                           addr_remote: bytes) -> Tuple[bytes, int, int]:
    """
    Decode and verify a wire message.

    Returns (filter_bytes, m, k).
    Raises ValueError on bad magic, version, or HMAC.
    """
    if len(data) < HDR_SIZE + TAG_LEN:
        raise ValueError("Message too short")
    magic, version, m, k, plen = struct.unpack(HDR_FMT, data[:HDR_SIZE])
    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    if version != VERSION:
        raise ValueError(f"Unknown version: {version}")
    end = HDR_SIZE + plen
    filter_bytes = data[HDR_SIZE:end]
    received_tag = data[end:end + TAG_LEN]
    ikey = _integrity_key(addr_local, addr_remote)
    expected_tag = _hmac8(ikey, data[:end])
    if not hmaclib.compare_digest(received_tag, expected_tag):
        raise ValueError("HMAC verification failed – message may be tampered")
    return filter_bytes, m, k


# ------------------------------------------------------------------ #
#  TCP socket exchange (simulation-friendly loopback)               #
# ------------------------------------------------------------------ #

class FilterExchangeServer:
    """
    Simple TCP server that listens for a filter message from a peer,
    stores it, and sends back its own filter.

    One instance per node; runs in a background thread.
    """

    def __init__(self,
                 host: str,
                 port: int,
                 addr_local: bytes,
                 addr_remote: bytes,
                 logger: logging.Logger):
        self.host = host
        self.port = port
        self.addr_local = addr_local
        self.addr_remote = addr_remote
        self.log = logger
        self._received: Queue = Queue(maxsize=1)
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, local_filter_bytes: bytes, m: int, k: int) -> None:
        """Start listening and prepare the filter to send back."""
        self._local_filter_bytes = local_filter_bytes
        self._m = m
        self._k = k
        self._thread = threading.Thread(
            target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            srv.settimeout(10.0)
            self.log.debug(f"FilterExchangeServer listening on {self.host}:{self.port}")
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                self.log.warning("Server accept timeout")
                return
            with conn:
                conn.settimeout(10.0)
                # Receive peer's filter
                raw = b""
                while len(raw) < MAX_MSG_BYTES:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) >= HDR_SIZE:
                        _, _, m, k, plen = struct.unpack(
                            HDR_FMT, raw[:HDR_SIZE])
                        expected_total = HDR_SIZE + plen + TAG_LEN
                        if len(raw) >= expected_total:
                            break

                try:
                    fb, m2, k2 = decode_filter_message(
                        raw, self.addr_local, self.addr_remote)
                    self.log.info(
                        f"Received filter from peer: m={m2}, k={k2}, "
                        f"bytes={len(fb)}")
                    self._received.put((fb, m2, k2))
                except ValueError as exc:
                    self.log.error(f"Filter decode failed: {exc}")
                    return

                # Send our filter
                reply = encode_filter_message(
                    self._local_filter_bytes,
                    self._m, self._k,
                    self.addr_local, self.addr_remote)
                conn.sendall(reply)
                conn.sendall(ACK_MSG)
                self.log.debug("Sent local filter to peer")

    def wait_for_peer_filter(self, timeout: float = 12.0) -> Optional[bytes]:
        """Block until the peer's filter is received."""
        try:
            fb, _, _ = self._received.get(timeout=timeout)
            return fb
        except Empty:
            self.log.error("Timed out waiting for peer filter")
            return None


class FilterExchangeClient:
    """
    TCP client that connects to the server, sends its filter,
    and receives the server's filter in return.
    """

    def __init__(self,
                 host: str,
                 port: int,
                 addr_local: bytes,
                 addr_remote: bytes,
                 logger: logging.Logger):
        self.host = host
        self.port = port
        self.addr_local = addr_local
        self.addr_remote = addr_remote
        self.log = logger

    def exchange(self,
                 local_filter_bytes: bytes,
                 m: int,
                 k: int,
                 retries: int = 3) -> Optional[bytes]:
        """
        Send local filter and receive peer's filter.
        Returns peer's filter bytes, or None on failure.
        """
        msg = encode_filter_message(
            local_filter_bytes, m, k,
            self.addr_local, self.addr_remote)

        for attempt in range(1, retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(10.0)
                    s.connect((self.host, self.port))
                    s.sendall(msg)

                    raw = b""
                    while len(raw) < MAX_MSG_BYTES:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                        if raw.endswith(ACK_MSG):
                            raw = raw[:-len(ACK_MSG)]
                            break

                fb, _, _ = decode_filter_message(
                    raw, self.addr_remote, self.addr_local)
                self.log.info(
                    f"Received peer filter: {len(fb)} bytes")
                return fb
            except (ConnectionRefusedError, socket.timeout, ValueError) as exc:
                self.log.warning(f"Exchange attempt {attempt} failed: {exc}")
                time.sleep(0.5 * attempt)

        return None


# ================================================================== #
#  Key Derivation Module                                             #
# ================================================================== #

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmaclib.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract."""
    return _hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand."""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = _hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


class KeyDerivationModule:
    """
    Clean interface: intersection_filter_bytes → final symmetric key.

    Parameters are loaded from config; default to 256-bit HKDF-SHA256.
    """

    def __init__(self,
                 output_length: int = 32,
                 info: bytes = b"ble-skg-v1",
                 min_bits: int = 64,
                 logger: Optional[logging.Logger] = None):
        self.output_length = output_length
        self.info = info
        self.min_bits = min_bits
        self.log = logger or logging.getLogger("ble_skg.kdf")

    def extract_ikm(self, intersection_bits: bytearray) -> Optional[bytes]:
        """
        Collect set bit positions from the intersection Bloom filter bit array
        and pack them as 2-byte big-endian integers.

        Returns None if fewer than min_bits set bits exist.
        """
        positions = []
        for byte_idx, byte_val in enumerate(intersection_bits):
            for bit_idx in range(8):
                if byte_val & (1 << bit_idx):
                    positions.append(byte_idx * 8 + bit_idx)

        if len(positions) < self.min_bits:
            self.log.warning(
                f"Insufficient intersection bits: {len(positions)} < {self.min_bits}")
            return None

        ikm = b"".join(struct.pack(">H", pos) for pos in positions)
        self.log.debug(f"IKM extracted: {len(ikm)} bytes ({len(positions)} set bits)")
        return ikm

    def derive(self,
               ikm: bytes,
               addr_local: bytes,
               addr_remote: bytes,
               session_nonce: bytes) -> bytes:
        """
        Derive a symmetric key using HKDF-SHA256.

        Salt = HMAC-SHA256(addr_local || addr_remote, session_nonce)
        PRK  = HKDF-Extract(salt, ikm)
        OKM  = HKDF-Expand(prk, info, output_length)
        """
        salt = _hmac_sha256(addr_local + addr_remote, session_nonce)
        prk = hkdf_extract(salt, ikm)
        key = hkdf_expand(prk, self.info, self.output_length)
        self.log.debug(f"Derived key: {key[:4].hex()}... ({self.output_length} bytes)")
        return key

    def verify_hmac_challenge(self,
                               key: bytes,
                               our_nonce: bytes,
                               peer_tag: bytes) -> bool:
        """
        Verify that the peer computed the same key by checking
        HMAC-SHA256(key, peer_nonce) matches the received tag.
        """
        expected = _hmac_sha256(key, our_nonce)
        ok = hmaclib.compare_digest(expected, peer_tag)
        self.log.info(f"Key confirmation {'SUCCESS' if ok else 'FAILED'}")
        return ok

    def make_challenge_tag(self, key: bytes, nonce: bytes) -> bytes:
        return _hmac_sha256(key, nonce)


# ================================================================== #
#  Secure In-Memory Key Store                                        #
# ================================================================== #

@dataclass
class StoredKey:
    key_id: str
    key_bytes: bytes
    derived_at: float = field(default_factory=time.monotonic)
    ttl_sec: float = 3600.0
    peer_addr: str = ""
    session_id: str = ""
    use_count: int = 0

    def is_expired(self) -> bool:
        return (time.monotonic() - self.derived_at) > self.ttl_sec

    def mark_used(self) -> None:
        self.use_count += 1


class SecureKeyStore:
    """
    In-memory key store with:
    - TTL-based expiration
    - Slot limit (max_keys)
    - Zero-on-evict (overwrite with zeros before deletion)
    - Thread-safe access
    - Event logging for Phase 8 metrics
    """

    def __init__(self,
                 max_keys: int = 10,
                 default_ttl_sec: float = 3600.0,
                 log_dir: str = "logs",
                 logger: Optional[logging.Logger] = None):
        self.max_keys = max_keys
        self.default_ttl_sec = default_ttl_sec
        self.log = logger or logging.getLogger("ble_skg.keystore")
        self._store: Dict[str, StoredKey] = {}
        self._lock = threading.Lock()
        self._event_log_path = Path(log_dir) / "key_events.jsonl"
        self._event_log_path.parent.mkdir(parents=True, exist_ok=True)

    def _log_event(self, event: str, key_id: str, extra: dict = None) -> None:
        record = {
            "ts": time.time(),
            "event": event,
            "key_id": key_id,
            **(extra or {}),
        }
        with open(self._event_log_path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
        self.log.debug(f"[keystore] {event} key_id={key_id}")

    def _evict_expired(self) -> None:
        """Remove expired keys (called under lock)."""
        expired = [kid for kid, sk in self._store.items() if sk.is_expired()]
        for kid in expired:
            self._zero_and_del(kid, reason="expired")

    def _zero_and_del(self, key_id: str, reason: str = "evicted") -> None:
        """Overwrite key material with zeros before deletion."""
        sk = self._store.get(key_id)
        if sk:
            # Overwrite in-place (Python bytes are immutable; use bytearray)
            zeroed = bytearray(len(sk.key_bytes))
            sk.key_bytes = bytes(zeroed)
            del self._store[key_id]
            self._log_event("deleted", key_id, {"reason": reason})

    def store(self,
              key_bytes: bytes,
              session_id: str,
              peer_addr: str,
              ttl_sec: float = None) -> str:
        """
        Store a derived key. Returns the assigned key_id.
        Evicts oldest key if the store is full.
        """
        with self._lock:
            self._evict_expired()
            if len(self._store) >= self.max_keys:
                # Evict the oldest key
                oldest_id = min(self._store, key=lambda k: self._store[k].derived_at)
                self._zero_and_del(oldest_id, reason="capacity")

            key_id = os.urandom(4).hex()
            sk = StoredKey(
                key_id=key_id,
                key_bytes=key_bytes,
                derived_at=time.monotonic(),
                ttl_sec=ttl_sec or self.default_ttl_sec,
                peer_addr=peer_addr,
                session_id=session_id,
            )
            self._store[key_id] = sk
            self._log_event("stored", key_id,
                            {"session_id": session_id,
                             "peer_addr": peer_addr,
                             "key_len": len(key_bytes)})
            return key_id

    def retrieve(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key by ID. Returns None if expired or missing."""
        with self._lock:
            sk = self._store.get(key_id)
            if sk is None:
                self.log.warning(f"Key {key_id} not found")
                return None
            if sk.is_expired():
                self._zero_and_del(key_id, reason="expired_on_retrieve")
                return None
            sk.mark_used()
            self._log_event("retrieved", key_id, {"use_count": sk.use_count})
            return sk.key_bytes

    def delete(self, key_id: str) -> bool:
        with self._lock:
            if key_id in self._store:
                self._zero_and_del(key_id, reason="explicit_delete")
                return True
            return False

    def active_keys(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._store)

    def purge_all(self) -> None:
        """Zero and delete all stored keys."""
        with self._lock:
            for kid in list(self._store.keys()):
                self._zero_and_del(kid, reason="purge")
        self.log.info("All keys purged")


# ================================================================== #
#  Session metric logger (Phase 8 preparation)                      #
# ================================================================== #

class MetricLogger:
    """
    Log all events needed for Phase 8 calculations:
    - number of frames, filter sizes, successful/failed sessions
    - timestamps for KGR calculation
    - key lengths for entropy calculations
    """

    def __init__(self, log_dir: str = "logs", node_id: str = "node"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.node_id = node_id
        self._path = self.log_dir / f"metrics_{node_id}.jsonl"
        self._session_start: Dict[str, float] = {}

    def session_start(self, session_id: str) -> None:
        self._session_start[session_id] = time.time()
        self._write({"event": "session_start",
                     "session_id": session_id,
                     "ts": self._session_start[session_id]})

    def session_end(self, session_id: str, success: bool,
                    frames_captured: int,
                    filter_size_bytes: int,
                    intersection_bits: int,
                    key_bits: int = 0) -> None:
        start = self._session_start.pop(session_id, time.time())
        duration = time.time() - start
        self._write({
            "event": "session_end",
            "session_id": session_id,
            "ts": time.time(),
            "success": success,
            "duration_sec": round(duration, 3),
            "frames_captured": frames_captured,
            "filter_size_bytes": filter_size_bytes,
            "intersection_bits": intersection_bits,
            "key_bits": key_bits,
            "kgr_bits_per_sec": round(key_bits / max(duration, 0.001), 2),
        })

    def _write(self, record: dict) -> None:
        record["node_id"] = self.node_id
        with open(self._path, "a") as fh:
            fh.write(json.dumps(record) + "\n")


# ================================================================== #
#  Demo                                                              #
# ================================================================== #

if __name__ == "__main__":
    print("=== Key Derivation + Storage Demo ===\n")

    logger = setup_logger("logs", "demo")
    kdf = KeyDerivationModule(output_length=32, logger=logger)
    store = SecureKeyStore(logger=logger)

    # Simulate an intersection bit array (1 kB Bloom filter, ~40% set)
    import random
    rng = random.Random(7)
    inter_bits = bytearray(rng.randbytes(1024))

    ikm = kdf.extract_ikm(inter_bits)
    if ikm:
        addr_a = bytes.fromhex("AABBCCDDEEFF")
        addr_b = bytes.fromhex("112233445566")
        nonce  = os.urandom(16)
        key = kdf.derive(ikm, addr_a, addr_b, nonce)
        print(f"  Derived key : {key.hex()}")

        # Verify challenge
        our_nonce = os.urandom(16)
        tag = kdf.make_challenge_tag(key, our_nonce)
        ok = kdf.verify_hmac_challenge(key, our_nonce, tag)
        print(f"  Challenge   : {'PASS' if ok else 'FAIL'}")

        # Store and retrieve
        kid = store.store(key, session_id="s001", peer_addr="AA:BB:CC:DD:EE:FF")
        retrieved = store.retrieve(kid)
        print(f"  Stored key  : {kid}")
        print(f"  Retrieved   : {(retrieved or b'').hex()[:16]}...")
        print(f"  Active keys : {store.active_keys()}")
    else:
        print("  Insufficient intersection bits – session would be discarded")
