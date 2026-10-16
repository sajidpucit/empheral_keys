"""
Phase 7: Packet Capture and Feature Extraction Module
=======================================================
- Enable monitor/sniff mode on BLE interface
- Capture frames, log to disk (pcap-like format)
- Label frames per node and per session
- Feature extraction: convert frames → hash inputs
- Simulated capture for testing without hardware

Real capture requires: pip install pyshark scapy bleak
Simulated capture works without any hardware or elevated privileges.
"""

import csv
import hashlib
import json
import os
import random
import struct
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, List, Optional

# Conditional hardware imports – graceful fallback to simulation
try:
    import pyshark  # type: ignore
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False

try:
    from scapy.all import sniff, Dot11  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ================================================================== #
#  Frame data structure (canonical; matches phase4_5_algorithm.py)  #
# ================================================================== #

@dataclass
class CapturedFrame:
    """
    A captured BLE advertisement frame with all metadata needed for
    logging and feature extraction.
    """
    session_id: str
    node_id: str                  # "A" or "B"
    frame_index: int              # sequential within session
    pdu_type: int                 # 0x00=AdvInd, 0x02=AdvNonConnInd
    advertiser_addr: str          # hex string "AA:BB:CC:DD:EE:FF"
    payload_hex: str              # advertising data as hex string
    rssi_dbm: int                 # received signal strength
    arrival_time_us: int          # monotonic microsecond timestamp
    capture_channel: int          # BLE advertisement channel (37/38/39)

    def advertiser_addr_bytes(self) -> bytes:
        return bytes.fromhex(self.advertiser_addr.replace(":", ""))

    def payload_bytes(self) -> bytes:
        return bytes.fromhex(self.payload_hex)

    def feature_bytes(self) -> bytes:
        """
        14-byte feature vector for Bloom filter input.
        Layout identical to BLEFrame.feature_bytes() in phase4_5_algorithm.py.
        """
        payload_hash4 = hashlib.sha256(self.payload_bytes()).digest()[:4]
        rssi_byte = self.rssi_dbm & 0xFF
        time_mod = self.arrival_time_us % 65536
        return (
            struct.pack("B", self.pdu_type)
            + self.advertiser_addr_bytes()
            + payload_hash4
            + struct.pack("B", rssi_byte)
            + struct.pack(">H", time_mod)
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CapturedFrame":
        return cls(**d)


# ================================================================== #
#  PCAP-style session log (JSON-lines format)                        #
# ================================================================== #

class SessionLog:
    """
    Write captured frames to a JSON-lines file for replay and analysis.
    Each line is one JSON-encoded CapturedFrame.
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")
        self._count = 0

    def write(self, frame: CapturedFrame) -> None:
        self._fh.write(json.dumps(frame.to_dict()) + "\n")
        self._count += 1

    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    @staticmethod
    def read(path: str) -> Iterator[CapturedFrame]:
        """Replay a saved session log."""
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield CapturedFrame.from_dict(json.loads(line))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __repr__(self):
        return f"SessionLog({self.path}, frames_written={self._count})"


# ================================================================== #
#  Monitor mode helper                                               #
# ================================================================== #

def enable_monitor_mode(interface: str) -> bool:
    """
    Enable BLE sniff / monitor mode on the given interface.

    On Linux with an nRF Sniffer or compatible BLE USB dongle:
        ip link set <iface> down
        iw dev <iface> set type monitor
        ip link set <iface> up

    Returns True if successful, False if unsupported (simulation mode).
    """
    import subprocess
    commands = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "monitor"],
        ["ip", "link", "set", interface, "up"],
    ]
    try:
        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode != 0:
                raise OSError(result.stderr.decode())
        print(f"[capture] Monitor mode enabled on {interface}")
        return True
    except (OSError, FileNotFoundError) as exc:
        print(f"[capture] Cannot enable monitor mode ({exc}). "
              f"Using simulation mode.")
        return False


# ================================================================== #
#  Real capture via pyshark (requires monitor-mode interface)        #
# ================================================================== #

def capture_pyshark(interface: str,
                    max_frames: int,
                    timeout: float,
                    session_id: str,
                    node_id: str,
                    log: SessionLog,
                    start_time_us: int) -> List[CapturedFrame]:
    """Capture BLE advertisement frames using pyshark (requires hardware)."""
    if not HAS_PYSHARK:
        raise RuntimeError("pyshark not installed. Run: pip install pyshark")

    frames: List[CapturedFrame] = []
    capture = pyshark.LiveCapture(
        interface=interface,
        display_filter="btle.advertising_header",
    )
    capture.set_debug()

    for idx, pkt in enumerate(capture.sniff_continuously(packet_count=max_frames)):
        if time.monotonic() > start_time_us / 1e6 + timeout:
            break
        try:
            pdu_type = int(pkt.btle.get_field("advertising_header.pdu_type"), 16)
            addr = pkt.btle.get_field("advertising_address").replace(":", "").upper()
            addr_fmt = ":".join(addr[i:i+2] for i in range(0, 12, 2))
            payload = bytes.fromhex(
                pkt.btle.get_field("advertising_data") or "00"
            ).hex()
            rssi = int(getattr(pkt, "radiotap", None) and
                       pkt.radiotap.get_field("dbm_antsignal") or -70)
            arrival = start_time_us + int(float(pkt.sniff_timestamp) * 1e6)
            channel = random.choice([37, 38, 39])  # approximation

            cf = CapturedFrame(
                session_id=session_id,
                node_id=node_id,
                frame_index=idx,
                pdu_type=pdu_type,
                advertiser_addr=addr_fmt,
                payload_hex=payload,
                rssi_dbm=rssi,
                arrival_time_us=arrival,
                capture_channel=channel,
            )
            frames.append(cf)
            log.write(cf)
        except Exception:
            continue

    capture.close()
    return frames


# ================================================================== #
#  Simulated BLE frame generator (no hardware required)             #
# ================================================================== #

_ADVERTISERS = [
    "AA:BB:CC:DD:EE:01",
    "AA:BB:CC:DD:EE:02",
    "AA:BB:CC:DD:EE:03",
    "11:22:33:44:55:01",
    "11:22:33:44:55:02",
    "DE:AD:BE:EF:CA:FE",
    "CA:FE:BA:BE:00:01",
    "FE:ED:FA:CE:00:01",
]

_PDU_TYPES = [0x00, 0x02]    # AdvInd, AdvNonConnInd
_CHANNELS  = [37, 38, 39]


def _random_payload(rng: random.Random, length: int = None) -> bytes:
    n = length if length is not None else rng.randint(6, 31)
    return rng.randbytes(n)


def simulate_capture(
    max_frames: int,
    session_id: str,
    node_id: str,
    log: SessionLog,
    loss_prob: float = 0.10,
    noise_prob: float = 0.05,
    rssi_range: tuple = (-80, -40),
    seed: int = None,
) -> List[CapturedFrame]:
    """
    Generate a realistic stream of simulated BLE advertisement frames.

    Parameters
    ----------
    max_frames  : how many frames to generate
    session_id  : session label
    node_id     : "A" or "B"
    log         : open SessionLog to write frames into
    loss_prob   : probability that a frame is dropped (channel loss)
    noise_prob  : probability that a spurious foreign frame is injected
    rssi_range  : (min_dbm, max_dbm) for RSSI simulation
    seed        : reproducible random seed (None = truly random)
    """
    rng = random.Random(seed)
    frames: List[CapturedFrame] = []
    base_time_us = int(time.monotonic() * 1e6)

    for idx in range(max_frames):
        # Simulate packet loss
        if rng.random() < loss_prob:
            continue

        # Simulate noise frames from distant advertisers
        if rng.random() < noise_prob:
            addr = ":".join(f"{rng.randint(0,255):02X}" for _ in range(6))
        else:
            addr = rng.choice(_ADVERTISERS)

        cf = CapturedFrame(
            session_id=session_id,
            node_id=node_id,
            frame_index=idx,
            pdu_type=rng.choice(_PDU_TYPES),
            advertiser_addr=addr,
            payload_hex=_random_payload(rng).hex(),
            rssi_dbm=rng.randint(*rssi_range),
            arrival_time_us=base_time_us + idx * 1000 + rng.randint(0, 500),
            capture_channel=rng.choice(_CHANNELS),
        )
        frames.append(cf)
        log.write(cf)

    log.flush()
    return frames


# ================================================================== #
#  Capture controller (selects real vs. simulation automatically)   #
# ================================================================== #

class CaptureController:
    """
    High-level interface for packet capture.
    Automatically falls back to simulation if hardware is unavailable.
    """

    def __init__(self,
                 interface: str = "wlan0",
                 pcap_dir: str = "results/pcap",
                 use_simulation: bool = False):
        self.interface = interface
        self.pcap_dir = Path(pcap_dir)
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.use_simulation = use_simulation or not HAS_PYSHARK

    def capture_session(self,
                        session_id: str,
                        node_id: str,
                        max_frames: int = 100,
                        timeout_sec: float = 30.0,
                        seed: int = None) -> List[CapturedFrame]:
        """
        Capture one session's worth of frames.
        Returns the list of CapturedFrame objects.
        """
        log_path = self.pcap_dir / f"session_{session_id}_{node_id}.jsonl"
        print(f"[capture] Session {session_id} Node {node_id} – "
              f"{'SIM' if self.use_simulation else 'LIVE'} – "
              f"target {max_frames} frames → {log_path}")

        with SessionLog(str(log_path)) as log:
            if self.use_simulation:
                frames = simulate_capture(
                    max_frames=max_frames,
                    session_id=session_id,
                    node_id=node_id,
                    log=log,
                    seed=seed,
                )
            else:
                if not enable_monitor_mode(self.interface):
                    print("[capture] Falling back to simulation.")
                    frames = simulate_capture(
                        max_frames=max_frames,
                        session_id=session_id,
                        node_id=node_id,
                        log=log,
                        seed=seed,
                    )
                else:
                    start_us = int(time.monotonic() * 1e6)
                    frames = capture_pyshark(
                        interface=self.interface,
                        max_frames=max_frames,
                        timeout=timeout_sec,
                        session_id=session_id,
                        node_id=node_id,
                        log=log,
                        start_time_us=start_us,
                    )

        print(f"[capture] Captured {len(frames)} frames for session {session_id}/{node_id}")
        return frames

    def export_csv(self, session_id: str, node_id: str) -> str:
        """Export a session log to CSV for analysis."""
        src = self.pcap_dir / f"session_{session_id}_{node_id}.jsonl"
        dst = self.pcap_dir / f"session_{session_id}_{node_id}.csv"
        with open(dst, "w", newline="", encoding="utf-8") as fh:
            writer = None
            for cf in SessionLog.read(str(src)):
                row = cf.to_dict()
                if writer is None:
                    writer = csv.DictWriter(fh, fieldnames=list(row.keys()))
                    writer.writeheader()
                writer.writerow(row)
        print(f"[capture] CSV exported to {dst}")
        return str(dst)


# ================================================================== #
#  CLI / demo                                                        #
# ================================================================== #

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 7 – Packet capture and feature extraction demo")
    parser.add_argument("--sim", action="store_true", default=True,
                        help="Use simulation mode (default)")
    parser.add_argument("--frames", type=int, default=120,
                        help="Number of frames to capture per node")
    parser.add_argument("--session", default="demo001",
                        help="Session ID label")
    parser.add_argument("--outdir", default="results/pcap",
                        help="Output directory for pcap logs")
    args = parser.parse_args()

    ctrl = CaptureController(use_simulation=args.sim, pcap_dir=args.outdir)

    frames_a = ctrl.capture_session(args.session, "A",
                                    max_frames=args.frames, seed=42)
    frames_b = ctrl.capture_session(args.session, "B",
                                    max_frames=args.frames, seed=42)

    ctrl.export_csv(args.session, "A")
    ctrl.export_csv(args.session, "B")

    # Show feature extraction for the first frame
    if frames_a:
        f0 = frames_a[0]
        print(f"\n[feature] Frame 0 feature bytes (hex): {f0.feature_bytes().hex()}")
        print(f"[feature] SHA-256 of feature bytes  : "
              f"{hashlib.sha256(f0.feature_bytes()).hexdigest()[:32]}...")
