"""
Phase 2: Define Target Problem
Phase 3: Build System and Threat Models
========================================
- State exact scenario (Bluetooth ad hoc, device constraints, use cases)
- Explicit research questions with quantitative targets
- Constraints and assumptions list
- Entity catalogue (nodes, attacker types)
- Communication flows in structured form
- Adversary capability specification
- Formal security goals

Run:
    python phase2_3_models.py --all
    python phase2_3_models.py --diagram          # ASCII block diagram
    python phase2_3_models.py --export notes/system_model.json
"""

import json
import argparse
import textwrap
from dataclasses import dataclass, field, asdict
from typing import List, Dict


# ================================================================== #
#  PHASE 2 – Target Problem Definition                               #
# ================================================================== #

SCENARIO = {
    "network_type": "Bluetooth 5.x ad hoc (peer-to-peer, no infrastructure)",
    "device_constraints": {
        "cpu": "ARM Cortex-M4 class (≥ 64 MHz)",
        "ram_kb": 256,
        "flash_kb": 512,
        "radio": "Bluetooth LE 5.x with monitor/sniff mode",
        "battery_mAh": 2000,
        "os": "Bare-metal or RTOS (FreeRTOS / Zephyr)",
    },
    "primary_use_cases": [
        "Secure pairing between two wearable health monitors",
        "Ephemeral session key agreement for IoT sensor mesh",
        "Zero-infrastructure emergency-responder communications",
    ],
}

RESEARCH_QUESTIONS = [
    {
        "id": "RQ1",
        "question": "Can a Bloom-filter-based SKG protocol achieve a key generation "
                    "rate of ≥ 1 bit/s on resource-constrained Bluetooth devices?",
        "metric": "Key generation rate (bits/s)",
        "target": "≥ 1 bit/s",
    },
    {
        "id": "RQ2",
        "question": "What is the key mismatch rate when the two devices are static "
                    "vs. moving at pedestrian speed?",
        "metric": "Key mismatch rate (fraction of failed sessions)",
        "target": "≤ 5 % static, ≤ 15 % mobile",
    },
    {
        "id": "RQ3",
        "question": "What Bloom filter size (m) and hash count (k) minimise the "
                    "false-positive rate while fitting within the 256 kB RAM budget?",
        "metric": "False positive rate & memory footprint",
        "target": "FPR ≤ 1 %; filter ≤ 4 kB",
    },
    {
        "id": "RQ4",
        "question": "Do derived keys pass a NIST SP 800-22 subset of randomness tests "
                    "at the 1 % significance level?",
        "metric": "NIST SP 800-22 test p-values",
        "target": "All selected tests p > 0.01",
    },
    {
        "id": "RQ5",
        "question": "How many Bluetooth advertisement frames must be captured per "
                    "session to achieve a 256-bit key?",
        "metric": "Frames per 256-bit key",
        "target": "≤ 500 frames",
    },
]

CONSTRAINTS_AND_ASSUMPTIONS = {
    "hardware": [
        "Max 4 kB RAM for filter storage",
        "No floating-point hardware; integer arithmetic only for filters",
        "Single Bluetooth radio; cannot transmit and sniff simultaneously",
    ],
    "energy": [
        "Filter exchange must complete within one BLE connection interval (7.5 ms–4 s)",
        "Total SKG phase energy budget: ≤ 10 mJ per key",
    ],
    "bandwidth": [
        "BLE 5.x: max 2 Mbps PHY, but L2CAP MTU ~ 512 bytes",
        "Filter messages must fit in ≤ 8 BLE packets",
    ],
    "deployment_assumptions": [
        "Both nodes are within Bluetooth radio range (≤ 10 m) throughout a session",
        "An eavesdropper is at least 2 m beyond the communicating pair",
        "The channel is not jammed during the key generation window",
        "No prior shared secret or PKI exists between the nodes",
        "The protocol is evaluated over Bluetooth advertisement channel (37/38/39)",
    ],
}


# ================================================================== #
#  PHASE 3 – System Model                                            #
# ================================================================== #

@dataclass
class Entity:
    """Represents a node, device, or actor in the system model."""
    name: str
    role: str          # "node" | "gateway" | "attacker"
    capabilities: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    trusted: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


ENTITIES: List[Entity] = [
    Entity(
        name="Alice (Node A)",
        role="node",
        capabilities=[
            "Broadcast BLE advertisement frames",
            "Receive and log BLE frames in sniff mode",
            "Compute Bloom filter over observed frames",
            "Exchange filter via BLE GATT",
            "Derive and store symmetric key",
        ],
        constraints=[
            "ARM Cortex-M4, 256 kB RAM, 512 kB flash",
            "Cannot sniff and advertise simultaneously",
        ],
        trusted=True,
    ),
    Entity(
        name="Bob (Node B)",
        role="node",
        capabilities=[
            "Same as Alice – symmetric protocol",
        ],
        constraints=[
            "Same hardware class as Alice",
        ],
        trusted=True,
    ),
    Entity(
        name="Passive Eavesdropper (Eve)",
        role="attacker",
        capabilities=[
            "Capture all BLE frames on channels 37/38/39",
            "Record timestamps and signal strength of every frame",
            "Analyse captured traffic off-line with unlimited compute",
        ],
        constraints=[
            "Located ≥ 2 m beyond Alice-Bob proximity",
            "Cannot inject or jam frames (passive only in base threat model)",
        ],
        trusted=False,
    ),
    Entity(
        name="Active Attacker (Mallory)",
        role="attacker",
        capabilities=[
            "All capabilities of Eve",
            "Inject crafted BLE advertisement frames",
            "Replay previously captured frames",
            "Attempt selective jamming to cause desynchronisation",
        ],
        constraints=[
            "Cannot break SHA-256 or HKDF in polynomial time",
            "Cannot predict the exact set of frames seen by both Alice and Bob",
        ],
        trusted=False,
    ),
]


COMMUNICATION_FLOWS = [
    {
        "phase": 1,
        "name": "Frame Collection",
        "steps": [
            "Both Alice and Bob enter BLE sniff/monitor mode on advertisement channels.",
            "Each node records every received BLE advertisement frame "
            "(timestamp, sequence-equivalent nonce, RSSI, source address, payload hash).",
            "Collection continues until the frame window (N frames) is full "
            "or a timeout occurs.",
        ],
    },
    {
        "phase": 2,
        "name": "Filter Construction",
        "steps": [
            "Alice extracts feature fields from each captured frame and hashes "
            "each frame into her Bloom filter B_A.",
            "Bob independently builds his Bloom filter B_B from his captured frames.",
            "Both filters are serialised to byte arrays of length m/8.",
        ],
    },
    {
        "phase": 3,
        "name": "Filter Exchange",
        "steps": [
            "Alice sends B_A to Bob over a BLE GATT write (possibly fragmented).",
            "Bob acknowledges receipt and sends B_B to Alice.",
            "Both sides verify message integrity with a short HMAC (pre-key = "
            "hash of device addresses).",
        ],
    },
    {
        "phase": 4,
        "name": "Intersection and Key Extraction",
        "steps": [
            "Alice computes I = B_A AND B_B (bitwise).",
            "Bob computes the same intersection independently.",
            "Each set bit position in I contributes one bit to raw key material.",
            "If |I| < min_intersection_bits, the session is discarded.",
        ],
    },
    {
        "phase": 5,
        "name": "Key Derivation",
        "steps": [
            "Both nodes feed the raw bit string into HKDF-SHA256 "
            "(salt = XOR of device addresses, info = protocol version label).",
            "HKDF outputs a 256-bit symmetric key K.",
            "Both nodes verify they share K by exchanging HMAC-SHA256(K, nonce) "
            "where nonce is a public random value.",
        ],
    },
    {
        "phase": 6,
        "name": "Key Use and Refresh",
        "steps": [
            "K is stored in RAM only, never written to flash.",
            "K is used to key AES-128-CTR or ChaCha20 for session encryption.",
            "After TTL expires or after a fixed byte count, a new SKG session begins.",
        ],
    },
]


ADVERSARY_CAPABILITIES = {
    "can_observe": [
        "All BLE advertisement frames on the three primary channels (37/38/39)",
        "Received signal strength of each frame at the attacker's location",
        "Timing of frame broadcasts",
        "The serialised Bloom filters B_A and B_B (transmitted in the clear "
        "in the base protocol)",
    ],
    "can_inject": [
        "Crafted BLE advertisement frames with arbitrary payload (active model)",
        "Replayed frames captured from a previous session (replay attack)",
    ],
    "can_replay": [
        "Any previously captured frame or filter message",
    ],
    "can_jam": [
        "Selectively jam BLE advertisement channels to reduce the common frame "
        "set and lower intersection entropy (denial-of-key-agreement attack)",
    ],
    "cannot_do": [
        "Reproduce the precise RSSI/timestamp fingerprint seen by Alice and Bob "
        "from a remote location (spatial decorrelation assumption)",
        "Break SHA-256 pre-image or HKDF security (computational assumption)",
        "Predict or control which frames are received by both Alice and Bob",
    ],
}

SECURITY_GOALS = [
    {
        "id": "SG1",
        "name": "Secrecy",
        "formal": "An eavesdropper who observes all transmitted frames and both "
                  "Bloom filters cannot compute K with probability non-negligibly "
                  "above 1/2^256.",
    },
    {
        "id": "SG2",
        "name": "Indistinguishability from Random",
        "formal": "K is computationally indistinguishable from a uniformly random "
                  "256-bit string to any PPT adversary.",
    },
    {
        "id": "SG3",
        "name": "Resistance to Eavesdropping",
        "formal": "The mutual information I(K; B_A, B_B, Frames_Eve) is negligible, "
                  "where Frames_Eve is the set of frames observed by the eavesdropper.",
    },
    {
        "id": "SG4",
        "name": "Robustness Against Desynchronisation",
        "formal": "The protocol terminates with two identical keys (or both parties "
                  "detect failure) even when Alice and Bob observe partially different "
                  "frame sets (intersection ratio ≥ threshold θ).",
    },
    {
        "id": "SG5",
        "name": "Replay Resistance",
        "formal": "Replaying a filter from a previous session does not allow an "
                  "attacker to force reuse of a previously derived key, because each "
                  "session uses a fresh nonce in the HKDF salt.",
    },
]


# ================================================================== #
#  ASCII Block Diagram (Phase 3 – "Draw system model diagram")       #
# ================================================================== #

SYSTEM_DIAGRAM = r"""
  ┌─────────────────────────────────────────────────────────────────┐
  │                      BLE Radio Environment                       │
  │                                                                  │
  │   ┌──────────┐   BLE Adv Frames    ┌──────────┐                │
  │   │  Alice   │◄───────────────────►│   Bob    │                │
  │   │ (Node A) │                     │ (Node B) │                │
  │   │          │ ─── B_A ──────────► │          │                │
  │   │          │ ◄── B_B ─────────── │          │                │
  │   └────┬─────┘   Filter Exchange   └────┬─────┘                │
  │        │                                │                       │
  │        │  K = HKDF(B_A ∧ B_B)          │  K = HKDF(B_A ∧ B_B)│
  │        ▼                                ▼                       │
  │   [Secure Session]              [Secure Session]                │
  │                                                                  │
  │   ╔══════════════════════════════════════╗                      │
  │   ║  Eve (Passive Eavesdropper)          ║                      │
  │   ║  Sees: all frames, B_A, B_B          ║                      │
  │   ║  Does NOT see: intersection secret   ║                      │
  │   ╚══════════════════════════════════════╝                      │
  └─────────────────────────────────────────────────────────────────┘

  Data flows:
    1. Alice & Bob broadcast BLE adv frames → both collect in sniff mode
    2. Each builds Bloom filter over locally observed frames
    3. Exchange filters via BLE GATT (authenticated with addr-derived HMAC)
    4. Both compute bitwise AND → extract raw key bits
    5. HKDF-SHA256 → 256-bit symmetric key K
    6. Confirm key match via HMAC challenge-response
"""


# ================================================================== #
#  Export                                                            #
# ================================================================== #

def build_model_dict() -> dict:
    return {
        "scenario": SCENARIO,
        "research_questions": RESEARCH_QUESTIONS,
        "constraints_and_assumptions": CONSTRAINTS_AND_ASSUMPTIONS,
        "entities": [e.to_dict() for e in ENTITIES],
        "communication_flows": COMMUNICATION_FLOWS,
        "adversary_capabilities": ADVERSARY_CAPABILITIES,
        "security_goals": SECURITY_GOALS,
    }


def export_model(path: str = "notes/system_model.json") -> None:
    from pathlib import Path
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(build_model_dict(), fh, indent=2)
    print(f"[model] System model exported to {out}")


def print_research_questions() -> None:
    print("\n=== Research Questions ===")
    for rq in RESEARCH_QUESTIONS:
        print(f"\n  {rq['id']}: {rq['question']}")
        print(f"       Metric : {rq['metric']}")
        print(f"       Target : {rq['target']}")


def print_security_goals() -> None:
    print("\n=== Formal Security Goals ===")
    for sg in SECURITY_GOALS:
        print(f"\n  {sg['id']} – {sg['name']}")
        print(textwrap.fill(sg['formal'], width=70,
                            initial_indent="    ",
                            subsequent_indent="    "))


def print_diagram() -> None:
    print(SYSTEM_DIAGRAM)


# ================================================================== #
#  CLI                                                               #
# ================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="Phase 2 & 3 – Problem definition and system model")
    parser.add_argument("--all", action="store_true",
                        help="Print everything and export JSON")
    parser.add_argument("--diagram", action="store_true",
                        help="Print ASCII system model diagram")
    parser.add_argument("--rq", action="store_true",
                        help="Print research questions")
    parser.add_argument("--goals", action="store_true",
                        help="Print formal security goals")
    parser.add_argument("--export", metavar="PATH",
                        default="notes/system_model.json",
                        help="Export full model to JSON file")
    args = parser.parse_args()

    if args.all or args.diagram:
        print_diagram()
    if args.all or args.rq:
        print_research_questions()
    if args.all or args.goals:
        print_security_goals()
    if args.all or args.export:
        export_model(args.export)

    if not any([args.all, args.diagram, args.rq, args.goals]):
        parser.print_help()


if __name__ == "__main__":
    main()
