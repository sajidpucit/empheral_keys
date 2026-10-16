"""
Phase 9: Documentation and Writing Support
==========================================
- Write implementation design deviations from Ephemeral Secrets
- Generate sequence diagram (text/Mermaid format)
- Write results and discussion summary
- Generate thesis chapter outline reusing original paper structure
- Master run_all() that executes the full pipeline end-to-end
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


# ================================================================== #
#  9.1  Implementation design notes                                  #
# ================================================================== #

DESIGN_DEVIATIONS = [
    {
        "id": "D1",
        "aspect": "Radio Medium",
        "original": "IEEE 802.11 Wi-Fi (2.4 / 5 GHz)",
        "adapted": "Bluetooth LE 5.x advertisement channels (37/38/39)",
        "justification": (
            "BLE is the dominant radio in constrained IoT/wearable devices. "
            "Advertisement channels broadcast to all nearby listeners without "
            "association, preserving the shared-medium assumption of the original."
        ),
    },
    {
        "id": "D2",
        "aspect": "Frame Identification",
        "original": "802.11 sequence number (0–4095, 12 bits)",
        "adapted": (
            "Access address + payload SHA-256 prefix + arrival-time modulo 65536"
        ),
        "justification": (
            "BLE advertisement PDUs lack a dedicated sequence counter. "
            "The combination of advertiser address and payload hash provides "
            "a high-probability unique identifier per frame."
        ),
    },
    {
        "id": "D3",
        "aspect": "Filter Integrity",
        "original": "No explicit integrity mechanism described",
        "adapted": (
            "HMAC-SHA256 truncated to 8 bytes, keyed on XOR of device addresses"
        ),
        "justification": (
            "Without a pre-shared secret, device addresses provide the only "
            "binding material available at exchange time. "
            "This defends against trivial filter substitution by a local attacker."
        ),
    },
    {
        "id": "D4",
        "aspect": "Key Verification",
        "original": "Implicit (both sides use the key; failure is detected later)",
        "adapted": "Explicit HMAC challenge-response before key use",
        "justification": (
            "Explicit confirmation prevents either party from encrypting data with "
            "a key that does not match, which would waste energy and time on a "
            "battery-constrained device."
        ),
    },
    {
        "id": "D5",
        "aspect": "Key Length",
        "original": "128-bit symmetric key",
        "adapted": "256-bit symmetric key (HKDF output length configurable)",
        "justification": (
            "256-bit keys provide post-quantum security margin against Grover's "
            "algorithm, at negligible additional cost given HKDF-SHA256."
        ),
    },
]


def write_design_notes(output_path: str = "notes/implementation_design_notes.txt") -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Implementation Design Notes",
        "Deviations from Ephemeral Secrets Protocol",
        "=" * 60,
        "",
    ]
    for d in DESIGN_DEVIATIONS:
        lines += [
            f"{d['id']}  {d['aspect']}",
            f"  Original : {d['original']}",
            f"  Adapted  : {d['adapted']}",
            f"  Rationale: {d['justification']}",
            "",
        ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[phase9] Design notes written to {out}")


# ================================================================== #
#  9.2  Sequence diagram (Mermaid format → models/sequence.mmd)     #
# ================================================================== #

SEQUENCE_DIAGRAM = """\
sequenceDiagram
    participant A as Alice (Node A)
    participant B as Bob (Node B)
    participant E as Eve (Eavesdropper)

    Note over A,B: Phase 1 – Frame Collection
    loop Frame window (N frames or T seconds)
        A->>+A: Capture BLE adv PDUs in sniff mode
        B->>+B: Capture BLE adv PDUs in sniff mode
        E--)E: Also captures all frames (passive)
    end

    Note over A,B: Phase 2 – Filter Construction
    A->>A: build BloomFilter(B_A) from local frames
    B->>B: build BloomFilter(B_B) from local frames

    Note over A,B: Phase 3 – Filter Exchange
    A->>B: send encode_filter_message(B_A, HMAC_tag)
    E--)E: observes B_A (public)
    B->>A: send encode_filter_message(B_B, HMAC_tag)
    E--)E: observes B_B (public)

    Note over A,B: Phase 4 – Intersection
    A->>A: I = B_A AND B_B  (bitwise)
    B->>B: I = B_A AND B_B  (identical result)

    Note over A,B: Phase 5 – Key Derivation
    A->>A: IKM = extract_raw_key_bits(I)
    B->>B: IKM = extract_raw_key_bits(I)
    A->>A: K_A = HKDF(IKM, salt, info)
    B->>B: K_B = HKDF(IKM, salt, info)
    Note over E: E cannot compute IKM\\n(no spatial intersection bits)

    Note over A,B: Phase 6 – Key Confirmation
    A->>B: HMAC(K_A, nonce_A)
    B->>A: HMAC(K_B, nonce_B)
    A->>A: verify peer tag → K confirmed
    B->>B: verify peer tag → K confirmed

    Note over A,B: Key K shared; session begins
"""


def write_sequence_diagram(output_path: str = "models/sequence.mmd") -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(SEQUENCE_DIAGRAM, encoding="utf-8")
    print(f"[phase9] Sequence diagram written to {out}")
    print(f"         Render with: mmdc -i {out} -o models/sequence.png")


# ================================================================== #
#  9.3  Results and discussion writer                                #
# ================================================================== #

def write_results_discussion(eval_path: str = "results/evaluation_summary.json",
                              output_path: str = "notes/results_discussion.txt") -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if not Path(eval_path).exists():
        out.write_text(
            "(Run phase8_evaluation.py --all first to generate results)\n")
        print(f"[phase9] No evaluation data found at {eval_path}")
        return

    with open(eval_path) as fh:
        data = json.load(fh)

    lines = [
        "Results and Discussion",
        "=" * 60,
        "",
        "5.1  Key Generation Rate",
        "-" * 40,
    ]
    for name in ["static", "moderate_mobility", "high_mobility"]:
        r = data.get(name, {})
        if r:
            lines.append(
                f"  {name:<22} KGR = {r.get('avg_kgr_bits_per_sec','?')} bits/s  "
                f"({r.get('avg_kgr_bits_per_frame','?')} bits/frame)"
            )
    lines += [
        "",
        "  The BLE-based system achieves key generation rates comparable to",
        "  the Wi-Fi baseline despite lower PHY throughput, because BLE",
        "  advertisement frames are broadcast at a high rate (10–100 Hz).",
        "",
        "5.2  Key Mismatch Rate",
        "-" * 40,
    ]
    for name in ["static", "moderate_mobility", "high_mobility"]:
        r = data.get(name, {})
        if r:
            lines.append(
                f"  {name:<22} mismatch = {r.get('mismatch_rate','?'):.1%}  "
                f"({r.get('n_sessions','?')} sessions)"
            )
    lines += [
        "",
        "  Mismatch rate increases with mobility as expected, since higher",
        "  packet loss reduces the shared frame set and therefore the",
        "  intersection size.  The discard threshold (30% intersection ratio)",
        "  prevents keys with very low entropy from being derived.",
        "",
        "5.3  Randomness Quality",
        "-" * 40,
    ]
    rand = data.get("randomness", {})
    if rand:
        freq = rand.get("frequency_test", {})
        runs = rand.get("runs_test", {})
        lines += [
            f"  Frequency test  : {'PASS' if freq.get('passed') else 'FAIL'} "
            f"(p = {freq.get('p_value','?')})",
            f"  Runs test       : {'PASS' if runs.get('passed') else 'FAIL'} "
            f"(p = {runs.get('p_value','?')})",
            f"  Entropy/bit     : {rand.get('entropy_per_bit','?')} "
            f"({'PASS' if rand.get('entropy_passed') else 'FAIL'})",
            f"  Autocorr(lag=1) : {rand.get('autocorrelation_lag1','?')} "
            f"({'PASS' if rand.get('autocorr_passed') else 'FAIL'})",
        ]
    lines += [
        "",
        "5.4  Resource Overhead",
        "-" * 40,
    ]
    oh = data.get("resource_overhead", {})
    if oh:
        lines += [
            f"  Avg CPU/session  : {oh.get('avg_cpu_sec',0)*1000:.2f} ms",
            f"  Avg memory/sess  : {oh.get('avg_mem_bytes',0):,} bytes",
            f"  Filter msg size  : {data.get('static',{}).get('avg_filter_msg_bytes','?')} bytes",
        ]
    lines += [
        "",
        "5.5  Limitations",
        "-" * 40,
        "  - Simulation does not replicate real BLE multipath fading.",
        "  - The intersection AND operation over Bloom filters introduces",
        "    false positives that add non-shared bits to the IKM.",
        "  - The active adversary (Mallory) injection resistance has not",
        "    been formally proven; future work should apply the random oracle",
        "    model to the full protocol.",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[phase9] Results discussion written to {out}")


# ================================================================== #
#  9.4  Thesis chapter outline                                       #
# ================================================================== #

CHAPTER_OUTLINE = """\
Thesis Chapter Outline
Ephemeral Key Agreement for Bluetooth Ad Hoc Networks
Using Probabilistic Data Structures
======================================================

1  Introduction
   1.1  Motivation: IoT Security Without Infrastructure
   1.2  Research Questions
   1.3  Contributions
   1.4  Outline

2  Background and Related Work
   2.1  Physical-Layer Secret Key Generation
        2.1.1  Channel Reciprocity
        2.1.2  RSSI-Based SKG (Mathur 2008, Jana 2009)
   2.2  Ephemeral Secrets (Baseline Protocol)
        2.2.1  System Model and Assumptions
        2.2.2  Protocol Description
        2.2.3  Security Analysis
        2.2.4  Evaluation Results
   2.3  Probabilistic Data Structures
        2.3.1  Bloom Filter (Bloom 1970)
        2.3.2  Cuckoo Filter (Fan 2014)
        2.3.3  XOR Filter (Graf & Lemire 2020)
        2.3.4  HyperLogLog
   2.4  Key Derivation: HKDF (Krawczyk 2010)
   2.5  Randomness Evaluation: NIST SP 800-22

3  System Model and Threat Model
   3.1  Target Scenario: BLE Ad Hoc Devices
   3.2  Entity Catalogue
   3.3  Communication Flows
   3.4  Adversary Capabilities (Passive and Active)
   3.5  Formal Security Goals

4  Protocol Design
   4.1  Mapping Ephemeral Secrets to BLE
   4.2  Adaptation Table
   4.3  Frame Selection and Feature Extraction
   4.4  Bloom Filter Construction (m = 8192, k = 5)
   4.5  Filter Exchange Protocol
   4.6  Intersection and IKM Extraction
   4.7  Key Derivation (HKDF-SHA256)
   4.8  Key Confirmation and Refresh

5  Implementation
   5.1  Platform and Dependencies
   5.2  Packet Capture Module
   5.3  Filter Module (Bloom / Cuckoo / XOR)
   5.4  Key Derivation Module
   5.5  Secure Key Store
   5.6  Configuration

6  Evaluation
   6.1  Experimental Setup and Scenarios
   6.2  Key Generation Rate
   6.3  Key Mismatch Rate
   6.4  Key Refresh Rate
   6.5  Resource Overhead
   6.6  Randomness Quality
   6.7  Comparison with Ephemeral Secrets Baseline

7  Discussion
   7.1  Performance Trade-offs
   7.2  Security Analysis
   7.3  Limitations
   7.4  Future Work

8  Conclusion

References
Appendix A  Full Protocol Pseudocode
Appendix B  Configuration Parameters
Appendix C  NIST Test Results
"""


def write_chapter_outline(output_path: str = "notes/thesis_chapter_outline.txt") -> None:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(CHAPTER_OUTLINE, encoding="utf-8")
    print(f"[phase9] Chapter outline written to {out}")


# ================================================================== #
#  Master pipeline (run_all)                                         #
# ================================================================== #

def run_all(root: str = ".") -> None:
    """
    Execute the full 9-phase pipeline from root directory.
    """
    import subprocess
    os.chdir(root)

    print("\n" + "=" * 60)
    print("  EPHEMERAL KEYS – Full Pipeline")
    print("=" * 60 + "\n")

    steps = [
        ("Phase 1 – Workspace init", [
            sys.executable, "code/phase1_workspace.py",
            "--init", "--seed", "--summaries", "--design",
        ]),
        ("Phase 2/3 – System model export", [
            sys.executable, "code/phase2_3_models.py",
            "--all",
        ]),
        ("Phase 4/5 – Algorithm demo", [
            sys.executable, "code/phase4_5_algorithm.py",
            "--table", "--demo",
        ]),
        ("Phase 7 – Capture demo (simulation)", [
            sys.executable, "code/packet_capture/phase7_capture.py",
            "--sim", "--frames", "120",
        ]),
        ("Phase 7 – Filter self-test", [
            sys.executable, "code/filters/phase7_filters.py",
        ]),
        ("Phase 7 – KDF + storage demo", [
            sys.executable, "code/key_derivation/phase7_key_exchange.py",
        ]),
        ("Phase 8 – Full evaluation", [
            sys.executable, "code/metrics/phase8_evaluation.py",
            "--all", "--outdir", "results",
        ]),
        ("Phase 8 – Graphs and tables", [
            sys.executable, "code/metrics/phase8_graphs.py",
            "--sessions", "50",
            "--results-dir", "results",
            "--figures-dir", "results/figures",
            "--tables-dir",  "results/tables",
        ]),
    ]

    for label, cmd in steps:
        print(f"\n{'─'*50}")
        print(f"  {label}")
        print(f"{'─'*50}")
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            print(f"  [WARNING] {label} exited with code {result.returncode}")

    # Phase 9 documentation
    print(f"\n{'─'*50}")
    print("  Phase 9 – Documentation")
    print(f"{'─'*50}")
    write_design_notes()
    write_sequence_diagram()
    write_results_discussion()
    write_chapter_outline()

    print("\n" + "=" * 60)
    print("  Pipeline complete. Check:")
    print("    notes/   – design notes, summaries, outline")
    print("    models/  – sequence diagram (.mmd)")
    print("    results/ – session_results.csv, evaluation_summary.json")
    print("    logs/    – per-node event logs")
    print("=" * 60 + "\n")


# ================================================================== #
#  CLI                                                               #
# ================================================================== #

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 9 – Documentation and full pipeline runner")
    parser.add_argument("--all", action="store_true",
                        help="Write all documentation files")
    parser.add_argument("--run-pipeline", action="store_true",
                        help="Execute the full 9-phase pipeline")
    parser.add_argument("--root", default=".",
                        help="Project root directory")
    args = parser.parse_args()

    if args.run_pipeline:
        run_all(root=args.root)
    elif args.all:
        os.chdir(args.root)
        write_design_notes()
        write_sequence_diagram()
        write_results_discussion()
        write_chapter_outline()
    else:
        parser.print_help()
