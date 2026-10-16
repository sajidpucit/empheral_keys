"""
Phase 1: Understand the Baseline
=================================
- Create project workspace
- Manage references (download, classify, summarise)
- Extract key design choices from the baseline paper (Ephemeral Secrets)

Usage:
    python phase1_workspace.py --init
    python phase1_workspace.py --classify refs.csv
    python phase1_workspace.py --summarise
"""

import os
import json
import hashlib
import argparse
import textwrap
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ------------------------------------------------------------------ #
#  Workspace initialisation (Phase 1 – "Create project workspace")   #
# ------------------------------------------------------------------ #

WORKSPACE_DIRS = [
    "papers",
    "notes",
    "models",
    "code",
    "results",
    "config",
    "logs",
    "results/pcap",
]

def init_workspace(root: str = ".") -> None:
    """Create the full folder structure for the project."""
    root_path = Path(root)
    for d in WORKSPACE_DIRS:
        (root_path / d).mkdir(parents=True, exist_ok=True)
    print(f"[workspace] Directories created under '{root_path.resolve()}':")
    for d in WORKSPACE_DIRS:
        print(f"  {root_path / d}")


# ------------------------------------------------------------------ #
#  Reference data model                                               #
# ------------------------------------------------------------------ #

REFERENCE_CATEGORIES = [
    "background_skg",
    "bloom_filters_related",
    "wireless_ad_hoc",
    "security_analysis",
    "evaluation_metrics",
]


@dataclass
class Reference:
    """Represents one cited paper with metadata for Phase 1 classification."""

    ref_id: str                             # e.g. "hershey2010"
    title: str
    authors: List[str]
    year: int
    venue: str = ""
    pdf_path: Optional[str] = None
    categories: List[str] = field(default_factory=list)
    summary: str = ""                       # problem / method / key idea / connection

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Reference":
        return cls(**d)

    def validate_categories(self) -> bool:
        return all(c in REFERENCE_CATEGORIES for c in self.categories)

    def one_paragraph_summary(self) -> str:
        """Return a formatted one-paragraph summary for the notes file."""
        wrap = textwrap.fill
        header = f"[{self.ref_id}] {self.title} ({self.year})"
        body = self.summary if self.summary else "(no summary yet)"
        cats = ", ".join(self.categories) if self.categories else "unclassified"
        return f"{header}\nCategories: {cats}\n{wrap(body, width=80)}\n"


# ------------------------------------------------------------------ #
#  Reference database (JSON-backed, lives in /notes)                 #
# ------------------------------------------------------------------ #

class ReferenceDatabase:
    """Simple JSON-backed store for all project references."""

    def __init__(self, db_path: str = "notes/references.json"):
        self.db_path = Path(db_path)
        self._refs: dict[str, Reference] = {}
        if self.db_path.exists():
            self._load()

    def _load(self) -> None:
        with open(self.db_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        self._refs = {k: Reference.from_dict(v) for k, v in raw.items()}
        print(f"[refs] Loaded {len(self._refs)} references from {self.db_path}")

    def save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, "w", encoding="utf-8") as fh:
            json.dump({k: v.to_dict() for k, v in self._refs.items()},
                      fh, indent=2)
        print(f"[refs] Saved {len(self._refs)} references to {self.db_path}")

    def add(self, ref: Reference) -> None:
        if not ref.validate_categories():
            bad = [c for c in ref.categories if c not in REFERENCE_CATEGORIES]
            raise ValueError(f"Unknown categories: {bad}. "
                             f"Allowed: {REFERENCE_CATEGORIES}")
        self._refs[ref.ref_id] = ref

    def get(self, ref_id: str) -> Optional[Reference]:
        return self._refs.get(ref_id)

    def all(self) -> List[Reference]:
        return list(self._refs.values())

    def by_category(self, category: str) -> List[Reference]:
        return [r for r in self._refs.values() if category in r.categories]

    def write_summaries(self, output_path: str = "notes/reference_summaries.txt") -> None:
        """Write all one-paragraph summaries to a plain-text notes file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for cat in REFERENCE_CATEGORIES:
            refs_in_cat = self.by_category(cat)
            if not refs_in_cat:
                continue
            lines.append("=" * 70)
            lines.append(f"CATEGORY: {cat.upper()}")
            lines.append("=" * 70)
            for r in refs_in_cat:
                lines.append(r.one_paragraph_summary())
        out.write_text("\n".join(lines), encoding="utf-8")
        print(f"[refs] Summaries written to {out}")


# ------------------------------------------------------------------ #
#  Key design choices of Ephemeral Secrets (Phase 1 extraction)      #
# ------------------------------------------------------------------ #

EPHEMERAL_SECRETS_DESIGN = {
    "network_setting": (
        "IEEE 802.11 wireless ad hoc (IBSS) network. "
        "Two co-located devices that can observe a shared radio environment."
    ),
    "adversary_model": (
        "Passive eavesdropper located outside the physical proximity of the "
        "two communicating nodes. The attacker can capture wireless frames but "
        "cannot reproduce the fine-grained channel measurements observed by "
        "the legitimate parties."
    ),
    "frame_capture_process": (
        "Both nodes place their Wi-Fi interface into monitor (promiscuous) mode "
        "and record all 802.11 frames in a fixed-length time window. Frames are "
        "identified by sequence number and timestamp."
    ),
    "filter_construction": (
        "Each node hashes the fields of every captured frame into a Bloom filter "
        "(bit array of length m with k independent hash functions). The filter "
        "compactly represents the set of locally observed frames."
    ),
    "key_derivation": (
        "The two nodes exchange their Bloom filters over the air. They compute "
        "the bitwise AND (intersection approximation) of the two filters to find "
        "frames observed by both. The bits at intersection positions are "
        "concatenated to form a raw key material, which is then passed through "
        "HKDF-SHA256 to derive the final symmetric key."
    ),
    "evaluation_metrics": (
        "Key generation rate (bits/s), key mismatch rate (fraction of sessions "
        "where the two sides derive different keys), key entropy / randomness "
        "(NIST SP 800-22 subset), and communication overhead (bytes per session)."
    ),
}


def write_design_notes(output_path: str = "notes/ephemeral_secrets_design.txt") -> None:
    """Write the one-page design notes for Ephemeral Secrets."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Ephemeral Secrets – Key Design Choices",
        "=" * 50,
        "",
    ]
    for key, value in EPHEMERAL_SECRETS_DESIGN.items():
        lines.append(f"  {key.replace('_', ' ').upper()}")
        lines.append(textwrap.fill(value, width=76, initial_indent="    ",
                                   subsequent_indent="    "))
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[design] Design notes written to {out}")


# ------------------------------------------------------------------ #
#  Seed the database with illustrative references                     #
# ------------------------------------------------------------------ #

SEED_REFERENCES = [
    Reference(
        ref_id="hershey1995",
        title="Effective eavesdropping and secret key agreement in wireless networks",
        authors=["J. Hershey", "A. Hassan", "R. Yarlagadda"],
        year=1995,
        venue="IEEE Transactions on Communications",
        categories=["background_skg"],
        summary=(
            "Problem: Establish a secret shared key using the wireless channel. "
            "Method: Exploit physical-layer randomness of the channel. "
            "Key idea: Both ends of a wireless link observe the same fading "
            "coefficients; a passive eavesdropper at a different location sees "
            "decorrelated channel. Connection: Foundational motivation for all "
            "SKG work including Ephemeral Secrets."
        ),
    ),
    Reference(
        ref_id="bloom1970",
        title="Space/time trade-offs in hash coding with allowable errors",
        authors=["B. Bloom"],
        year=1970,
        venue="CACM",
        categories=["bloom_filters_related"],
        summary=(
            "Problem: Membership testing with limited memory. "
            "Method: Bit array with k hash functions; allow controllable false "
            "positives. "
            "Key idea: Compact probabilistic set representation. "
            "Connection: Ephemeral Secrets uses Bloom filters to summarise the "
            "set of locally observed 802.11 frames."
        ),
    ),
    Reference(
        ref_id="fan2014cuckoo",
        title="Cuckoo filter: practically better than Bloom",
        authors=["B. Fan", "D. Andersen", "M. Kaminsky", "M. Mitzenmacher"],
        year=2014,
        venue="CoNEXT",
        categories=["bloom_filters_related"],
        summary=(
            "Problem: Bloom filters do not support deletion; FPR degrades. "
            "Method: Fingerprint-based cuckoo hashing. "
            "Key idea: Better space efficiency at low FPR; supports deletion. "
            "Connection: Potential drop-in replacement for Bloom filter in "
            "Ephemeral Secrets to improve accuracy."
        ),
    ),
    Reference(
        ref_id="mathur2008radio",
        title="Radio-telepathy: Extracting a secret key from an unauthenticated "
               "wireless channel",
        authors=["S. Mathur", "W. Trappe", "N. Mandayam", "C. Ye", "A. Reznik"],
        year=2008,
        venue="MobiCom",
        categories=["background_skg", "wireless_ad_hoc"],
        summary=(
            "Problem: Key agreement without pre-shared secrets in ad hoc networks. "
            "Method: RSSI-based secret key extraction with quantisation and "
            "information reconciliation. "
            "Key idea: Level-crossing algorithm for key bit generation. "
            "Connection: Provides baseline metrics (KGR, mismatch rate) compared "
            "in Ephemeral Secrets."
        ),
    ),
    Reference(
        ref_id="jana2009effectiveness",
        title="On the effectiveness of secret key extraction from wireless signal "
               "strength in real environments",
        authors=["S. Jana", "S. N. Premnath", "M. Clark",
                 "S. K. Kasera", "N. Patwari", "S. V. Krishnamurthy"],
        year=2009,
        venue="MobiCom",
        categories=["background_skg", "security_analysis"],
        summary=(
            "Problem: Empirical evaluation of RSSI-based SKG in realistic settings. "
            "Method: Experiments with 802.11 devices in indoor/outdoor environments. "
            "Key idea: Environment dynamics heavily influence KGR; static nodes "
            "yield very low rates. "
            "Connection: Motivates the packet-timing approach in Ephemeral Secrets "
            "as an alternative to pure RSSI."
        ),
    ),
    Reference(
        ref_id="bellare1993random",
        title="Random oracles are practical: A paradigm for designing efficient protocols",
        authors=["M. Bellare", "P. Rogaway"],
        year=1993,
        venue="CCS",
        categories=["security_analysis"],
        summary=(
            "Problem: Formal security proofs for hash-based protocols. "
            "Method: Random oracle model. "
            "Key idea: Ideal hash functions enable provably secure constructions. "
            "Connection: Justifies the security of HKDF-based key derivation used "
            "in Ephemeral Secrets."
        ),
    ),
    Reference(
        ref_id="krawczyk2010hkdf",
        title="Cryptographic extraction and key derivation: The HKDF scheme",
        authors=["H. Krawczyk"],
        year=2010,
        venue="CRYPTO",
        categories=["security_analysis"],
        summary=(
            "Problem: Derive cryptographically strong keys from weak/biased input. "
            "Method: Two-step HMAC-based KDF (extract then expand). "
            "Key idea: HKDF provides composable, provably secure key derivation. "
            "Connection: Ephemeral Secrets uses HKDF to stretch the raw intersection "
            "bits into usable symmetric keys."
        ),
    ),
    Reference(
        ref_id="nist80022",
        title="A statistical test suite for random and pseudorandom number generators",
        authors=["A. Rukhin et al."],
        year=2010,
        venue="NIST Special Publication 800-22",
        categories=["evaluation_metrics"],
        summary=(
            "Problem: Standardised evaluation of key/random bit quality. "
            "Method: Battery of 15 statistical tests (frequency, runs, spectral, etc.). "
            "Key idea: Provides pass/fail thresholds for randomness. "
            "Connection: Ephemeral Secrets cites NIST SP 800-22 tests for key "
            "quality evaluation; we replicate a subset in our metrics module."
        ),
    ),
]


def seed_references(db: ReferenceDatabase) -> None:
    """Populate the database with seed references."""
    for ref in SEED_REFERENCES:
        db.add(ref)
    db.save()
    print(f"[refs] Seeded {len(SEED_REFERENCES)} references.")


# ------------------------------------------------------------------ #
#  CLI entry point                                                    #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="Phase 1 – Workspace and reference management")
    parser.add_argument("--init", action="store_true",
                        help="Initialise workspace directories")
    parser.add_argument("--seed", action="store_true",
                        help="Seed reference database with baseline references")
    parser.add_argument("--summaries", action="store_true",
                        help="Write reference summaries to notes/")
    parser.add_argument("--design", action="store_true",
                        help="Write Ephemeral Secrets design notes")
    parser.add_argument("--root", default=".",
                        help="Project root directory (default: current dir)")
    args = parser.parse_args()

    os.chdir(args.root)

    if args.init:
        init_workspace()

    db = ReferenceDatabase("notes/references.json")

    if args.seed:
        seed_references(db)

    if args.summaries:
        db.write_summaries()

    if args.design:
        write_design_notes()

    if not any([args.init, args.seed, args.summaries, args.design]):
        parser.print_help()


if __name__ == "__main__":
    main()
