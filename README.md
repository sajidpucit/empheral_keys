# Bloom-Filter-Based Ephemeral Key Agreement for Bluetooth LE Ad Hoc Networks

Source code and results for the paper:

> M. Sajid, S. A. Gillani, P. A. Shah, M. K. Ehsan, S. Ahmed, H. O. Ali,
> "Bloom-Filter-Based Ephemeral Key Agreement for Bluetooth LE Ad Hoc Networks," 2026.

Two co-located BLE devices reconcile the advertisement frames they both observe on
channels 37/38/39 through Bloom filters and derive a shared 256-bit key with
HKDF-SHA256, without a pre-shared secret or a public-key infrastructure.
The evaluation is a simulation-based feasibility study (i.i.d. Bernoulli frame loss,
three mobility scenarios, 30 sessions each).

The core protocol and evaluation use only the Python standard library.
`matplotlib` and `numpy` are needed only to regenerate the figures.

## Repository layout

```
ble-bloom-plkg/
├── config/config.yaml                    # protocol and evaluation parameters
├── code/
│   ├── packet_capture/phase7_capture.py  # Architecture Modules 1-2: frame capture, SHA-256 features
│   ├── filters/phase7_filters.py         # Module 3: Bloom, Cuckoo, XOR filters (+ HyperLogLog)
│   ├── key_derivation/phase7_key_exchange.py
│   │                                     # Modules 4-8: HMAC-tagged filter exchange (TCP),
│   │                                     # HKDF-SHA256, HMAC challenge-response, SecureKeyStore
│   ├── metrics/phase8_evaluation.py      # scenario evaluation, NIST SP 800-22 subset, CSV/JSON export
│   ├── metrics/phase8_graphs.py          # figures and tables
│   ├── generate_report.py                # HTML report from figures and tables
│   ├── phase1_workspace.py               # workspace and reference management
│   ├── phase2_3_models.py                # problem definition, system and threat model
│   ├── phase4_5_algorithm.py             # protocol specification and step-by-step demo
│   └── phase9_documentation.py           # documentation and full-pipeline runner
└── results/                              # outputs reported in the paper
    ├── session_results.csv               # per-session results (paper, Appendix A)
    ├── evaluation_summary.json           # aggregated results and randomness tests
    ├── tables/                           # scenario summary, randomness, overhead, filter sweep, per-session
    ├── figures/                          # evaluation figures
    ├── pcap/                             # example simulated capture (one session, nodes A and B)
    └── report.html                       # all figures and tables in one page
```

## Requirements

* Python 3.9 or later (uses `random.randbytes` and `int.bit_count`)
* For figures only: `pip install -r requirements.txt`

## Reproducing the results

Run from the repository root. Writing to a new folder keeps the published
`results/` untouched.

```bash
# Full evaluation: 3 scenarios x 30 sessions, randomness tests, resource overhead,
# then all figures, tables and the HTML report
python code/metrics/phase8_evaluation.py --all --outdir results_rerun

# One scenario only
python code/metrics/phase8_evaluation.py --scenario static --sessions 30 --outdir results_rerun

# Figures and tables only (from an existing evaluation_summary.json)
python code/metrics/phase8_graphs.py --results-dir results_rerun \
       --figures-dir results_rerun/figures --tables-dir results_rerun/tables --sessions 30
```

### What reproduces exactly and what does not

All sessions use fixed seeds, so the following values reproduce bit-for-bit on any
machine: frames captured per node, filter set bits, intersection bits and ratio,
success and mismatch flags, key length, bits per frame, and the Bloom filter
parameter sweep.

Values that depend on wall-clock time vary with the machine and its load:
elapsed time per session, key generation rate in bits/s (computed as
256 bits / elapsed time), CPU time, and memory. The randomness-test p-values
also vary between runs, because the keys they test are derived from the
per-session result records, which include the elapsed time.

## Running the individual modules

```bash
python code/filters/phase7_filters.py                         # filter self-test
python code/packet_capture/phase7_capture.py --sim --frames 120
python code/key_derivation/phase7_key_exchange.py             # HKDF, confirmation, key store demo
python code/phase4_5_algorithm.py --table --demo              # protocol walk-through
python code/phase9_documentation.py --run-pipeline            # all phases in order
```

The capture module runs in simulation mode by default. Optional packages for
real-hardware capture (`pyshark`, `scapy`, `bleak`) are not needed for any result
in the paper.

## Main parameters

| Parameter | Value |
|---|---|
| Bloom filter size *m* | 8,192 bits (1 kB) |
| Hash functions *k* | 5 (HMAC-SHA256 based) |
| Minimum intersection | 64 bits |
| Key derivation | HKDF-SHA256, 256-bit output |
| Frame-loss probability | 0.05 (static), 0.15 (moderate), 0.30 (high) |
| Sessions | 30 per scenario, 90 in total |

## Licence

MIT, see [LICENSE](LICENSE).

## Citation

If you use this code, please cite the paper (see [CITATION.cff](CITATION.cff)).
