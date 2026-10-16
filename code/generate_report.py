"""
Phase 9 – HTML Report Generator
=================================
Produces a single self-contained HTML file that embeds every PNG figure
and every CSV table as an interactive, styled report.
Opens directly in any browser — no server required.

Usage:
    python generate_report.py
    python generate_report.py --figures results/figures \
                               --tables  results/tables  \
                               --out     results/report.html
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
from pathlib import Path


# ── ordered figure manifest ───────────────────────────────────────
FIGURES = [
    ("01_kgr_by_scenario.png",
     "Figure 1 – Key Generation Rate by Scenario",
     "Average KGR (bits/s) for static, moderate-mobility, and high-mobility "
     "scenarios compared to the Ephemeral Secrets Wi-Fi baseline (dashed line). "
     "All three BLE scenarios significantly exceed the baseline owing to the high "
     "advertisement broadcast frequency."),

    ("02_kgr_per_frame.png",
     "Figure 2 – Key Generation Rate per Captured Frame",
     "Bits of key material derived per captured frame. Higher packet loss "
     "(high-mobility scenario) reduces the frame count but the remaining frames "
     "contribute proportionally more intersection bits, keeping the per-frame "
     "rate roughly stable."),

    ("03_mismatch_rate.png",
     "Figure 3 – Session Success vs Mismatch Rate",
     "Stacked bar showing the fraction of sessions that produced a matched key "
     "(green) vs sessions that were discarded due to insufficient intersection "
     "(red). The baseline mismatch rate from Ephemeral Secrets is shown as a "
     "dashed reference."),

    ("04_intersection_bits_boxplot.png",
     "Figure 4 – Intersection Bit Count Distribution (Box Plot)",
     "Distribution of the number of set bits in the Bloom filter intersection "
     "(B_A AND B_B) across all sessions per scenario. The median and IQR fall "
     "as mobility increases, reflecting higher packet loss."),

    ("05_intersection_bits_violin.png",
     "Figure 5 – Intersection Bit Count Distribution (Violin)",
     "Violin plot version of Figure 4, showing the full density of the "
     "intersection bit count. The wide, symmetric shape in the static scenario "
     "narrows and shifts downward with mobility."),

    ("06_filter_fill_ratio.png",
     "Figure 6 – Bloom Filter Fill Ratio per Session",
     "Fraction of bits set in each node's Bloom filter over successive sessions. "
     "A fill ratio below ~15% is ideal; higher fill ratios increase false-positive "
     "rates and degrade intersection accuracy."),

    ("07_session_latency.png",
     "Figure 7 – Session Processing Latency Distribution",
     "Histogram of total CPU time (ms) per session including filter construction, "
     "intersection, and HKDF derivation. All scenarios complete in well under "
     "100 ms, satisfying the IoT energy budget."),

    ("08_resource_overhead.png",
     "Figure 8 – Resource Overhead: Bandwidth and CPU Time",
     "Left: filter exchange message size (bytes) per scenario vs the Ephemeral "
     "Secrets baseline. Our 2×1 kB filters are larger due to the 256-bit key "
     "length increase. Right: average CPU time per session in milliseconds."),

    ("09_randomness_pvalues.png",
     "Figure 9 – NIST SP 800-22 Subset Randomness Test Results",
     "p-values for four randomness tests applied to the concatenated key bit "
     "stream from all derived keys. All p-values exceed the α = 0.01 significance "
     "threshold (dashed), confirming cryptographic quality."),

    ("10_entropy_per_scenario.png",
     "Figure 10 – Per-Session Key Entropy by Scenario",
     "Shannon entropy (bits per bit) of each derived key across sessions. "
     "Values close to 1.0 indicate uniform, unpredictable key bits. "
     "All scenarios maintain near-ideal entropy throughout."),

    ("11_kgr_vs_loss.png",
     "Figure 11 – KGR Sensitivity to Packet Loss Rate",
     "Sweep of average KGR as packet loss probability varies from 0% to 50%. "
     "The shaded band shows ±1 standard deviation. KGR degrades gracefully; "
     "sessions fail (KGR = 0) only at very high loss rates above ~45%."),

    ("12_fpr_vs_m.png",
     "Figure 12 – Bloom Filter False Positive Rate vs Filter Size",
     "Theoretical FPR curve for k=5 hash functions and n=150 items as filter "
     "size m varies. Our chosen configuration (m=8192 bits, vertical dashed line) "
     "sits comfortably below the 1% FPR target."),

    ("13_fpr_vs_k.png",
     "Figure 13 – Bloom FPR vs Number of Hash Functions",
     "FPR as a function of k for m=8192 bits and n=150 items. The optimal k is "
     "highlighted in green; our choice of k=5 is confirmed as near-optimal for "
     "these parameters."),

    ("14_bloom_vs_cuckoo_size.png",
     "Figure 14 – Filter Memory Footprint: Bloom vs Cuckoo vs XOR",
     "Memory footprint (bytes) of the three filter types as the number of items "
     "increases. At our operating point (n=150, dashed line), all three fit comfortably "
     "within the 4 kB RAM budget, with XOR being the most compact."),

    ("15_key_bit_distribution.png",
     "Figure 15 – Derived Key Byte-Value Distribution",
     "Histogram of all byte values across every derived key. The distribution "
     "closely follows the uniform expectation line (dashed), visually confirming "
     "the absence of obvious bias in the key material."),

    ("16_comparison_baseline.png",
     "Figure 16 – This Work vs Ephemeral Secrets Baseline",
     "Grouped bar chart (log-scale y-axis) comparing four key metrics between "
     "this BLE-adapted system and the original Ephemeral Secrets Wi-Fi protocol. "
     "Our system surpasses baseline KGR and achieves zero mismatch, at the cost "
     "of a slightly larger filter message."),

    ("17_session_timeline.png",
     "Figure 17 – Cumulative Successful Sessions Over Time",
     "Cumulative count of successfully completed SKG sessions as a function of "
     "session index. The linear growth in all scenarios indicates consistent, "
     "reliable key agreement throughout the evaluation."),

    ("18_kgr_trend.png",
     "Figure 18 – KGR Trend (Rolling Average)",
     "Rolling-window (window=5) average of KGR per session. The stable, flat "
     "trend across all scenarios confirms that performance does not degrade "
     "over time — there is no warm-up or cool-down effect."),
]

# ── ordered table manifest ────────────────────────────────────────
TABLES = [
    ("table_01_scenario_summary.csv",
     "Table 1 – Aggregated Results per Scenario",
     "Main performance summary: success rate, mismatch rate, KGR, intersection "
     "size, CPU time, and filter bandwidth for each test scenario."),

    ("table_02_randomness_tests.csv",
     "Table 2 – NIST SP 800-22 Subset Randomness Test Results",
     "Detailed results of four NIST-based statistical tests applied to all "
     "derived key bits. Each row shows the test name, computed p-value, "
     "acceptance threshold, and PASS/FAIL verdict."),

    ("table_03_resource_overhead.csv",
     "Table 3 – Resource Overhead Summary",
     "CPU time and filter exchange message size per scenario, including the "
     "percentage overhead relative to the Ephemeral Secrets baseline."),

    ("table_04_baseline_comparison.csv",
     "Table 4 – Comparison with Ephemeral Secrets Baseline",
     "Side-by-side comparison of six metrics between this work and the original "
     "Ephemeral Secrets paper, including both quantitative and qualitative "
     "differences."),

    ("table_05_filter_parameters.csv",
     "Table 5 – Optimal Bloom Filter Parameter Sweep",
     "Theoretical optimal Bloom filter parameters (m, k, actual FPR, memory) "
     "for a range of item counts (n = 50–500) and target FPR values "
     "(0.001 – 0.05), with feasibility flags for the 4 kB RAM budget."),

    ("table_06_per_session_detail.csv",
     "Table 6 – Per-Session Detail",
     "Raw per-session data for all 150 sessions (50 × 3 scenarios): frame "
     "counts, intersection statistics, key generation outcome, latency, and KGR."),
]


# ── CSS + JS ──────────────────────────────────────────────────────
STYLE = """
:root {
  --blue:   #2E86AB;
  --amber:  #F18F01;
  --red:    #C73E1D;
  --dark:   #1a1a2e;
  --mid:    #16213e;
  --card:   #0f3460;
  --text:   #e0e0e0;
  --muted:  #a0aec0;
  --pass:   #4CAF50;
  --fail:   #F44336;
  --accent: #7B2D8B;
  --border: rgba(255,255,255,0.10);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', Arial, sans-serif;
  background: var(--dark);
  color: var(--text);
  line-height: 1.65;
}
header {
  background: linear-gradient(135deg, var(--mid) 0%, var(--card) 100%);
  padding: 3rem 2rem 2rem;
  text-align: center;
  border-bottom: 2px solid var(--blue);
}
header h1 { font-size: 2rem; color: #fff; margin-bottom: .5rem; }
header p  { color: var(--muted); font-size: 1rem; max-width: 700px; margin: 0 auto; }
.badge {
  display: inline-block;
  background: var(--blue);
  color: #fff;
  border-radius: 20px;
  padding: .2rem .8rem;
  font-size: .78rem;
  margin: .2rem;
}
nav {
  background: var(--mid);
  padding: .8rem 1.5rem;
  position: sticky;
  top: 0;
  z-index: 100;
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-wrap: wrap;
  gap: .5rem;
  align-items: center;
}
nav a {
  color: var(--muted);
  text-decoration: none;
  font-size: .85rem;
  padding: .3rem .7rem;
  border-radius: 6px;
  transition: background .2s, color .2s;
}
nav a:hover { background: var(--card); color: #fff; }
nav span { color: var(--blue); font-weight: bold; margin-right: .5rem; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }
h2 {
  font-size: 1.5rem;
  color: var(--blue);
  border-left: 4px solid var(--blue);
  padding-left: .75rem;
  margin: 2.5rem 0 1.2rem;
}
h3 { font-size: 1.1rem; color: #fff; margin-bottom: .5rem; }
.section-intro {
  color: var(--muted);
  font-size: .95rem;
  margin-bottom: 1.5rem;
  max-width: 800px;
}
.fig-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(520px, 1fr));
  gap: 1.5rem;
}
.fig-card {
  background: var(--mid);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  transition: transform .2s, box-shadow .2s;
}
.fig-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 30px rgba(0,0,0,.4);
}
.fig-card img {
  width: 100%;
  display: block;
  background: #fff;
}
.fig-caption {
  padding: .9rem 1rem;
}
.fig-caption h3 { color: var(--blue); font-size: .95rem; }
.fig-caption p  { color: var(--muted); font-size: .83rem; margin-top: .35rem; line-height: 1.5; }
.tbl-card {
  background: var(--mid);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 2rem;
}
.tbl-header {
  padding: .9rem 1.2rem;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: .5rem;
}
.tbl-header h3 { color: var(--blue); font-size: 1rem; }
.tbl-header p  { color: var(--muted); font-size: .82rem; max-width: 700px; line-height: 1.45; }
.tbl-scroll { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: .82rem;
}
thead th {
  background: var(--card);
  color: #fff;
  padding: .55rem .9rem;
  text-align: left;
  white-space: nowrap;
  border-bottom: 2px solid var(--blue);
}
tbody tr:nth-child(even) { background: rgba(255,255,255,.03); }
tbody tr:hover           { background: rgba(46,134,171,.15); }
tbody td {
  padding: .45rem .9rem;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  color: var(--text);
}
td.pass { color: var(--pass); font-weight: bold; }
td.fail { color: var(--fail); font-weight: bold; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
  gap: 1rem;
  margin: 1.5rem 0;
}
.stat-card {
  background: var(--mid);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem 1.2rem;
  text-align: center;
}
.stat-card .val  { font-size: 1.8rem; font-weight: bold; color: var(--blue); }
.stat-card .lbl  { font-size: .78rem; color: var(--muted); margin-top: .25rem; }
footer {
  text-align: center;
  padding: 2rem;
  color: var(--muted);
  font-size: .82rem;
  border-top: 1px solid var(--border);
  margin-top: 3rem;
}
@media (max-width: 600px) {
  .fig-grid { grid-template-columns: 1fr; }
  header h1 { font-size: 1.4rem; }
}
"""

JS = """
// Highlight PASS/FAIL cells
document.querySelectorAll('tbody td').forEach(td => {
  if (td.textContent.trim() === 'PASS') td.classList.add('pass');
  if (td.textContent.trim() === 'FAIL') td.classList.add('fail');
  if (td.textContent.trim() === 'Yes')  td.style.color = '#4CAF50';
  if (td.textContent.trim() === 'No')   td.style.color = '#F44336';
});
// Smooth scroll for nav links
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const t = document.querySelector(a.getAttribute('href'));
    if (t) t.scrollIntoView({behavior:'smooth', block:'start'});
  });
});
"""


# ── helper: encode PNG as base64 data-URI ─────────────────────────
def png_to_data_uri(path: Path) -> str:
    data = base64.b64encode(path.read_bytes()).decode()
    return f"data:image/png;base64,{data}"


# ── helper: load CSV as list-of-dicts ─────────────────────────────
def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ── HTML builders ─────────────────────────────────────────────────
def build_stat_cards(fig_dir: Path, tbl_dir: Path) -> str:
    """Top-level summary stat cards derived from table_01."""
    tbl1 = tbl_dir / "table_01_scenario_summary.csv"
    if not tbl1.exists():
        return ""
    rows = load_csv(tbl1)
    static = next((r for r in rows if "static" in r.get("Scenario","")), rows[0] if rows else {})

    stats = [
        (static.get("Avg KGR (bits/s)", "—"), "Avg KGR (bits/s) – Static"),
        (static.get("Success Rate (%)", "—") + "%", "Session Success Rate"),
        (static.get("Avg CPU (ms)", "—") + " ms", "Avg Session CPU Time"),
        (static.get("Key Length (bits)", "256"), "Key Length (bits)"),
        (str(len(list(fig_dir.glob("*.png")))), "Figures Generated"),
        (static.get("Filter Msg (B)", "—") + " B", "Filter Msg Size"),
    ]
    cards = []
    for val, label in stats:
        cards.append(
            f'<div class="stat-card">'
            f'<div class="val">{val}</div>'
            f'<div class="lbl">{label}</div>'
            f'</div>'
        )
    return '<div class="stats-grid">' + "".join(cards) + "</div>"


def build_figures_section(fig_dir: Path) -> str:
    parts = ['<h2 id="figures">📊 Performance Figures</h2>',
             '<p class="section-intro">All 18 figures are auto-generated from the '
             'simulation results. Hover over a card to highlight it. '
             'Right-click → Save image to export any figure.</p>',
             '<div class="fig-grid">']
    for fname, title, caption in FIGURES:
        path = fig_dir / fname
        if not path.exists():
            continue
        uri = png_to_data_uri(path)
        parts.append(
            f'<div class="fig-card">'
            f'<img src="{uri}" alt="{title}" loading="lazy">'
            f'<div class="fig-caption">'
            f'<h3>{title}</h3>'
            f'<p>{caption}</p>'
            f'</div></div>'
        )
    parts.append("</div>")
    return "\n".join(parts)


def build_tables_section(tbl_dir: Path) -> str:
    parts = ['<h2 id="tables">📋 Performance Tables</h2>',
             '<p class="section-intro">All 6 tables are also available as '
             'individual CSV files in <code>results/tables/</code>.</p>']

    for fname, title, description in TABLES:
        path = tbl_dir / fname
        if not path.exists():
            continue
        rows = load_csv(path)
        if not rows:
            continue
        headers = list(rows[0].keys())

        # Limit per_session_detail table to first 30 rows in HTML (full data in CSV)
        display_rows = rows[:30] if "per_session" in fname else rows
        footnote = (f'<p style="color:var(--muted);font-size:.78rem;padding:.5rem 1rem">'
                    f'Showing first 30 of {len(rows)} rows. Full data in CSV.</p>'
                    if len(rows) > 30 else "")

        thead = "".join(f"<th>{h}</th>" for h in headers)
        tbody_rows = []
        for r in display_rows:
            cells = "".join(f"<td>{r[h]}</td>" for h in headers)
            tbody_rows.append(f"<tr>{cells}</tr>")
        tbody = "\n".join(tbody_rows)

        parts.append(
            f'<div class="tbl-card">'
            f'<div class="tbl-header">'
            f'<div><h3>{title}</h3><p>{description}</p></div>'
            f'</div>'
            f'<div class="tbl-scroll">'
            f'<table><thead><tr>{thead}</tr></thead>'
            f'<tbody>{tbody}</tbody></table>'
            f'</div>{footnote}</div>'
        )
    return "\n".join(parts)


def build_nav(fig_dir: Path) -> str:
    n_figs = len(list(fig_dir.glob("*.png")))
    links = [
        ('<a href="#overview">Overview</a>'),
        ('<a href="#figures">Figures</a>'),
        ('<a href="#tables">Tables</a>'),
    ]
    nav_links = "\n".join(links)
    return (
        f'<nav>'
        f'<span>📡 Ephemeral Keys</span>'
        f'{nav_links}'
        f'<span style="margin-left:auto;font-size:.8rem;color:var(--muted)">'
        f'{n_figs} figures · 6 tables</span>'
        f'</nav>'
    )


# ── master builder ────────────────────────────────────────────────
def generate_report(figures_dir: str = "results/figures",
                    tables_dir:  str = "results/tables",
                    out_path:    str = "results/report.html") -> str:
    fig_dir = Path(figures_dir)
    tbl_dir = Path(tables_dir)
    out     = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # load eval summary for metadata
    eval_json = out.parent / "evaluation_summary.json"
    meta = {}
    if eval_json.exists():
        with open(eval_json) as fh:
            meta = json.load(fh)

    rand = meta.get("randomness", {})
    freq_p = rand.get("frequency_test", {}).get("p_value", "—")
    ent    = rand.get("entropy_per_bit", "—")
    oh     = meta.get("resource_overhead", {})
    cpu_ms = round(oh.get("avg_cpu_sec", 0) * 1000, 2) if oh else "—"

    stat_cards    = build_stat_cards(fig_dir, tbl_dir)
    figures_html  = build_figures_section(fig_dir)
    tables_html   = build_tables_section(tbl_dir)
    nav_html      = build_nav(fig_dir)

    badges = "".join(
        f'<span class="badge">{b}</span>'
        for b in ["Python 3", "Bluetooth LE", "Bloom Filter",
                  "HKDF-SHA256", "NIST SP 800-22", "Phase 1–9"]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ephemeral Keys – BLE SKG Evaluation Report</title>
<style>{STYLE}</style>
</head>
<body>

<header>
  <h1>🔑 Ephemeral Keys – BLE Secret Key Generation</h1>
  <p>Evaluation Report: Adapting the Ephemeral Secrets Protocol to
  Bluetooth LE Ad Hoc Networks using Probabilistic Data Structures</p>
  <div style="margin-top:1rem">{badges}</div>
</header>

{nav_html}

<div class="container">

  <h2 id="overview">🔎 Evaluation Overview</h2>
  <p class="section-intro">
    This report summarises Phase 8 evaluation results for the BLE-adapted
    Ephemeral Secrets secret key generation protocol. Three mobility scenarios
    (static, moderate, high) were each simulated over 50 independent sessions.
    All 18 performance figures and 6 summary tables were auto-generated from
    the simulation output.
  </p>

  {stat_cards}

  {figures_html}

  {tables_html}

</div>

<footer>
  Ephemeral Keys Project · Generated automatically by
  <code>generate_report.py</code> ·
  Entropy/bit = {ent} · Frequency test p = {freq_p} · CPU/session ≈ {cpu_ms} ms
</footer>

<script>{JS}</script>
</body>
</html>"""

    out.write_text(html, encoding="utf-8")
    size_kb = out.stat().st_size // 1024
    print(f"[report] HTML report written → {out}  ({size_kb} kB)")
    return str(out)


# ── CLI ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate self-contained HTML evaluation report")
    parser.add_argument("--figures", default="results/figures")
    parser.add_argument("--tables",  default="results/tables")
    parser.add_argument("--out",     default="results/report.html")
    args = parser.parse_args()
    generate_report(figures_dir=args.figures,
                    tables_dir=args.tables,
                    out_path=args.out)
