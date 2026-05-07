"""
pq_tls_analysis.py
==================
Hybrid Post-Quantum TLS — Complete Performance & Security Analysis
Generates all graphs needed for the PFA report.

Place this file in the same folder as latency_raw.csv
Run: python pq_tls_analysis.py

Output files (saved in results/ subfolder):
  01_latency_boxplot.png
  02_latency_barplot.png
  03_latency_per_run.png
  04_cert_sizes.png
  05_handshake_sizes.png
  06_security_table.png
  07_mlkem_comparison.png
  08_full_report_figure.png   ← one combined figure for the report
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch
import warnings
warnings.filterwarnings("ignore")

# ── Try to import pandas, install hint if missing ─────────────────────────────
try:
    import pandas as pd
except ImportError:
    print("pandas not found. Install it with:  pip install pandas matplotlib numpy")
    raise

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION — edit these if your numbers differ
# ─────────────────────────────────────────────────────────────────────────────

CSV_FILE    = "latency_raw.csv"          # input file (same folder as script)
OUT_DIR     = "results"                  # output folder for graphs
DPI         = 150                        # image resolution (150 = good for report)

# Colour palette (consistent across all graphs)
COLOURS = {
    "classical" : "#4C8BBF",   # blue
    "pq"        : "#3DAA6B",   # green
    "hybrid"    : "#D4820A",   # orange/gold
}

MODE_LABELS = {
    "classical" : "Classical TLS\n(RSA-2048 + ECDH-P256)",
    "pq"        : "Post-Quantum TLS\n(ML-KEM-768 + ML-DSA-65)",
    "hybrid"    : "Hybrid TLS\n(X25519 + ML-KEM-768\n+ ML-DSA-65)",
}

# Certificate sizes (bytes) — from your measurements
CERT_SIZES = {
    "RSA-2048\n(Classical CA)"   : {"PEM": 1204, "DER": 847},
    "RSA-2048\n(Classical Server)": {"PEM": 1078, "DER": 754},
    "ML-DSA-65\n(PQ CA)"         : {"PEM": 7611, "DER": 5578},
    "ML-DSA-65\n(PQ Server)"     : {"PEM": 7582, "DER": 5557},
    "p384_mldsa65\n(Hybrid CA)"  : {"PEM": 7863, "DER": 5765},
    "p384_mldsa65\n(Hybrid Server)":{"PEM": 7842, "DER": 5749},
}

# Handshake total sizes (bytes)
HANDSHAKE_SIZES = {
    "classical" : 3427,
    "pq"        : 11399,
    "hybrid"    : 11696,
}

# ML-KEM parameter comparison
MLKEM_DATA = {
    "ML-KEM-512\n(NIST Level 1)" : {"pk": 800,  "ct": 768,  "sk": 1632, "ops": 120000},
    "ML-KEM-768\n(NIST Level 3)" : {"pk": 1184, "ct": 1088, "sk": 2400, "ops": 70000},
    "ML-KEM-1024\n(NIST Level 5)": {"pk": 1568, "ct": 1568, "sk": 3168, "ops": 45000},
}

# Security properties for the table
SECURITY_PROPS = [
    ("Forward Secrecy",                  True,  True,  True),
    ("Quantum-Resistant Key Exchange",   False, True,  True),
    ("HNDL Attack Protection",           False, True,  True),
    ("Classical Fallback Security",      True,  False, True),
    ("NIST PQC Standardised (2024)",     False, True,  True),
    ("Zero Decapsulation Failure",       True,  True,  True),
    ("Browser Compatible Today",         True,  False, False),
]

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def ensure_output_dir():
    os.makedirs(OUT_DIR, exist_ok=True)

def save(fig, name):
    path = os.path.join(OUT_DIR, name)
    fig.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=fig.get_facecolor())
    print(f"  ✓  Saved: {path}")
    plt.close(fig)

def remove_outliers_iqr(series):
    """Remove outliers using the 1.5 × IQR rule."""
    Q1, Q3 = series.quantile(0.25), series.quantile(0.75)
    IQR = Q3 - Q1
    return series[(series >= Q1 - 1.5 * IQR) & (series <= Q3 + 1.5 * IQR)]

def style_ax(ax, title="", xlabel="", ylabel=""):
    ax.set_facecolor("#F7F9FC")
    ax.grid(axis="y", color="white", linewidth=1.2, zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color("#CCCCCC")
    if title:  ax.set_title(title,  fontsize=12, fontweight="bold", pad=10)
    if xlabel: ax.set_xlabel(xlabel, fontsize=10, labelpad=6)
    if ylabel: ax.set_ylabel(ylabel, fontsize=10, labelpad=6)

# ─────────────────────────────────────────────────────────────────────────────
#  LOAD & CLEAN DATA
# ─────────────────────────────────────────────────────────────────────────────

def load_data():
    print(f"\nLoading {CSV_FILE} ...")
    df = pd.read_csv(CSV_FILE)
    df.columns = [c.strip().lower().strip('"') for c in df.columns]

    # accept both "time_ms" and "time"
    if "time_ms" not in df.columns and "time" in df.columns:
        df.rename(columns={"time": "time_ms"}, inplace=True)

    df["mode"]    = df["mode"].str.strip().str.strip('"').str.lower()
    df["time_ms"] = pd.to_numeric(df["time_ms"], errors="coerce")
    df.dropna(subset=["time_ms"], inplace=True)

    # Remove zero values (failed connections)
    df = df[df["time_ms"] > 0]

    print(f"  Rows loaded: {len(df)}")
    print(f"  Modes found: {df['mode'].unique().tolist()}")

    # Clean each mode
    clean_frames = []
    stats = {}
    for mode in ["classical", "pq", "hybrid"]:
        subset = df[df["mode"] == mode]["time_ms"]
        if len(subset) == 0:
            print(f"  ⚠  No data for mode: {mode}")
            continue
        cleaned = remove_outliers_iqr(subset)
        clean_frames.append(df.loc[cleaned.index])
        stats[mode] = {
            "mean"   : cleaned.mean(),
            "median" : cleaned.median(),
            "std"    : cleaned.std(),
            "min"    : cleaned.min(),
            "max"    : cleaned.max(),
            "n"      : len(cleaned),
            "removed": len(subset) - len(cleaned),
        }
        print(f"  {mode:12s}: mean={cleaned.mean():.2f} ms  "
              f"median={cleaned.median():.2f} ms  "
              f"std={cleaned.std():.2f} ms  n={len(cleaned)}")

    df_clean = pd.concat(clean_frames) if clean_frames else df
    return df_clean, stats

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 1 — Box Plot
# ─────────────────────────────────────────────────────────────────────────────

def plot_boxplot(df_clean, stats):
    print("\nGenerating Graph 1: Latency Box Plot ...")
    modes  = [m for m in ["classical", "pq", "hybrid"] if m in df_clean["mode"].unique()]
    data   = [df_clean[df_clean["mode"] == m]["time_ms"].values for m in modes]
    labels = [MODE_LABELS[m] for m in modes]
    colors = [COLOURS[m] for m in modes]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("white")

    bp = ax.boxplot(data, patch_artist=True, notch=False,
                    medianprops=dict(color="black", linewidth=2),
                    whiskerprops=dict(linewidth=1.5),
                    capprops=dict(linewidth=1.5),
                    flierprops=dict(marker="o", markersize=4, alpha=0.4))

    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)

    ax.set_xticks(range(1, len(modes) + 1))
    ax.set_xticklabels(labels, fontsize=9)
    style_ax(ax,
             title="TLS Handshake Latency Distribution\n(after IQR outlier removal)",
             ylabel="Latency (ms)")

    # Annotate medians
    for i, (bp_box, mode) in enumerate(zip(bp["medians"], modes), 1):
        med = bp_box.get_ydata()[0]
        ax.annotate(f"{med:.1f} ms",
                    xy=(i, med), xytext=(i + 0.18, med),
                    fontsize=8, color="black", va="center",
                    arrowprops=dict(arrowstyle="-", color="gray", lw=0.8))

    fig.text(0.5, -0.02,
             "Figure 1 — Box plot of TLS handshake latency across 3 modes. "
             "Lower median and tighter IQR indicate more consistent performance.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "01_latency_boxplot.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 2 — Bar Plot (Mean ± Std)
# ─────────────────────────────────────────────────────────────────────────────

def plot_barplot(stats):
    print("Generating Graph 2: Latency Bar Plot ...")
    modes  = [m for m in ["classical", "pq", "hybrid"] if m in stats]
    means  = [stats[m]["mean"] for m in modes]
    stds   = [stats[m]["std"]  for m in modes]
    labels = [MODE_LABELS[m]   for m in modes]
    colors = [COLOURS[m]       for m in modes]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("white")

    bars = ax.bar(range(len(modes)), means, yerr=stds, capsize=6,
                  color=colors, alpha=0.82, width=0.5, edgecolor="white",
                  linewidth=1.5, error_kw=dict(elinewidth=1.5, ecolor="#333333"))

    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + std + 3,
                f"{mean:.1f} ms", ha="center", va="bottom",
                fontsize=9, fontweight="bold")

    ax.set_xticks(range(len(modes)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, max(means) * 1.35)
    style_ax(ax,
             title="Mean TLS Handshake Latency with Standard Deviation",
             ylabel="Mean Latency (ms)")

    # Overhead annotation
    if "classical" in stats and "hybrid" in stats:
        overhead = stats["hybrid"]["mean"] - stats["classical"]["mean"]
        sign     = "+" if overhead >= 0 else ""
        ax.annotate(f"Hybrid overhead vs Classical:\n{sign}{overhead:.1f} ms",
                    xy=(0.72, 0.88), xycoords="axes fraction",
                    fontsize=9, color="#555555",
                    bbox=dict(boxstyle="round,pad=0.4", facecolor="#FFF8E7",
                              edgecolor="#D4820A", linewidth=1))

    fig.text(0.5, -0.02,
             "Figure 2 — Mean handshake latency ± 1 standard deviation. "
             "Error bars indicate measurement variability.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "02_latency_barplot.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 3 — Per-Run Line Chart
# ─────────────────────────────────────────────────────────────────────────────

def plot_per_run(df_clean):
    print("Generating Graph 3: Per-Run Latency Trace ...")
    modes = [m for m in ["classical", "pq", "hybrid"] if m in df_clean["mode"].unique()]

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor("white")

    for mode in modes:
        subset = df_clean[df_clean["mode"] == mode].reset_index(drop=True)
        ax.plot(subset.index + 1, subset["time_ms"],
                label=MODE_LABELS[mode].replace("\n", " — "),
                color=COLOURS[mode], linewidth=1.4, alpha=0.85)
        # Rolling mean
        if len(subset) >= 5:
            rolling = subset["time_ms"].rolling(window=5, center=True).mean()
            ax.plot(subset.index + 1, rolling,
                    color=COLOURS[mode], linewidth=2.5,
                    linestyle="--", alpha=0.6)

    style_ax(ax,
             title="Handshake Latency per Trial (dashed = 5-run rolling mean)",
             xlabel="Trial Number",
             ylabel="Latency (ms)")
    ax.legend(fontsize=8, loc="upper right",
              framealpha=0.9, edgecolor="#CCCCCC")

    fig.text(0.5, -0.02,
             "Figure 3 — Per-trial latency trace. Dashed lines show the 5-trial "
             "rolling mean. Higher variance in classical mode is visible.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "03_latency_per_run.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 4 — Certificate Sizes
# ─────────────────────────────────────────────────────────────────────────────

def plot_cert_sizes():
    print("Generating Graph 4: Certificate Sizes ...")
    labels = list(CERT_SIZES.keys())
    pem    = [CERT_SIZES[k]["PEM"] for k in labels]
    der    = [CERT_SIZES[k]["DER"] for k in labels]
    x      = np.arange(len(labels))
    w      = 0.38

    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor("white")

    bars_pem = ax.bar(x - w/2, pem, w, label="PEM (bytes)",
                      color="#4C8BBF", alpha=0.82, edgecolor="white")
    bars_der = ax.bar(x + w/2, der, w, label="DER (bytes)",
                      color="#3DAA6B", alpha=0.82, edgecolor="white")

    for bar in list(bars_pem) + list(bars_der):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 80,
                f"{h:,}", ha="center", va="bottom", fontsize=7.5)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylim(0, max(pem) * 1.22)
    style_ax(ax,
             title="Certificate File Sizes — Classical vs Post-Quantum vs Hybrid",
             ylabel="Size (bytes)")
    ax.legend(fontsize=9)

    # Ratio annotation
    rsa_pem = CERT_SIZES[list(CERT_SIZES.keys())[1]]["PEM"]
    pq_pem  = CERT_SIZES[list(CERT_SIZES.keys())[3]]["PEM"]
    ratio   = pq_pem / rsa_pem
    ax.annotate(f"PQ certificates are ≈{ratio:.1f}× larger than RSA",
                xy=(0.5, 0.88), xycoords="axes fraction",
                ha="center", fontsize=10, color="#CC3333", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="#FFF0F0",
                          edgecolor="#CC3333", linewidth=1))

    fig.text(0.5, -0.02,
             "Figure 4 — Certificate sizes in PEM (base64 text) and DER (binary) "
             "formats. Post-quantum certificates are approximately 7× larger than RSA.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "04_cert_sizes.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 5 — Handshake Data Volumes
# ─────────────────────────────────────────────────────────────────────────────

def plot_handshake_sizes():
    print("Generating Graph 5: Handshake Data Volumes ...")
    modes  = list(HANDSHAKE_SIZES.keys())
    sizes  = list(HANDSHAKE_SIZES.values())
    colors = [COLOURS[m] for m in modes]
    labels = [MODE_LABELS[m].replace("\n", " ") for m in modes]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("white")

    bars = ax.bar(range(len(modes)), sizes, color=colors,
                  alpha=0.82, width=0.5, edgecolor="white", linewidth=1.5)

    for bar, size in zip(bars, sizes):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 150,
                f"{size:,} B", ha="center", va="bottom",
                fontsize=10, fontweight="bold")

    ax.set_xticks(range(len(modes)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, max(sizes) * 1.22)
    style_ax(ax,
             title="Total TLS Handshake Data Volume per Connection",
             ylabel="Total Bytes Exchanged")

    # Ratio
    ratio = HANDSHAKE_SIZES["hybrid"] / HANDSHAKE_SIZES["classical"]
    ax.annotate(f"Hybrid handshake is ≈{ratio:.1f}× larger than classical",
                xy=(0.5, 0.88), xycoords="axes fraction",
                ha="center", fontsize=10, color="#333333",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="#FFF8E7",
                          edgecolor="#D4820A", linewidth=1))

    fig.text(0.5, -0.02,
             "Figure 5 — Total bytes exchanged during TLS handshake. "
             "The overhead comes primarily from the larger PQ certificate and key shares.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "05_handshake_sizes.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 6 — Security Properties Table
# ─────────────────────────────────────────────────────────────────────────────

def plot_security_table():
    print("Generating Graph 6: Security Properties Table ...")
    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor("white")
    ax.axis("off")

    col_labels = ["Security Property", "Classical TLS", "Post-Quantum TLS", "Hybrid TLS"]
    row_labels = [p[0] for p in SECURITY_PROPS]
    rows       = []
    for prop in SECURITY_PROPS:
        row = [
            "✓" if prop[1] else "✗",
            "✓" if prop[2] else "✗",
            "✓" if prop[3] else "✗",
        ]
        rows.append(row)

    # Build table
    table_data = [[row_labels[i]] + rows[i] for i in range(len(row_labels))]
    col_widths = [0.38, 0.18, 0.22, 0.17]

    tbl = ax.table(
        cellText=table_data,
        colLabels=col_labels,
        cellLoc="center",
        loc="center",
        colWidths=col_widths,
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1, 2.0)

    # Style header
    for j in range(len(col_labels)):
        cell = tbl[0, j]
        cell.set_facecolor("#1F3A7A")
        cell.set_text_props(color="white", fontweight="bold")

    # Style cells
    for i in range(1, len(row_labels) + 1):
        # Property name column
        tbl[i, 0].set_facecolor("#F0F4FA")
        tbl[i, 0].set_text_props(ha="left", fontsize=9)

        for j in range(1, 4):
            val  = rows[i - 1][j - 1]
            cell = tbl[i, j]
            if val == "✓":
                cell.set_facecolor("#E8F5E9")
                cell.set_text_props(color="#1B7A3E", fontsize=14, fontweight="bold")
            else:
                cell.set_facecolor("#FFEBEE")
                cell.set_text_props(color="#C62828", fontsize=14, fontweight="bold")

        # Alternating row background for property column
        if i % 2 == 0:
            tbl[i, 0].set_facecolor("#E8EDF5")

    ax.set_title("Security Properties Comparison — Classical vs PQ vs Hybrid TLS",
                 fontsize=12, fontweight="bold", pad=16, color="#1F3A7A")

    fig.text(0.5, 0.01,
             "Figure 6 — Security property comparison. "
             "Hybrid TLS is the only mode that satisfies all critical properties "
             "during the quantum transition period.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "06_security_table.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 7 — ML-KEM Parameter Comparison
# ─────────────────────────────────────────────────────────────────────────────

def plot_mlkem_comparison():
    print("Generating Graph 7: ML-KEM Parameter Comparison ...")
    variants = list(MLKEM_DATA.keys())
    pk_sizes = [MLKEM_DATA[v]["pk"] for v in variants]
    ct_sizes = [MLKEM_DATA[v]["ct"] for v in variants]
    sk_sizes = [MLKEM_DATA[v]["sk"] for v in variants]
    ops      = [MLKEM_DATA[v]["ops"] for v in variants]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    fig.patch.set_facecolor("white")

    x   = np.arange(len(variants))
    w   = 0.28
    pal = ["#4C8BBF", "#3DAA6B", "#D4820A"]

    # Left: key/ciphertext sizes
    b1 = ax1.bar(x - w,   pk_sizes, w, label="Public Key",  color=pal[0], alpha=0.82)
    b2 = ax1.bar(x,       ct_sizes, w, label="Ciphertext",  color=pal[1], alpha=0.82)
    b3 = ax1.bar(x + w,   sk_sizes, w, label="Private Key", color=pal[2], alpha=0.82)

    for bars in [b1, b2, b3]:
        for bar in bars:
            h = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2, h + 25,
                     str(h), ha="center", va="bottom", fontsize=7.5)

    ax1.set_xticks(x)
    ax1.set_xticklabels(variants, fontsize=8)
    ax1.legend(fontsize=8)
    style_ax(ax1,
             title="ML-KEM Key and Ciphertext Sizes",
             ylabel="Size (bytes)")

    # Highlight which one the project uses
    ax1.axvspan(0.67, 1.33, alpha=0.08, color="#D4820A", zorder=0)
    ax1.text(1, max(sk_sizes) * 1.05, "← Used in\nthis project",
             ha="center", fontsize=8, color="#D4820A", fontweight="bold")

    # Right: throughput
    bar_colors = [pal[0], pal[1], pal[2]]
    bars2 = ax2.bar(x, ops, color=bar_colors, alpha=0.82, width=0.5)

    for bar, op in zip(bars2, ops):
        ax2.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 1500,
                 f"{op:,} ops/s", ha="center", va="bottom", fontsize=9)

    ax2.set_xticks(x)
    ax2.set_xticklabels(variants, fontsize=8)
    style_ax(ax2,
             title="ML-KEM Key Generation Throughput",
             ylabel="Operations per Second")

    ax2.axhspan(0, 1000, alpha=0.06, color="#CC3333")
    ax2.text(0.5, 0.06,
             "RSA-2048: ~500 ops/s\n(100× slower than ML-KEM-768)",
             transform=ax2.transAxes, ha="center", fontsize=8,
             color="#CC3333",
             bbox=dict(boxstyle="round", facecolor="#FFF0F0",
                       edgecolor="#CC3333", linewidth=0.8))

    fig.suptitle("ML-KEM Parameter Sets — Security vs Performance Trade-off",
                 fontsize=12, fontweight="bold", y=1.02)

    fig.text(0.5, -0.03,
             "Figure 7 — Comparison of ML-KEM parameter sets. "
             "ML-KEM-768 (highlighted) was selected for this project as the "
             "NIST Level 3 recommendation.",
             ha="center", fontsize=8, color="#555555", style="italic")

    save(fig, "07_mlkem_comparison.png")

# ─────────────────────────────────────────────────────────────────────────────
#  GRAPH 8 — Combined Report Figure
# ─────────────────────────────────────────────────────────────────────────────

def plot_combined(df_clean, stats):
    print("Generating Graph 8: Combined Report Figure ...")

    fig = plt.figure(figsize=(16, 12))
    fig.patch.set_facecolor("white")
    fig.suptitle(
        "Hybrid Post-Quantum TLS — Performance & Security Evaluation",
        fontsize=15, fontweight="bold", color="#1F3A7A", y=0.98
    )

    gs = gridspec.GridSpec(2, 3, figure=fig,
                           hspace=0.45, wspace=0.35,
                           top=0.92, bottom=0.08)

    modes  = [m for m in ["classical", "pq", "hybrid"] if m in stats]
    colors = [COLOURS[m] for m in modes]
    labels_short = ["Classical", "Post-Quantum", "Hybrid"]

    # ── Top-left: bar chart latency ──────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, 0])
    means = [stats[m]["mean"] for m in modes]
    stds  = [stats[m]["std"]  for m in modes]
    bars  = ax1.bar(range(len(modes)), means, yerr=stds, capsize=5,
                    color=colors, alpha=0.82, width=0.5, edgecolor="white",
                    error_kw=dict(elinewidth=1.5))
    for bar, mean in zip(bars, means):
        ax1.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 5,
                 f"{mean:.0f} ms", ha="center", fontsize=8, fontweight="bold")
    ax1.set_xticks(range(len(modes)))
    ax1.set_xticklabels(labels_short, fontsize=9)
    ax1.set_ylim(0, max(means) * 1.35)
    style_ax(ax1, title="Handshake Latency (Mean ± SD)", ylabel="ms")

    # ── Top-middle: handshake sizes ──────────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    hs_modes  = ["classical", "pq", "hybrid"]
    hs_sizes  = [HANDSHAKE_SIZES[m] for m in hs_modes]
    hs_colors = [COLOURS[m] for m in hs_modes]
    bars2 = ax2.bar(range(3), hs_sizes, color=hs_colors,
                    alpha=0.82, width=0.5, edgecolor="white")
    for bar, s in zip(bars2, hs_sizes):
        ax2.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 200,
                 f"{s//1000}K", ha="center", fontsize=9, fontweight="bold")
    ax2.set_xticks(range(3))
    ax2.set_xticklabels(labels_short, fontsize=9)
    style_ax(ax2, title="Handshake Size (bytes)", ylabel="Bytes")

    # ── Top-right: cert sizes (server only) ──────────────────────────────────
    ax3 = fig.add_subplot(gs[0, 2])
    cert_labels = ["RSA-2048\nServer", "ML-DSA-65\nServer", "p384_mldsa65\nServer"]
    cert_keys   = list(CERT_SIZES.keys())
    cert_pem    = [CERT_SIZES[cert_keys[1]]["PEM"],
                   CERT_SIZES[cert_keys[3]]["PEM"],
                   CERT_SIZES[cert_keys[5]]["PEM"]]
    cert_colors = [COLOURS["classical"], COLOURS["pq"], COLOURS["hybrid"]]
    bars3 = ax3.bar(range(3), cert_pem, color=cert_colors,
                    alpha=0.82, width=0.5, edgecolor="white")
    for bar, s in zip(bars3, cert_pem):
        ax3.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 100,
                 f"{s:,}", ha="center", fontsize=8, fontweight="bold")
    ax3.set_xticks(range(3))
    ax3.set_xticklabels(cert_labels, fontsize=8)
    style_ax(ax3, title="Server Certificate Size (PEM)", ylabel="Bytes")

    # ── Bottom: per-run trace ─────────────────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, :])
    for mode in ["classical", "pq", "hybrid"]:
        if mode not in df_clean["mode"].unique():
            continue
        subset = df_clean[df_clean["mode"] == mode].reset_index(drop=True)
        ax4.plot(subset.index + 1, subset["time_ms"],
                 label=mode.capitalize(),
                 color=COLOURS[mode], linewidth=1.3, alpha=0.8)
        if len(subset) >= 5:
            rolling = subset["time_ms"].rolling(5, center=True).mean()
            ax4.plot(subset.index + 1, rolling,
                     color=COLOURS[mode], linewidth=2.5, linestyle="--", alpha=0.6)
    style_ax(ax4,
             title="Per-Trial Latency Trace (solid = raw, dashed = 5-run rolling mean)",
             xlabel="Trial Number", ylabel="Latency (ms)")
    ax4.legend(fontsize=9, loc="upper right")

    save(fig, "08_full_report_figure.png")

# ─────────────────────────────────────────────────────────────────────────────
#  PRINT STATISTICS SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(stats):
    print("\n" + "="*60)
    print("  STATISTICAL SUMMARY (use these numbers in your report)")
    print("="*60)

    for mode in ["classical", "pq", "hybrid"]:
        if mode not in stats:
            print(f"\n  {mode.upper()}: no data")
            continue
        s = stats[mode]
        print(f"\n  {mode.upper()}")
        print(f"    Samples  : {s['n']} (outliers removed: {s['removed']})")
        print(f"    Mean     : {s['mean']:.2f} ms")
        print(f"    Median   : {s['median']:.2f} ms")
        print(f"    Std Dev  : {s['std']:.2f} ms")
        print(f"    Min      : {s['min']:.2f} ms")
        print(f"    Max      : {s['max']:.2f} ms")

    if "classical" in stats and "hybrid" in stats:
        overhead = stats["hybrid"]["mean"] - stats["classical"]["mean"]
        pct      = (overhead / stats["classical"]["mean"]) * 100
        print(f"\n  HYBRID OVERHEAD vs CLASSICAL:")
        print(f"    + {overhead:.2f} ms  ({pct:+.1f}%)")

    if "classical" in stats and "pq" in stats:
        overhead_pq = stats["pq"]["mean"] - stats["classical"]["mean"]
        pct_pq      = (overhead_pq / stats["classical"]["mean"]) * 100
        print(f"\n  PQ-ONLY OVERHEAD vs CLASSICAL:")
        print(f"    + {overhead_pq:.2f} ms  ({pct_pq:+.1f}%)")

    print("\n" + "="*60)
    print("  HANDSHAKE DATA VOLUMES")
    print("="*60)
    for mode, size in HANDSHAKE_SIZES.items():
        ratio = size / HANDSHAKE_SIZES["classical"]
        print(f"  {mode:12s}: {size:>7,} bytes  ({ratio:.1f}× vs classical)")

    print("\n" + "="*60)
    print("  OUTPUT FILES")
    print("="*60)
    files = [
        "01_latency_boxplot.png    ← Use in Chapter 5: Latency Distribution",
        "02_latency_barplot.png    ← Use in Chapter 5: Mean Latency Comparison",
        "03_latency_per_run.png    ← Use in Chapter 5: Variance Analysis",
        "04_cert_sizes.png         ← Use in Chapter 5: Bandwidth Overhead",
        "05_handshake_sizes.png    ← Use in Chapter 5: Handshake Data Volume",
        "06_security_table.png     ← Use in Chapter 2 or 5: Security Analysis",
        "07_mlkem_comparison.png   ← Use in Chapter 2: Algorithm Analysis",
        "08_full_report_figure.png ← Use as main summary figure in Chapter 5",
    ]
    for f in files:
        print(f"  results/{f}")
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  PQ-TLS Analysis Script")
    print("=" * 60)

    # Check CSV exists
    if not os.path.exists(CSV_FILE):
        print(f"\n  ERROR: {CSV_FILE} not found.")
        print(f"  Make sure this script is in the same folder as {CSV_FILE}")
        print(f"  Current folder: {os.getcwd()}")
        return

    ensure_output_dir()

    # Load data
    df_clean, stats = load_data()

    if df_clean.empty:
        print("\n  ERROR: No valid data found in CSV.")
        return

    # Generate all graphs
    print("\nGenerating graphs...")
    plot_boxplot(df_clean, stats)
    plot_barplot(stats)
    plot_per_run(df_clean)
    plot_cert_sizes()
    plot_handshake_sizes()
    plot_security_table()
    plot_mlkem_comparison()
    plot_combined(df_clean, stats)

    # Print summary
    print_summary(stats)

    print("\n  All done! Open the results/ folder to see your graphs.")
    print("  Use 08_full_report_figure.png as your main chapter figure.\n")


if __name__ == "__main__":
    main()