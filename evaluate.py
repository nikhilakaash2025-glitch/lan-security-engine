"""Generate plots from detection_results.csv."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd

CSV_PATH = Path("logs/detection_results.csv")
PLOT_DIR = Path("plots")


def main():
    if not CSV_PATH.exists():
        raise SystemExit(f"CSV file not found: {CSV_PATH}")

    df = pd.read_csv(CSV_PATH)

    if df.empty:
        raise SystemExit("CSV contains no results to evaluate.")

    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["risk_score"])

    if df.empty:
        raise SystemExit("No valid risk scores found.")

    PLOT_DIR.mkdir(parents=True, exist_ok=True)

    # Plot 1: Number of events at each risk level.
    level_order = ["LOW", "MEDIUM", "HIGH"]
    counts = (
        df["risk_level"]
        .value_counts()
        .reindex(level_order, fill_value=0)
    )

    ax = counts.plot(kind="bar", title="Detection Events by Risk Level")
    ax.set_xlabel("Risk Level")
    ax.set_ylabel("Number of Events")
    plt.tight_layout()
    plt.savefig(PLOT_DIR / "risk_distribution.png", dpi=150)
    plt.close()

    # Plot 2: Risk score over time.
    timed = df.dropna(subset=["timestamp"]).sort_values("timestamp")

    if not timed.empty:
        plt.figure()
        plt.plot(timed["timestamp"], timed["risk_score"], marker="o")
        plt.title("Detection Risk Score Over Time")
        plt.xlabel("Timestamp (UTC)")
        plt.ylabel("Risk Score")
        plt.ylim(0, 100)
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        plt.savefig(PLOT_DIR / "detection_timeline.png", dpi=150)
        plt.close()

    print(f"Analyzed {len(df)} event(s).")
    print("\nRisk-level counts:")
    print(counts.to_string())
    print(f"\nPlots saved in: {PLOT_DIR}/")


if __name__ == "__main__":
    main()
