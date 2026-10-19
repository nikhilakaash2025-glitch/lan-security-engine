"""CSV logging for simulated ARP/DNS detection and risk results."""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = Path("logs/detection_results.csv")

CSV_FIELDS = [
    "timestamp",
    "event_type",
    "status",
    "risk_score",
    "risk_level",
    "source_ip",
    "domain",
    "reason",
    "dry_run_isolation",
]


def log_result(
    event: dict[str, Any],
    risk: dict[str, Any],
    log_path: str | Path = DEFAULT_LOG_PATH,
) -> None:
    """Append one event and its risk assessment to a CSV file."""
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0

    row = {
        "timestamp": event.get("timestamp")
        or datetime.now(timezone.utc).isoformat(),
        "event_type": risk.get("event_type", event.get("event_type", "UNKNOWN")),
        "status": event.get("status", ""),
        "risk_score": risk.get("risk_score", 0),
        "risk_level": risk.get("risk_level", "LOW"),
        "source_ip": event.get("source_ip", event.get("ip", "")),
        "domain": event.get("domain", ""),
        "reason": risk.get("reason", event.get("reason", "")),
        "dry_run_isolation": risk.get("dry_run_isolation", False),
    }

    with path.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        if needs_header:
            writer.writeheader()
        writer.writerow(row)
