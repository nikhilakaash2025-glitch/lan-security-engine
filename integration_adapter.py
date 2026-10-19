"""Adapter connecting detector results to risk scoring and CSV logging.

This module only records results and produces dry-run recommendations.
It never modifies network interfaces or firewall rules.
"""

from pathlib import Path
from typing import Any

from logger import log_result
from risk_engine import score_event


def process_result(
    event_type: str,
    result: dict[str, Any],
    log_path: str | Path = "logs/detection_results.csv",
) -> list[dict[str, Any]]:
    """Score and log one ARP result or all alerts in a DNS result."""
    normalized_type = event_type.upper()

    if normalized_type not in {"ARP", "DNS"}:
        raise ValueError("event_type must be ARP or DNS")

    status = str(result.get("status", "unknown")).lower()
    if normalized_type == "DNS" and result.get("alerts"):
        details = result["alerts"]
    else:
        details = [result]

    processed = []

    for detail in details:
        event = {
            "event_type": normalized_type,
            "status": status,
            "reason": detail.get("reason", result.get("reason", "")),
        }

        if normalized_type == "ARP":
            event.update({
                "ip": result.get("ip", ""),
                "source_ip": result.get("ip", ""),
                "old_mac": result.get("old_mac", ""),
                "new_mac": result.get("new_mac", ""),
            })
        else:
            event.update({
                "domain": result.get("domain", ""),
                "answer_ip": detail.get("answer_ip", ""),
            })

        risk = score_event(event)
        log_result(event, risk, log_path)
        processed.append({"event": event, "risk": risk})

    return processed
