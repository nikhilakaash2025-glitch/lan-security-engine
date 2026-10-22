
"""Adapter connecting detector results to risk scoring,
CSV logging, and dry-run response recommendations.

This module does not modify firewall rules or network interfaces.
"""

from pathlib import Path
from typing import Any

from logger import log_result
from risk_engine import score_event
from response_controller import recommend_response


def process_result(
    event_type: str,
    result: dict[str, Any],
    log_path: str | Path = "logs/detection_results.csv",
) -> list[dict[str, Any]]:
    """Score, log, and recommend a response for ARP/DNS results."""

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

        # 1. Calculate the risk assessment.
        risk = score_event(event)

        # 2. Record the event and risk assessment in the CSV.
        log_result(event, risk, log_path)

        # 3. Recommend a response based on the risk level.
        response = recommend_response(risk)

        # 4. Return all results to the caller.
        processed.append({
            "event": event,
            "risk": risk,
            "response": response,
        })

    return processed
