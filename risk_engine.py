"""Explainable risk scoring for ARP/DNS detector results.

Isolation decisions are recommendations only. No network changes occur.
"""

from typing import Any

DEFAULT_CONFIDENCE = 0.75


def classify_risk(score: int) -> str:
    """Map a score from 0 to 100 to a severity level."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def score_event(event: dict[str, Any]) -> dict[str, Any]:
    """Score one ARP or DNS detector result."""
    event_type = str(event.get("event_type", "")).upper()
    status = str(event.get("status", "")).lower()

    if event_type not in {"ARP", "DNS", "ARP_SPOOF", "DNS_SPOOF"}:
        if "old_mac" in event or "new_mac" in event:
            event_type = "ARP"
        elif "domain" in event or "alerts" in event:
            event_type = "DNS"
        else:
            event_type = "UNKNOWN"

    if status != "alert":
        return {
            "event_type": event_type,
            "risk_score": 0,
            "risk_level": "LOW",
            "dry_run_isolation": False,
            "reason": "Detector did not report an alert",
        }

    base_score = (
        60 if event_type in {"ARP", "ARP_SPOOF"}
        else 70 if event_type in {"DNS", "DNS_SPOOF"}
        else 40
    )
    confidence = float(event.get("confidence", DEFAULT_CONFIDENCE))
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")

    score = round(base_score * confidence)
    level = classify_risk(score)

    return {
        "event_type": event_type,
        "risk_score": score,
        "risk_level": level,
        "dry_run_isolation": level == "HIGH",
        "reason": str(
            event.get("reason")
            or f"Detector reported a suspicious {event_type} result"
        ),
    }
