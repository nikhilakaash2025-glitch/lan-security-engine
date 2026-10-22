"""Safe enforcement adapter for the LAN security engine.

This version records enforcement decisions only.
It does not execute firewall commands or change network interfaces.
"""


def enforce_response(response: dict) -> dict:
    """Validate a response and return an explicit simulation result."""

    action = str(response.get("action", "")).upper()

    if action not in {
        "MONITOR",
        "INVESTIGATE",
        "BLOCK_RECOMMENDED",
    }:
        return {
            "success": False,
            "mode": "DRY_RUN",
            "blocked": False,
            "status": "REJECTED",
            "message": "Unknown or unsupported response action.",
        }

    return {
        "success": True,
        "mode": "DRY_RUN",
        "blocked": False,
        "status": "SIMULATED_ONLY",
        "action": action,
        "message": (
            "Decision recorded for demonstration. "
            "No firewall rules were changed and no traffic was blocked."
        ),
    }
