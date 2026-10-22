
"""Response recommendations and safe enforcement-test reporting.

This module does not modify firewall rules or network interfaces.
A reported recommendation is not proof that traffic was blocked.
"""


def recommend_response(risk: dict) -> dict:
    """Choose a response based on the existing risk assessment."""

    level = str(risk.get("risk_level", "LOW")).upper()
    score = int(risk.get("risk_score", 0))

    if level == "HIGH":
        action = "BLOCK_RECOMMENDED"
        message = "High risk: validate evidence before approved containment."
    elif level == "MEDIUM":
        action = "INVESTIGATE"
        message = "Medium risk: investigate the suspicious event."
    else:
        action = "MONITOR"
        message = "Low risk: continue monitoring."

    return {
        "risk_score": score,
        "risk_level": level,
        "action": action,
        "mode": "DRY_RUN",
        "blocked": False,
        "enforcement_status": "NOT_ATTEMPTED",
        "message": message,
    }


def report_enforcement_test(risk: dict) -> dict:
    """Report a simulated enforcement decision without changing the firewall."""

    response = recommend_response(risk)

    return {
        **response,
        "mode": "TEST_SIMULATION",
        "enforcement_status": "SIMULATED_ONLY",
        "blocked": False,
        "message": (
            "Simulation only: no firewall rule was applied and "
            "no packets were blocked."
        ),
    }


if __name__ == "__main__":
    examples = [
        {"risk_score": 0, "risk_level": "LOW"},
        {"risk_score": 45, "risk_level": "MEDIUM"},
        {"risk_score": 75, "risk_level": "HIGH"},
    ]

    for risk in examples:
        response = recommend_response(risk)
        print(
            f"[{response['risk_level']}] "
            f"Score={response['risk_score']} | "
            f"Action={response['action']} | "
            f"Mode={response['mode']} | "
            f"Blocked={response['blocked']} | "
            f"Status={response['enforcement_status']}"
        )

    print("\n--- Safe enforcement-test demonstration ---")
    result = report_enforcement_test(
        {"risk_score": 75, "risk_level": "HIGH"}
    )
    print(f"Action: {result['action']}")
    print(f"Mode: {result['mode']}")
    print(f"Status: {result['enforcement_status']}")
    print(f"Blocked: {result['blocked']}")
    print(result["message"])
