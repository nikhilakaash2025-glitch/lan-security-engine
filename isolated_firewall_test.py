"""Safely test packet filtering inside a temporary network namespace."""

import shutil
import subprocess


def run_isolated_test() -> dict:
    """Drop localhost ICMP echo requests only inside a temporary namespace."""
    required = ("nft", "unshare", "ip", "ping")
    tools = {name: shutil.which(name) for name in required}

    result = {
        "tools": tools,
        "namespace_test": "NOT_RUN",
        "filter_rule_counter": 0,
        "host_firewall_changed": False,
        "host_packets_blocked": False,
    }

    if not all(tools.values()):
        result["namespace_test"] = "MISSING_TOOLS"
        return result

    script = r"""
set -eu
ip link set lo up

nft add table inet isolated_test
nft 'add chain inet isolated_test input { type filter hook input priority 0; policy accept; }'
nft add rule inet isolated_test input iifname lo ip protocol icmp icmp type echo-request counter drop

ping -c 2 -W 1 127.0.0.1 >/dev/null 2>&1 || true

nft list chain inet isolated_test input
"""

    try:
        completed = subprocess.run(
            ["sudo", "unshare", "--net", "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        output = completed.stdout + completed.stderr
        result["output"] = output

        if completed.returncode == 0 and "packets 2" in output:
            result["namespace_test"] = "PASS"
            result["filter_rule_counter"] = 2
        else:
            result["namespace_test"] = "FAIL"

    except (OSError, subprocess.TimeoutExpired) as error:
        result["namespace_test"] = "ERROR"
        result["output"] = str(error)

    return result


if __name__ == "__main__":
    report = run_isolated_test()

    print("Isolated firewall test")
    for name, value in report.items():
        if name != "tools":
            print(f"{name}: {value}")

    for name, path in report["tools"].items():
        print(f"{name}: {path or 'NOT FOUND'}")
