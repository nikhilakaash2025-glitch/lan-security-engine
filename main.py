
"""Analyze a saved capture for suspicious ARP/DNS activity.

Alerts are scored, logged, and given dry-run response recommendations.
No packets are blocked and no network settings are changed.
"""

from scapy.all import ARP, DNS

from arp_detector import ArpDetector
from dns_detector import DNSDetector
from packet_capture import read_pcap
from integration_adapter import process_result


def report_result(event_type, result):
    """Score, log, and display response recommendations once per alert."""
    processed = process_result(event_type, result)

    if not processed:
        return

    # Display one summary for the alert, not once per answer IP.
    item = processed[0]
    risk = item["risk"]
    response = item["response"]

    print(f"  Risk score:       {risk['risk_score']}/100")
    print(f"  Threat level:     {risk['risk_level']}")
    print(f"  Recommended action: {response['action']}")
    print(f"  Response mode:    {response['mode']}")
    print(f"  Packets blocked:  {response['blocked']}")


def process_capture(pcap_file):
    """Process a saved capture using ARP and DNS detectors."""
    arp_detector = ArpDetector()
    dns_detector = DNSDetector()

    packet_count = 0
    alert_count = 0

    print("=" * 60)
    print("       NETWORK SECURITY DETECTION ENGINE")
    print("=" * 60)
    print(f"Capture file: {pcap_file}")
    print("-" * 60)

    try:
        for packet in read_pcap(pcap_file):
            packet_count += 1

            # Inspect ARP packets with sender IP and MAC information.
            if packet.haslayer(ARP):
                arp = packet[ARP]

                if arp.op in (1, 2) and arp.psrc != "0.0.0.0":
                    try:
                        result = arp_detector.process_mapping(
                            arp.psrc, arp.hwsrc
                        )

                        if result["status"] == "alert":
                            alert_count += 1
                            print("\n[ARP ALERT]")
                            print(f"  IP address: {result['ip']}")
                            print(f"  Previous MAC: {result['old_mac']}")
                            print(f"  New MAC:      {result['new_mac']}")
                            print(f"  Reason:       {result['reason']}")

                            report_result("ARP", result)
                            print("-" * 60)

                    except ValueError as error:
                        print(f"[ARP PACKET SKIPPED] {error}")

            # Inspect DNS packets and process suspicious results.
            if packet.haslayer(DNS):
                result = dns_detector.process_packet(packet)

                if result["status"] == "alert":
                    alert_count += 1
                    print("\n[DNS ALERT]")
                    print(f"  Domain: {result.get('domain', 'unknown')}")

                    alerts = result.get("alerts", [])
                    answer_ips = [
                        item.get("answer_ip", "unknown")
                        for item in alerts
                    ]

                    print(f"  Suspicious answer IPs ({len(answer_ips)}):")
                    for ip in answer_ips:
                        print(f"    - {ip}")

                    reasons = list(dict.fromkeys(
                        item.get("reason", "Suspicious DNS result")
                        for item in alerts
                    ))
                    print(f"  Reason: {reasons[0] if reasons else 'Suspicious DNS result'}")

                    report_result("DNS", result)
                    print("-" * 60)

    except FileNotFoundError:
        print(f"Error: capture file not found: {pcap_file}")
        return

    except PermissionError:
        print(f"Error: permission denied reading: {pcap_file}")
        return

    print("\n" + "=" * 60)
    print("                 CAPTURE SUMMARY")
    print("=" * 60)
    print(f"  Packets processed: {packet_count}")
    print(f"  Alerts generated:  {alert_count}")
    print("  Enforcement mode:  DRY_RUN")
    print("  Packets blocked:   No")
    print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze a saved capture for suspicious ARP and DNS activity."
    )
    parser.add_argument(
        "pcap_file",
        help="Path to a saved .pcap or .pcapng file supported by Scapy",
    )
    args = parser.parse_args()

    process_capture(args.pcap_file)
