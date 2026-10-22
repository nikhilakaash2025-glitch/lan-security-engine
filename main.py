
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
    """Score, log, and display response recommendations."""
    processed = process_result(event_type, result)

    for item in processed:
        risk = item["risk"]
        response = item["response"]

        print(f"  Risk score: {risk['risk_score']}/100")
        print(f"  Threat level: {risk['risk_level']}")
        print(f"  Recommended action: {response['action']}")
        print(f"  Response mode: {response['mode']}")
        print(f"  Packets blocked: {response['blocked']}")


def process_capture(pcap_file):
    """Process a saved capture using ARP and DNS detectors."""
    arp_detector = ArpDetector()
    dns_detector = DNSDetector()

    packet_count = 0
    alert_count = 0

    print(f"Reading capture: {pcap_file}")

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
                            print(f"  IP:      {result['ip']}")
                            print(f"  Old MAC: {result['old_mac']}")
                            print(f"  New MAC: {result['new_mac']}")
                            print(f"  Reason:  {result['reason']}")

                            report_result("ARP", result)

                    except ValueError as error:
                        print(f"[ARP PACKET SKIPPED] {error}")

            # Inspect DNS packets and process suspicious results.
            if packet.haslayer(DNS):
                result = dns_detector.process_packet(packet)

                if result["status"] == "alert":
                    alert_count += 1
                    print("\n[DNS ALERT]")
                    print(f"  Domain: {result.get('domain', 'unknown')}")

                    for item in result.get("alerts", []):
                        print(f"  Answer IP: {item.get('answer_ip', 'unknown')}")
                        print(f"  Reason:    {item.get('reason', 'Suspicious DNS result')}")

                    report_result("DNS", result)

    except FileNotFoundError:
        print(f"Error: capture file not found: {pcap_file}")
        return

    except PermissionError:
        print(f"Error: permission denied reading: {pcap_file}")
        return

    print("\n--- Capture Summary ---")
    print(f"Packets processed: {packet_count}")
    print(f"Alerts generated:  {alert_count}")
    print("Enforcement mode: DRY_RUN (no packets blocked)")


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
