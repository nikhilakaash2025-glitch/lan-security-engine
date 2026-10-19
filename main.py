
from scapy.all import ARP, DNS

from arp_detector import ArpDetector
from dns_detector import DNSDetector
from packet_capture import read_pcap


def process_capture(pcap_file):
    """Process a saved packet capture using the ARP and DNS detectors."""
    arp_detector = ArpDetector()
    dns_detector = DNSDetector()

    packet_count = 0
    alert_count = 0

    print(f"Reading capture: {pcap_file}")

    try:
        for packet in read_pcap(pcap_file):
            packet_count += 1

            # Inspect ARP packets that contain a sender IP and MAC.
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

                    except ValueError as error:
                        print(f"[ARP PACKET SKIPPED] {error}")

            # Inspect DNS responses and print suspicious-answer alerts.
            if packet.haslayer(DNS):
                result = dns_detector.process_packet(packet)

                if result["status"] == "alert":
                    alert_count += 1
                    print("\n[DNS ALERT]")
                    print(f"  Domain: {result.get('domain', 'unknown')}")

                    for item in result.get("alerts", []):
                        print(f"  Answer IP: {item['answer_ip']}")
                        print(f"  Reason:    {item['reason']}")

    except FileNotFoundError:
        print(f"Error: capture file not found: {pcap_file}")
        return

    except PermissionError:
        print(f"Error: permission denied reading: {pcap_file}")
        return

    print("\n--- Capture Summary ---")
    print(f"Packets processed: {packet_count}")
    print(f"Alerts generated:  {alert_count}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze a saved capture for suspicious ARP and DNS changes."
    )
    parser.add_argument(
        "pcap_file",
        help="Path to a saved .pcap or .pcapng file supported by Scapy",
    )
    args = parser.parse_args()

    process_capture(args.pcap_file)
