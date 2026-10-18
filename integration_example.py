
"""Example of passing captured DNS metadata to a detector."""

from packet_capture import PacketCapture


def process_records(records, detector):
    """Send DNS records to a detector's process_record method."""
    for record in records:
        if record["protocol"] == "DNS":
            detector.process_record(record["details"])


if __name__ == "__main__":
    # Synthetic input only; no network traffic is generated.
    from scapy.all import DNS, DNSQR, Ether, IP, UDP

    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(id=1234, rd=1, qd=DNSQR(qname="example.com"))
    )

    records = PacketCapture().capture_offline([packet])

    for record in records:
        print(record)
