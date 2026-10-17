
"""Packet capture and metadata extraction for the CN review project."""

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, UDP


def _dns_name(value):
    """Convert a DNS name to readable text."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value).rstrip(".")



def _record_list(value, expected_type):
    """Normalize a DNS record, record list, or chained DNS records."""
    if value is None:
        return []

    if isinstance(value, (list, tuple)):
        records = []
        for item in value:
            records.extend(_record_list(item, expected_type))
        return records

    if isinstance(value, expected_type):
        records = []
        current = value

        while isinstance(current, expected_type):
            records.append(current)
            current = current.payload

        return records

    return []



def extract_packet(packet):
    """Convert a Scapy packet into a simple dictionary."""
    record = {
        "protocol": "OTHER",
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "details": {},
    }

    if Ether in packet:
        record["src_mac"] = packet[Ether].src
        record["dst_mac"] = packet[Ether].dst

    if IP in packet:
        record["src_ip"] = packet[IP].src
        record["dst_ip"] = packet[IP].dst

    # ARP metadata
    if ARP in packet:
        arp = packet[ARP]
        record["protocol"] = "ARP"
        record["src_mac"] = arp.hwsrc
        record["src_ip"] = arp.psrc
        record["dst_ip"] = arp.pdst
        record["details"] = {
            "operation": int(arp.op),
            "sender_mac": arp.hwsrc,
            "target_mac": arp.hwdst,
            "target_ip": arp.pdst,
        }
        return record

    # DNS metadata over UDP
    if DNS in packet and UDP in packet:
        dns = packet[DNS]
        details = {
            "is_response": bool(dns.qr),
            "transaction_id": int(dns.id),
            "questions": [],
            "answers": [],
        }

        for question in _record_list(dns.qd[0] if dns.qd else None, DNSQR):
            details["questions"].append({
                "name": _dns_name(question.qname),
                "type": int(question.qtype),
            })

        for answer in _record_list(dns.an[0] if dns.an else None, DNSRR):
            details["answers"].append({
                "name": _dns_name(answer.rrname),
                "type": int(answer.type),
                "data": str(answer.rdata),
            })

        record["protocol"] = "DNS"
        record["details"] = details
        return record

    return record


class PacketCapture:
    """Process synthetic packets or passively capture authorized lab traffic."""

    def capture_offline(self, packets):
        """Extract records from an iterable of Scapy packets."""
        return [extract_packet(packet) for packet in packets]

    def capture_live(self, interface, count=10, timeout=5):
        """Passively capture a bounded sample of ARP and UDP DNS traffic."""
        from scapy.all import sniff

        if not interface or not interface.strip():
            raise ValueError("An explicit interface name is required.")
        if count < 1:
            raise ValueError("count must be at least 1.")
        if timeout < 1:
            raise ValueError("timeout must be at least 1 second.")

        packets = sniff(
            iface=interface,
            count=count,
            timeout=timeout,
            store=True,
            filter="arp or (udp port 53)",
        )
        return self.capture_offline(packets)
