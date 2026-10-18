from scapy.all import Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

packets = [
    # First ARP mapping
    Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
    / ARP(
        op=2,
        psrc="192.0.2.1",
        hwsrc="02:00:00:00:00:01",
        pdst="192.0.2.10",
        hwdst="ff:ff:ff:ff:ff:ff",
    ),

    # Same IP, different MAC: should trigger an ARP alert
    Ether(src="02:00:00:00:00:99", dst="ff:ff:ff:ff:ff:ff")
    / ARP(
        op=2,
        psrc="192.0.2.1",
        hwsrc="02:00:00:00:00:99",
        pdst="192.0.2.10",
        hwdst="ff:ff:ff:ff:ff:ff",
    ),

    # First DNS answer for example.test
    Ether()
    / IP(src="192.0.2.53", dst="192.0.2.10")
    / UDP(sport=53, dport=53000)
    / DNS(
        id=1,
        qr=1,
        qd=DNSQR(qname="example.test"),
        an=DNSRR(rrname="example.test", type="A", rdata="192.0.2.20"),
        ancount=1,
    ),

    # Different DNS answer: should trigger a DNS alert
    Ether()
    / IP(src="192.0.2.53", dst="192.0.2.10")
    / UDP(sport=53, dport=53000)
    / DNS(
        id=2,
        qr=1,
        qd=DNSQR(qname="example.test"),
        an=DNSRR(rrname="example.test", type="A", rdata="192.0.2.99"),
        ancount=1,
    ),
]

wrpcap("demo.pcap", packets)
print("Created demo.pcap with", len(packets), "synthetic packets.")
