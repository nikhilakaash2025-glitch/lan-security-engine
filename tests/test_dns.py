
import unittest

from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR

from dns_detector import DNSDetector



def make_dns_response(domain, answer_ip):
    """Build and parse a synthetic DNS response packet."""
    packet = (
        Ether()
        / IP(src="192.0.2.53", dst="192.0.2.100")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=1234,
            qr=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(
                rrname=domain,
                type="A",
                ttl=60,
                rdata=answer_ip,
            ),
            ancount=1,
        )
    )

    # Serialize and parse again so Scapy populates the DNS fields.
    return Ether(bytes(packet))



class TestDNSDetector(unittest.TestCase):

    def setUp(self):
        self.detector = DNSDetector()

    def test_first_answer_establishes_baseline(self):
        packet = make_dns_response("example.com", "192.0.2.10")

        result = self.detector.process_packet(packet)

        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["domain"], "example.com")

    def test_multiple_known_answers_do_not_alert(self):
        first = make_dns_response("example.com", "192.0.2.10")
        second = make_dns_response("example.com", "192.0.2.20")

        self.detector.process_packet(first)

    # Configure the second IP as another known, legitimate answer.
        self.detector.ledger[("example.com", "A")].add("192.0.2.20")

        result = self.detector.process_packet(second)

        self.assertEqual(result["status"], "observed")

    def test_same_answer_does_not_alert(self):
        packet = make_dns_response("example.com", "192.0.2.10")

        self.detector.process_packet(packet)
        result = self.detector.process_packet(packet)

        self.assertEqual(result["status"], "observed")

    def test_changed_answer_generates_alert(self):
        first = make_dns_response("example.com", "192.0.2.10")
        second = make_dns_response("example.com", "192.0.2.99")

        self.detector.process_packet(first)
        result = self.detector.process_packet(second)

        self.assertEqual(result["status"], "alert")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(
            result["alerts"][0]["answer_ip"],
            "192.0.2.99",
        )

    def test_non_dns_packet_is_ignored(self):
        packet = Ether() / IP(dst="192.0.2.10") / UDP(dport=12345)

        result = self.detector.process_packet(packet)

        self.assertEqual(result["status"], "ignored")


if __name__ == "__main__":
    unittest.main()
