
import os
import tempfile
import unittest

from scapy.all import Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

from main import process_capture


class TestMainIntegration(unittest.TestCase):
    def run_capture(self, packets):
        temp_file = tempfile.NamedTemporaryFile(
            suffix=".pcap", delete=False
        )
        temp_file.close()

        try:
            wrpcap(temp_file.name, packets)
            process_capture(temp_file.name)
        finally:
            os.unlink(temp_file.name)

    def test_empty_capture(self):
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.NamedTemporaryFile(suffix=".pcap") as capture:
            output = StringIO()

            with redirect_stdout(output):
                process_capture(capture.name)

        self.assertIn("Packets processed: 0", output.getvalue())
        self.assertIn("Alerts generated:  0", output.getvalue())


    def test_arp_mapping_change_generates_alert(self):
        packets = [
            Ether() / ARP(
                op=2,
                psrc="192.0.2.1",
                hwsrc="02:00:00:00:00:01",
                pdst="192.0.2.10",
                hwdst="02:00:00:00:00:10",
            ),
            Ether() / ARP(
                op=2,
                psrc="192.0.2.1",
                hwsrc="02:00:00:00:00:99",
                pdst="192.0.2.10",
                hwdst="02:00:00:00:00:10",
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap") as capture:
            wrpcap(capture.name, packets)

            # The second mapping should produce an ARP alert.
            from contextlib import redirect_stdout
            from io import StringIO

            output = StringIO()
            with redirect_stdout(output):
                process_capture(capture.name)

            self.assertIn("[ARP ALERT]", output.getvalue())
            self.assertIn("192.0.2.1", output.getvalue())

    def test_dns_response_is_processed(self):
        dns_packet = (
            Ether()
            / IP(src="192.0.2.53", dst="192.0.2.10")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="example.test"),
                an=DNSRR(
                    rrname="example.test",
                    type="A",
                    rdata="192.0.2.20",
                ),
                ancount=1,
            )
        )

        with tempfile.NamedTemporaryFile(suffix=".pcap") as capture:
            wrpcap(capture.name, [dns_packet])

            from contextlib import redirect_stdout
            from io import StringIO

            output = StringIO()
            with redirect_stdout(output):
                process_capture(capture.name)

            self.assertIn("Packets processed: 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
