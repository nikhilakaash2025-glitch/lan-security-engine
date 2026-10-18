
import os
import tempfile
import unittest

from scapy.all import Ether, IP, UDP, Raw, wrpcap

from packet_capture import read_pcap


class TestPacketCapture(unittest.TestCase):

    def test_read_pcap_returns_saved_packets(self):
        # Create a temporary PCAP containing synthetic packets.
        packets = [
            Ether() / IP(dst="192.0.2.10") / UDP(dport=53) / Raw(b"test1"),
            Ether() / IP(dst="192.0.2.20") / UDP(dport=53) / Raw(b"test2"),
        ]

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name

        try:
            wrpcap(pcap_path, packets)

            captured_packets = list(read_pcap(pcap_path))

            self.assertEqual(len(captured_packets), 2)
            self.assertTrue(captured_packets[0].haslayer(IP))
            self.assertEqual(captured_packets[0][IP].dst, "192.0.2.10")
            self.assertEqual(captured_packets[1][IP].dst, "192.0.2.20")

        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)


if __name__ == "__main__":
    unittest.main()
