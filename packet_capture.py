
import os

from scapy.all import PcapReader


def read_pcap(file_path):
    """
    Read packets from a saved PCAP file.
    An empty file yields no packets.
    """
    if os.path.getsize(file_path) == 0:
        return

    with PcapReader(file_path) as reader:
        for packet in reader:
            yield packet

