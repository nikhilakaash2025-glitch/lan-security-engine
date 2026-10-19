
from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, UDP

from packet_capture import PacketCapture, extract_packet


def test_arp_packet():
    packet = Ether() / ARP(
        op=1,
        psrc="192.0.2.10",
        pdst="192.0.2.1",
        hwsrc="02:00:00:00:00:01",
    )

    result = extract_packet(packet)

    assert result["protocol"] == "ARP"
    assert result["src_ip"] == "192.0.2.10"
    assert result["details"]["operation"] == 1


def test_dns_query():
    packet = (
        Ether()
        / IP(src="192.0.2.10", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(id=1234, rd=1, qd=DNSQR(qname="example.com"))
    )

    result = extract_packet(packet)

    assert result["protocol"] == "DNS"
    assert result["details"]["is_response"] is False
    assert result["details"]["questions"][0]["name"] == "example.com"


def test_dns_response():
    packet = (
        Ether()
        / IP(src="192.0.2.53", dst="192.0.2.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=1234,
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                rdata="192.0.2.20",
            ),
        )
    )

    result = extract_packet(packet)

    assert result["protocol"] == "DNS"
    assert result["details"]["is_response"] is True
    assert result["details"]["answers"][0]["data"] == "192.0.2.20"


def test_offline_capture():
    packets = [Ether() / ARP(psrc="192.0.2.10", pdst="192.0.2.1")]

    records = PacketCapture().capture_offline(packets)

    assert len(records) == 1
    assert records[0]["protocol"] == "ARP"


def test_empty_packet_list():
    assert PacketCapture().capture_offline([]) == []

def test_dns_response_with_multiple_answers():
    packet = (
        Ether()
        / IP(src="192.0.2.53", dst="192.0.2.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=4321,
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(
                rrname="example.com",
                type="A",
                rdata="192.0.2.20",
            ) / DNSRR(
                rrname="example.com",
                type="A",
                rdata="192.0.2.21",
            ),
        )
    )

    result = extract_packet(packet)

    assert result["protocol"] == "DNS"
    assert len(result["details"]["answers"]) == 2
    assert {
        answer["data"] for answer in result["details"]["answers"]
    } == {"192.0.2.20", "192.0.2.21"}


import pytest


def test_capture_live_rejects_empty_interface():
    with pytest.raises(ValueError, match="interface"):
        PacketCapture().capture_live("", count=1, timeout=1)


def test_capture_live_rejects_zero_count():
    with pytest.raises(ValueError, match="count"):
        PacketCapture().capture_live("eth0", count=0, timeout=1)


def test_capture_live_rejects_zero_timeout():
    with pytest.raises(ValueError, match="timeout"):
        PacketCapture().capture_live("eth0", count=1, timeout=0)
