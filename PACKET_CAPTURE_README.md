# Packet Capture Module

## Purpose

`packet_capture.py` extracts ARP and DNS metadata from Scapy packets for the Computer Networks Final Review project. It supports offline packet processing and bounded, passive live capture on an explicitly selected interface.

## Dependencies

- Python 3.12+
- Scapy 2.8.0
- pytest 9.1.1 for tests
- System libpcap libraries for BPF-filtered live capture

Install Python dependencies inside the project virtual environment:

```bash
python -m pip install -r requirements.txt
```

## Public interface

### `extract_packet(packet)`

Converts one Scapy packet into a dictionary.

### `PacketCapture.capture_offline(packets)`

Accepts an iterable of Scapy packets and returns a list of extracted dictionaries. Useful for synthetic tests and offline PCAP processing.

### `PacketCapture.capture_live(interface, count=10, timeout=5)`

Passively captures a bounded sample of ARP and UDP DNS traffic on the specified interface.

- `interface`: required interface name, such as `eth0`
- `count`: maximum number of matching packets; must be at least 1
- `timeout`: capture timeout in seconds; must be at least 1
- Returns: a list of extracted packet dictionaries

Live capture may require elevated privileges and only captures traffic visible to the selected interface. Use it only on systems and networks you are authorized to inspect.

## Output format

Every extracted packet has these top-level keys:

- `protocol`: `ARP`, `DNS`, or `OTHER`
- `src_mac`, `dst_mac`: MAC addresses when available
- `src_ip`, `dst_ip`: IPv4 addresses when available
- `details`: protocol-specific metadata

For DNS packets, `details` includes:

- `is_response`: Boolean indicating query or response
- `transaction_id`: DNS transaction ID
- `questions`: list of question dictionaries with `name` and `type`
- `answers`: list of answer dictionaries with `name`, `type`, and `data`

For ARP packets, `details` includes the operation, sender MAC, target MAC, and target IP.

## Run tests

From the project root:

```bash
python -m pytest -v
```

## Current test coverage

Nine tests cover ARP extraction, DNS queries and responses, multiple DNS answers, offline capture, empty packet input, and invalid live-capture arguments.

## Limitations

- Live capture may return an empty list when no matching packets are visible during the capture window.
- WSL2 virtual networking may not expose all traffic visible on the Windows host or physical network.
- This module extracts metadata only. It does not detect anomalies, transmit packets, spoof DNS, or isolate network interfaces.
