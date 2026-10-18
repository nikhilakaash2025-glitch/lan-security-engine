# DNS Anomaly Detection Module

## Project
Lightweight ARP Poisoning & DNS Spoofing Detection Engine
with Automated Interface Isolation

## Module Owner
Member 3 - DNS Detection

## Overview
This module analyzes normalized DNS query and response
records to identify potentially suspicious DNS activity.

## Detection Features

1. Unexpected DNS Answers
   Detects DNS A records containing IP addresses outside
   the configured expected-answer list.

2. Unauthorized DNS Servers
   Detects responses from DNS servers not included in
   the configured approved-server list.

3. Conflicting DNS Answers
   Detects different A-record answers for the same domain
   within a configurable time window.

4. Unsolicited DNS Responses
   Detects DNS responses without a matching recent query.

5. Expired Query Cleanup
   Removes pending queries that exceed the configured timeout
   when subsequent records are processed.

## Files

dns_detector.py
    Main DNS detection engine.

dns_config.json
    Detection rules and configuration settings.

tests/test_dns_detector.py
    Automated unit tests using synthetic DNS records.

## Requirements

Python 3.12 or another compatible Python 3 version.

The module uses Python's standard library.

## Running Tests

From the project directory:

python3 -m unittest discover -s tests -v

## Checking Syntax

python3 -m py_compile dns_detector.py

## Integration With Packet Capture

The packet capture module should convert captured DNS
packets into normalized dictionaries.

Example DNS response:

{
    "timestamp": 1001.0,
    "src_ip": "8.8.8.8",
    "dst_ip": "192.168.1.10",
    "transaction_id": 1234,
    "domain": "example.com",
    "record_type": "A",
    "is_response": True,
    "answers": ["93.184.215.14"]
}

Example integration:

from dns_detector import DNSDetector

detector = DNSDetector("dns_config.json")

alerts = detector.process_record(record)

for alert in alerts:
    print(alert)

## Important Integration Notes

- Process DNS queries and responses in chronological order.
- Use consistent timestamps for matching and expiration.
- DNS responses must contain the required dictionary fields.
- A response's source IP identifies the responding DNS server.
- Query and response transaction IDs must match.
- Query and response source/destination addresses are reversed.
- The detector returns a list of alert dictionaries.
- The integration layer is responsible for forwarding alerts
  to the team's logging or response module.
- This module does not isolate network interfaces itself.

## Limitations

- DNS anomalies are indicators, not proof of DNS spoofing.
- Legitimate DNS load balancing can produce different answers.
- Missing captured queries can cause unsolicited-response alerts.
- Expected DNS answers must be maintained in the configuration.
- Conflict detection compares the current answer with the most
  recently stored answer for the same domain.
- Pending-query cleanup occurs when records are processed.
- The module currently focuses on DNS A-record answer anomalies.
- This module does not independently capture network packets.

## Testing

The module includes synthetic tests covering:

- Expected DNS answers
- Unexpected DNS answers
- Authorized DNS servers
- Unauthorized DNS servers
- Conflicting DNS answers
- Identical DNS answers
- Conflicts outside the configured time window
- Matching DNS queries and responses
- Unsolicited DNS responses
- Responses after the query timeout
- Expired pending-query cleanup

No spoofed network traffic is required for these tests.


## Integration Example

The file `dns_integration_example.py` demonstrates how
another module can communicate with the DNS detector.

Run it using:

python3 dns_integration_example.py

The example:

1. Initializes the DNS detector.
2. Sends a simulated DNS query.
3. Sends a simulated suspicious DNS response.
4. Receives DNS detection alerts.
5. Displays the alert type, severity, and description.

The example uses synthetic records and does not capture
live network traffic.

Member 1 can use this example as a reference when
connecting the packet capture module.

