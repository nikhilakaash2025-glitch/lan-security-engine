from dns_detector import DNSDetector

# Initialize the DNS detector
detector = DNSDetector("dns_config.json")

# Example DNS query
query = {
    "timestamp": 1000.0,
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "transaction_id": 1234,
    "domain": "example.com",
    "record_type": "A",
    "is_response": False,
    "answers": []
}

# Example suspicious DNS response
response = {
    "timestamp": 1001.0,
    "src_ip": "8.8.8.8",
    "dst_ip": "192.168.1.10",
    "transaction_id": 1234,
    "domain": "example.com",
    "record_type": "A",
    "is_response": True,
    "answers": ["192.0.2.99"]
}

# Process the DNS query
detector.process_record(query)

# Process the DNS response
alerts = detector.process_record(response)

# Display detected alerts
print("\n--- DNS DETECTION RESULTS ---")

if alerts:
    for alert in alerts:
        print(f"Alert Type: {alert['alert_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Description: {alert['description']}")
        print("----------------------------")
else:
    print("No DNS anomalies detected.")
