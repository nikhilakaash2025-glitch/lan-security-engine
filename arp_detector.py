
import ipaddress
import re


def normalize_ip(ip: str) -> str:
    """Validate an IP address and return its normalized form."""
    return str(ipaddress.ip_address(ip))


def normalize_mac(mac: str) -> str:
    """Validate a MAC address and return lowercase colon-separated form."""
    mac = mac.strip().lower().replace("-", ":")

    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError(f"Invalid MAC address: {mac}")

    return mac


class ArpDetector:
    """Track IP-to-MAC mappings and flag unexpected mapping changes."""

    def __init__(
        self,
        trusted_mappings=None,
        update_on_change=False,
    ):
        self.ledger = {}
        self.trusted_mappings = {}

        self.update_on_change = update_on_change

        # Normalize any configured trusted IP-to-MAC mappings.
        if trusted_mappings:
            for ip, mac in trusted_mappings.items():
                normalized_ip = normalize_ip(ip)
                normalized_mac = normalize_mac(mac)

                self.trusted_mappings[normalized_ip] = normalized_mac
                self.ledger[normalized_ip] = normalized_mac

    def process_mapping(self, ip: str, mac: str) -> dict:
        """
        Process one observed IP-to-MAC mapping.

        Returns a dictionary describing whether the mapping was learned,
        unchanged, or suspicious.
        """
        ip = normalize_ip(ip)
        mac = normalize_mac(mac)

        trusted_mac = self.trusted_mappings.get(ip)

        if trusted_mac is not None and mac != trusted_mac:
            return {
                "status": "alert",
                "ip": ip,
                "old_mac": trusted_mac,
                "new_mac": mac,
                "reason": "Mapping conflicts with trusted configuration",
            }

        old_mac = self.ledger.get(ip)

        if old_mac is None:
            self.ledger[ip] = mac
            return {
                "status": "learned",
                "ip": ip,
                "old_mac": None,
                "new_mac": mac,
                "reason": "First mapping observed",
            }

        if old_mac == mac:
            return {
                "status": "unchanged",
                "ip": ip,
                "old_mac": old_mac,
                "new_mac": mac,
                "reason": "Mapping matches existing ledger",
            }

        # A changed mapping is suspicious, but not proof of an attack.
        if self.update_on_change:
            self.ledger[ip] = mac

        return {
            "status": "alert",
            "ip": ip,
            "old_mac": old_mac,
            "new_mac": mac,
            "reason": "IP address is now associated with a different MAC",
        }

    def get_ledger(self) -> dict:
        """Return a copy of the current IP-to-MAC ledger."""
        return self.ledger.copy()
