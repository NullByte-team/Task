"""
NullByte Tool - IP File Loader
Reads a list of IP addresses or domains from a text file.
Supports: one IP per line, ranges like 192.168.1.1-10, CIDR notation.
"""

import os
import re
import ipaddress
from typing import List


def load_ips_from_file(filepath: str) -> List[str]:
    """
    Load IPs/domains from a text file.
    Supports:
        - Single IPs:    192.168.1.1
        - Domains:       example.com
        - CIDR:          192.168.1.0/24   (expanded to individual IPs, max /24)
        - Range:         192.168.1.1-20
        - Comments:      # this line is ignored
    Returns a deduplicated list of targets.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    targets: List[str] = []
    seen = set()

    with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # CIDR notation
            if "/" in line:
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    # Limit expansion to /16 to avoid huge lists
                    if network.prefixlen < 16:
                        raise ValueError("CIDR too broad (smaller than /16). Skipping.")
                    for ip in network.hosts():
                        t = str(ip)
                        if t not in seen:
                            seen.add(t)
                            targets.append(t)
                except ValueError as e:
                    # Return the original string if expansion fails
                    if line not in seen:
                        seen.add(line)
                        targets.append(line)
                continue

            # Range notation: 192.168.1.1-20
            range_match = re.match(
                r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", line
            )
            if range_match:
                prefix = range_match.group(1)
                start  = int(range_match.group(2))
                end    = int(range_match.group(3))
                for i in range(start, min(end + 1, 256)):
                    t = f"{prefix}{i}"
                    if t not in seen:
                        seen.add(t)
                        targets.append(t)
                continue

            # Plain IP or domain
            if line not in seen:
                seen.add(line)
                targets.append(line)

    return targets


def validate_target(target: str) -> bool:
    """Check if a target string looks like a valid IP or domain."""
    # IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Domain name (simple check)
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(target))
