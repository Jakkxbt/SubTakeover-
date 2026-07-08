#!/usr/bin/env python3
"""
Target Parser Module
Parses and validates URLs, IPs, domains, and target files
"""

import os
import re
import socket
import ipaddress
from typing import List, Dict, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin
import json


class TargetType(Enum):
    URL = "URL"
    IP = "IP Address"
    IP_RANGE = "IP Range"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    CIDR = "CIDR Network"
    HOSTNAME = "Hostname"
    UNKNOWN = "Unknown"


@dataclass
class Target:
    """Parsed target with metadata"""
    original: str
    target_type: TargetType
    value: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    path: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)
    resolved_ip: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def get_url(self, with_path: bool = True) -> str:
        """Get URL representation of target"""
        if self.target_type == TargetType.URL:
            return self.original

        protocol = self.protocol or "http"
        port_str = f":{self.port}" if self.port and self.port not in [80, 443] else ""
        path_str = self.path if with_path and self.path else ""

        # Re-append query parameters — without them the web scanners (XSS/SQLi)
        # receive a parameter-less URL and have nothing to test.
        query_str = ""
        if with_path and self.params:
            query_str = "?" + "&".join(f"{k}={v}" for k, v in self.params.items())

        return f"{protocol}://{self.value}{port_str}{path_str}{query_str}"

    def get_host(self) -> str:
        """Get hostname or IP"""
        return self.value

    def get_base_url(self) -> str:
        """Get base URL without path"""
        return self.get_url(with_path=False)


class TargetParser:
    """Parser for various target formats"""

    # Regex patterns
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
    IP_RANGE_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$')
    DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)

    def __init__(self, resolve_dns: bool = False, default_ports: List[int] = None):
        self.resolve_dns = resolve_dns
        self.default_ports = default_ports or [80, 443, 8080, 8443]
        self.targets: List[Target] = []

    def parse(self, target_str: str) -> Target:
        """Parse a single target string"""
        target_str = target_str.strip()

        if not target_str:
            return Target(original=target_str, target_type=TargetType.UNKNOWN, value="")

        # Check if it's a URL
        if self._is_url(target_str):
            return self._parse_url(target_str)

        # Check if it's a CIDR notation
        if self._is_cidr(target_str):
            return self._parse_cidr(target_str)

        # Check if it's an IP range
        if self._is_ip_range(target_str):
            return self._parse_ip_range(target_str)

        # Check if it's an IP address
        if self._is_ip(target_str):
            return self._parse_ip(target_str)

        # Check if it's a domain
        if self._is_domain(target_str):
            return self._parse_domain(target_str)

        # Try to parse as hostname:port
        if ':' in target_str and not target_str.startswith('http'):
            host, port_str = target_str.rsplit(':', 1)
            try:
                port = int(port_str)
                if self._is_ip(host):
                    target = self._parse_ip(host)
                elif self._is_domain(host):
                    target = self._parse_domain(host)
                else:
                    target = Target(original=target_str, target_type=TargetType.HOSTNAME, value=host)
                target.port = port
                return target
            except ValueError:
                pass

        # Default to hostname
        return Target(original=target_str, target_type=TargetType.HOSTNAME, value=target_str)

    def parse_file(self, file_path: str) -> List[Target]:
        """Parse targets from a file"""
        targets = []

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target file not found: {file_path}")

        ext = os.path.splitext(file_path)[1].lower()

        if ext == '.json':
            targets = self._parse_json_file(file_path)
        elif ext in ['.csv', '.tsv']:
            targets = self._parse_csv_file(file_path)
        elif ext in ['.xml', '.nmap']:
            targets = self._parse_nmap_xml(file_path)
        else:
            # Plain text file (one target per line)
            targets = self._parse_text_file(file_path)

        self.targets.extend(targets)
        return targets

    def _parse_text_file(self, file_path: str) -> List[Target]:
        """Parse plain text file with targets"""
        targets = []

        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                target = self.parse(line)
                if target.target_type != TargetType.UNKNOWN:
                    targets.append(target)

        return targets

    def _parse_json_file(self, file_path: str) -> List[Target]:
        """Parse JSON file with targets"""
        targets = []

        with open(file_path, 'r') as f:
            data = json.load(f)

        # Handle different JSON formats
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    targets.append(self.parse(item))
                elif isinstance(item, dict):
                    if 'url' in item:
                        target = self.parse(item['url'])
                    elif 'target' in item:
                        target = self.parse(item['target'])
                    elif 'host' in item:
                        target = self.parse(item['host'])
                    elif 'ip' in item:
                        target = self.parse(item['ip'])
                    else:
                        continue
                    # Add metadata
                    target.metadata = {k: v for k, v in item.items() if k not in ['url', 'target', 'host', 'ip']}
                    targets.append(target)
        elif isinstance(data, dict):
            if 'targets' in data:
                return self._parse_json_content(data['targets'])
            if 'hosts' in data:
                return self._parse_json_content(data['hosts'])

        return targets

    def _parse_json_content(self, items: list) -> List[Target]:
        """Parse JSON content items"""
        targets = []
        for item in items:
            if isinstance(item, str):
                targets.append(self.parse(item))
            elif isinstance(item, dict):
                target_str = item.get('url') or item.get('target') or item.get('host') or item.get('ip', '')
                if target_str:
                    target = self.parse(target_str)
                    target.metadata = item
                    targets.append(target)
        return targets

    def _parse_csv_file(self, file_path: str) -> List[Target]:
        """Parse CSV file with targets"""
        targets = []

        with open(file_path, 'r') as f:
            # Determine delimiter
            first_line = f.readline()
            f.seek(0)
            delimiter = '\t' if '\t' in first_line else ','

            # Check if first line is header
            headers = None
            if any(h in first_line.lower() for h in ['url', 'target', 'host', 'ip', 'domain']):
                headers = [h.strip().lower() for h in first_line.split(delimiter)]
                next(f)  # Skip header

            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(delimiter)

                if headers:
                    # Use headers to find target column
                    row = dict(zip(headers, parts))
                    target_str = row.get('url') or row.get('target') or row.get('host') or row.get('ip') or row.get('domain', '')
                    if target_str:
                        target = self.parse(target_str.strip())
                        target.metadata = row
                        targets.append(target)
                else:
                    # First column is target
                    target = self.parse(parts[0].strip())
                    if len(parts) > 1:
                        target.metadata['extra'] = parts[1:]
                    targets.append(target)

        return targets

    def _parse_nmap_xml(self, file_path: str) -> List[Target]:
        """Parse Nmap XML output file"""
        targets = []

        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall('.//host'):
                # Get IP address
                address = host.find('address[@addrtype="ipv4"]')
                if address is None:
                    address = host.find('address[@addrtype="ipv6"]')
                if address is None:
                    continue

                ip = address.get('addr')

                # Get hostname if available
                hostname = None
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname[@type="PTR"]')
                    if hostname_elem is None:
                        hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')

                # Get open ports
                ports = []
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_num = int(port.get('portid'))
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        ports.append({'port': port_num, 'service': service_name})

                # Create target for each open port or just the host
                if ports:
                    for port_info in ports:
                        target = Target(
                            original=ip,
                            target_type=TargetType.IP,
                            value=hostname or ip,
                            port=port_info['port'],
                            resolved_ip=ip,
                            metadata={'service': port_info['service'], 'hostname': hostname}
                        )
                        targets.append(target)
                else:
                    target = Target(
                        original=ip,
                        target_type=TargetType.IP,
                        value=hostname or ip,
                        resolved_ip=ip,
                        metadata={'hostname': hostname}
                    )
                    targets.append(target)

        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")

        return targets

    def _is_url(self, s: str) -> bool:
        """Check if string is a URL"""
        return bool(self.URL_PATTERN.match(s)) or s.startswith(('http://', 'https://'))

    def _is_ip(self, s: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _is_cidr(self, s: str) -> bool:
        """Check if string is CIDR notation"""
        try:
            ipaddress.ip_network(s, strict=False)
            return '/' in s
        except ValueError:
            return False

    def _is_ip_range(self, s: str) -> bool:
        """Check if string is an IP range (start-end)"""
        if '-' not in s:
            return False
        parts = s.split('-')
        if len(parts) != 2:
            return False
        return self._is_ip(parts[0].strip()) and self._is_ip(parts[1].strip())

    def _is_domain(self, s: str) -> bool:
        """Check if string is a valid domain"""
        return bool(self.DOMAIN_PATTERN.match(s))

    def _parse_url(self, url_str: str) -> Target:
        """Parse URL into Target"""
        parsed = urlparse(url_str)

        # Extract query parameters
        params = {}
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value

        # Determine port
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == 'https' else 80

        # Determine target type
        host = parsed.hostname or ''
        if self._is_ip(host):
            target_type = TargetType.IP
        else:
            target_type = TargetType.URL

        target = Target(
            original=url_str,
            target_type=target_type,
            value=host,
            port=port,
            protocol=parsed.scheme,
            path=parsed.path or '/',
            params=params
        )

        if self.resolve_dns and not self._is_ip(host):
            target.resolved_ip = self._resolve_hostname(host)

        return target

    def _parse_ip(self, ip_str: str) -> Target:
        """Parse IP address into Target"""
        return Target(
            original=ip_str,
            target_type=TargetType.IP,
            value=ip_str,
            resolved_ip=ip_str
        )

    def _parse_cidr(self, cidr_str: str) -> Target:
        """Parse CIDR notation into Target"""
        network = ipaddress.ip_network(cidr_str, strict=False)

        return Target(
            original=cidr_str,
            target_type=TargetType.CIDR,
            value=cidr_str,
            metadata={
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'num_hosts': network.num_addresses - 2 if network.num_addresses > 2 else 1,
                'hosts': [str(ip) for ip in network.hosts()]
            }
        )

    def _parse_ip_range(self, range_str: str) -> Target:
        """Parse IP range into Target"""
        start_ip, end_ip = range_str.split('-')
        start = ipaddress.ip_address(start_ip.strip())
        end = ipaddress.ip_address(end_ip.strip())

        # Generate list of IPs in range
        hosts = []
        current = start
        while current <= end:
            hosts.append(str(current))
            current += 1

        return Target(
            original=range_str,
            target_type=TargetType.IP_RANGE,
            value=range_str,
            metadata={
                'start_ip': str(start),
                'end_ip': str(end),
                'num_hosts': len(hosts),
                'hosts': hosts
            }
        )

    def _parse_domain(self, domain_str: str) -> Target:
        """Parse domain into Target"""
        # Check if it's a subdomain
        parts = domain_str.split('.')
        target_type = TargetType.SUBDOMAIN if len(parts) > 2 else TargetType.DOMAIN

        target = Target(
            original=domain_str,
            target_type=target_type,
            value=domain_str
        )

        if self.resolve_dns:
            target.resolved_ip = self._resolve_hostname(domain_str)

        return target

    def _resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def expand_targets(self) -> List[Target]:
        """Expand CIDR and IP ranges into individual targets"""
        expanded = []

        for target in self.targets:
            if target.target_type == TargetType.CIDR:
                hosts = target.metadata.get('hosts', [])
                for host in hosts:
                    expanded.append(Target(
                        original=host,
                        target_type=TargetType.IP,
                        value=host,
                        resolved_ip=host
                    ))
            elif target.target_type == TargetType.IP_RANGE:
                hosts = target.metadata.get('hosts', [])
                for host in hosts:
                    expanded.append(Target(
                        original=host,
                        target_type=TargetType.IP,
                        value=host,
                        resolved_ip=host
                    ))
            else:
                expanded.append(target)

        return expanded

    def get_unique_hosts(self) -> Set[str]:
        """Get unique host values from all targets"""
        hosts = set()
        for target in self.targets:
            hosts.add(target.value)
            if target.resolved_ip:
                hosts.add(target.resolved_ip)
        return hosts

    def get_urls(self) -> List[str]:
        """Get URL representations of all targets"""
        return [target.get_url() for target in self.targets]

    def filter_by_type(self, target_type: TargetType) -> List[Target]:
        """Filter targets by type"""
        return [t for t in self.targets if t.target_type == target_type]

    def add_target(self, target_str: str) -> Target:
        """Add a single target"""
        target = self.parse(target_str)
        self.targets.append(target)
        return target

    def clear(self):
        """Clear all targets"""
        self.targets = []


def parse_targets_from_string(targets_str: str) -> List[Target]:
    """Parse multiple targets from a string (comma or newline separated)"""
    parser = TargetParser()

    # Split by comma or newline
    targets = re.split(r'[,\n]', targets_str)

    for target_str in targets:
        target_str = target_str.strip()
        if target_str:
            parser.add_target(target_str)

    return parser.targets


def validate_target(target_str: str) -> Tuple[bool, str]:
    """Validate a target string and return (is_valid, error_message)"""
    parser = TargetParser()
    target = parser.parse(target_str)

    if target.target_type == TargetType.UNKNOWN:
        return False, f"Could not determine target type for: {target_str}"

    return True, f"Valid {target.target_type.value}: {target.value}"


if __name__ == "__main__":
    import sys

    parser = TargetParser(resolve_dns=True)

    # Test various target formats
    test_targets = [
        "http://example.com",
        "https://example.com/path?id=1&name=test",
        "192.168.1.1",
        "192.168.1.0/24",
        "192.168.1.1-192.168.1.10",
        "example.com",
        "sub.example.com",
        "192.168.1.1:8080",
        "example.com:443",
    ]

    print("Target Parser Test")
    print("=" * 60)

    for target_str in test_targets:
        target = parser.parse(target_str)
        print(f"\nInput: {target_str}")
        print(f"  Type: {target.target_type.value}")
        print(f"  Value: {target.value}")
        print(f"  Port: {target.port}")
        print(f"  Protocol: {target.protocol}")
        print(f"  URL: {target.get_url()}")
        if target.resolved_ip:
            print(f"  Resolved IP: {target.resolved_ip}")

    # Test file parsing if file argument provided
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        print(f"\n\nParsing file: {file_path}")
        print("=" * 60)

        targets = parser.parse_file(file_path)
        for target in targets:
            print(f"  {target.target_type.value}: {target.value}")
