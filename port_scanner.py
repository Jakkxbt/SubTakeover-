#!/usr/bin/env python3
"""
Port Scanner Module with Service Detection
Inspired by Nmap's service detection capabilities
"""

import socket
import ssl
import concurrent.futures
import time
import re
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class ServiceInfo:
    """Information about a detected service"""
    port: int
    state: PortState
    service_name: str
    product: str = ""
    version: str = ""
    banner: str = ""
    ssl: bool = False
    extra_info: Dict = None

    def __post_init__(self):
        if self.extra_info is None:
            self.extra_info = {}


# Common ports and their default services
COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    902: "vmware-auth",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql-s",
    1434: "ms-sql-m",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3000: "ppp",
    3128: "squid-http",
    3306: "mysql",
    3389: "ms-wbt-server",
    4444: "krb524",
    5000: "upnp",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes",
    6667: "irc",
    7001: "weblogic",
    7002: "weblogic-ssl",
    8000: "http-alt",
    8008: "http",
    8009: "ajp13",
    8080: "http-proxy",
    8081: "blackice-icecap",
    8443: "https-alt",
    8888: "sun-answerbook",
    9000: "cslistener",
    9001: "tor-orport",
    9042: "cassandra",
    9090: "zeus-admin",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9418: "git",
    9999: "abyss",
    10000: "webmin",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
    28017: "mongodb-web",
}

# Top ports for quick scan
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]

# Service detection probes (simplified nmap-style)
SERVICE_PROBES = {
    "NULL": b"",
    "HTTP": b"GET / HTTP/1.0\r\n\r\n",
    "HTTPs": b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
    "SSH": b"SSH-2.0-OpenSSH_probe\r\n",
    "FTP": b"",
    "SMTP": b"EHLO probe\r\n",
    "POP3": b"",
    "IMAP": b"",
    "MySQL": b"",
    "Redis": b"PING\r\n",
    "MongoDB": b"\x3a\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
}

# Service signature patterns
SERVICE_SIGNATURES = {
    "ssh": [
        (r"SSH-[\d.]+-(OpenSSH[_\d.]+\S*)", "OpenSSH"),
        (r"SSH-[\d.]+-(dropbear[_\d.]+)", "Dropbear"),
        (r"SSH-[\d.]+-libssh[_\d.]+", "libssh"),
    ],
    "http": [
        (r"Server:\s*Apache[/\s]*([\d.]+)?", "Apache"),
        (r"Server:\s*nginx[/\s]*([\d.]+)?", "nginx"),
        (r"Server:\s*Microsoft-IIS[/\s]*([\d.]+)?", "Microsoft IIS"),
        (r"Server:\s*lighttpd[/\s]*([\d.]+)?", "lighttpd"),
        (r"Server:\s*Tomcat[/\s]*([\d.]+)?", "Apache Tomcat"),
        (r"Server:\s*Jetty[/\s]*([\d.]+)?", "Jetty"),
        (r"Server:\s*gunicorn[/\s]*([\d.]+)?", "Gunicorn"),
        (r"X-Powered-By:\s*PHP[/\s]*([\d.]+)?", "PHP"),
        (r"X-Powered-By:\s*ASP\.NET", "ASP.NET"),
        (r"X-Powered-By:\s*Express", "Express.js"),
    ],
    "ftp": [
        (r"220[- ].*vsftpd\s*([\d.]+)?", "vsftpd"),
        (r"220[- ].*ProFTPD\s*([\d.]+)?", "ProFTPD"),
        (r"220[- ].*Pure-FTPd", "Pure-FTPd"),
        (r"220[- ].*FileZilla Server", "FileZilla Server"),
        (r"220[- ]Microsoft FTP Service", "Microsoft FTP"),
    ],
    "smtp": [
        (r"220.*Postfix", "Postfix"),
        (r"220.*Sendmail", "Sendmail"),
        (r"220.*Microsoft ESMTP", "Microsoft SMTP"),
        (r"220.*Exim", "Exim"),
    ],
    "mysql": [
        (r"([\d.]+)-MariaDB", "MariaDB"),
        (r"([\d.]+).*MySQL", "MySQL"),
    ],
    "postgresql": [
        (r"PostgreSQL ([\d.]+)", "PostgreSQL"),
    ],
    "redis": [
        (r"\+PONG", "Redis"),
        (r"redis_version:([\d.]+)", "Redis"),
    ],
    "mongodb": [
        (r"MongoDB", "MongoDB"),
        (r"ismaster", "MongoDB"),
    ],
    "telnet": [
        (r"login:", "Telnet"),
        (r"Welcome to", "Telnet"),
    ],
    "elasticsearch": [
        (r'"cluster_name"\s*:', "Elasticsearch"),
        (r'"version"\s*:\s*\{\s*"number"\s*:\s*"([\d.]+)"', "Elasticsearch"),
    ],
}


class PortScanner:
    """Multi-threaded port scanner with service detection"""

    def __init__(self, timeout: float = 2.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: Dict[int, ServiceInfo] = {}

    def scan_port(self, host: str, port: int) -> ServiceInfo:
        """Scan a single port and detect service"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                # Port is open, try to get banner
                banner = self._grab_banner(sock, host, port)
                service_name = COMMON_PORTS.get(port, "unknown")
                product, version = self._detect_service(banner, service_name, port)

                # Check for SSL
                is_ssl = self._check_ssl(host, port)

                return ServiceInfo(
                    port=port,
                    state=PortState.OPEN,
                    service_name=service_name,
                    product=product,
                    version=version,
                    banner=banner[:500] if banner else "",
                    ssl=is_ssl,
                )
            else:
                return ServiceInfo(
                    port=port,
                    state=PortState.CLOSED,
                    service_name="",
                )
        except socket.timeout:
            return ServiceInfo(
                port=port,
                state=PortState.FILTERED,
                service_name="",
            )
        except Exception as e:
            return ServiceInfo(
                port=port,
                state=PortState.CLOSED,
                service_name="",
                extra_info={"error": str(e)}
            )
        finally:
            sock.close()

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        """Grab service banner"""
        banner = ""

        # Determine which probe to use
        probe = SERVICE_PROBES.get("NULL")

        service = COMMON_PORTS.get(port, "")
        if service in ["http", "http-proxy", "http-alt"]:
            probe = SERVICE_PROBES["HTTP"]
        elif service == "https":
            return self._grab_https_banner(host, port)
        elif service == "redis":
            probe = SERVICE_PROBES["Redis"]
        elif service == "mongodb":
            probe = SERVICE_PROBES["MongoDB"]
        elif service == "smtp":
            probe = SERVICE_PROBES["SMTP"]

        try:
            if probe:
                sock.send(probe)
            sock.settimeout(self.timeout)
            banner = sock.recv(4096).decode('utf-8', errors='ignore')
        except:
            pass

        return banner

    def _grab_https_banner(self, host: str, port: int) -> str:
        """Grab HTTPS banner with SSL"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    return ssock.recv(4096).decode('utf-8', errors='ignore')
        except:
            return ""

    def _detect_service(self, banner: str, default_service: str, port: int) -> Tuple[str, str]:
        """Detect service product and version from banner"""
        product = ""
        version = ""

        if not banner:
            return product, version

        # Try to match against known signatures
        for service, patterns in SERVICE_SIGNATURES.items():
            for pattern, prod in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    product = prod
                    if match.groups():
                        version = match.group(1) if match.group(1) else ""
                    return product, version

        return product, version

    def _check_ssl(self, host: str, port: int) -> bool:
        """Check if port has SSL/TLS"""
        # Known SSL ports
        ssl_ports = {443, 465, 636, 993, 995, 8443, 9443}
        if port in ssl_ports:
            return True

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False

    def scan_ports(self, host: str, ports: List[int]) -> Dict[int, ServiceInfo]:
        """Scan multiple ports concurrently"""
        self.results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, host, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    self.results[port] = result
                except Exception as e:
                    self.results[port] = ServiceInfo(
                        port=port,
                        state=PortState.CLOSED,
                        service_name="",
                        extra_info={"error": str(e)}
                    )

        return self.results

    def quick_scan(self, host: str) -> Dict[int, ServiceInfo]:
        """Quick scan of top ports"""
        return self.scan_ports(host, TOP_PORTS)

    def full_scan(self, host: str) -> Dict[int, ServiceInfo]:
        """Full scan of all common ports"""
        return self.scan_ports(host, list(COMMON_PORTS.keys()))

    def range_scan(self, host: str, start_port: int, end_port: int) -> Dict[int, ServiceInfo]:
        """Scan a range of ports"""
        ports = list(range(start_port, end_port + 1))
        return self.scan_ports(host, ports)

    def custom_scan(self, host: str, ports: str) -> Dict[int, ServiceInfo]:
        """Scan custom port specification (e.g., '22,80,443,8000-9000')"""
        port_list = self._parse_port_spec(ports)
        return self.scan_ports(host, port_list)

    def _parse_port_spec(self, ports: str) -> List[int]:
        """Parse port specification string"""
        result = []
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        return sorted(set(result))

    def get_open_ports(self) -> Dict[int, ServiceInfo]:
        """Get only open ports from results"""
        return {
            port: info for port, info in self.results.items()
            if info.state == PortState.OPEN
        }

    def get_services_summary(self) -> str:
        """Get summary of discovered services"""
        open_ports = self.get_open_ports()
        if not open_ports:
            return "No open ports found"

        lines = []
        for port in sorted(open_ports.keys()):
            info = open_ports[port]
            service = info.service_name
            if info.product:
                service += f" ({info.product}"
                if info.version:
                    service += f" {info.version}"
                service += ")"
            ssl_str = " [SSL]" if info.ssl else ""
            lines.append(f"  {port}/tcp  open  {service}{ssl_str}")

        return "\n".join(lines)


class ServiceVersionDetector:
    """Enhanced service version detection"""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def detect_http_server(self, host: str, port: int = 80, use_ssl: bool = False) -> Dict:
        """Detailed HTTP server detection"""
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((host, port), timeout=self.timeout)
                sock = context.wrap_socket(sock, server_hostname=host)
            else:
                sock = socket.create_connection((host, port), timeout=self.timeout)

            request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.send(request.encode())
            response = sock.recv(8192).decode('utf-8', errors='ignore')
            sock.close()

            info = {
                "server": "",
                "powered_by": "",
                "technologies": [],
                "headers": {},
            }

            for line in response.split('\r\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    info["headers"][key] = value

                    if key == "server":
                        info["server"] = value
                    elif key == "x-powered-by":
                        info["powered_by"] = value
                        info["technologies"].append(value)
                    elif key == "x-aspnet-version":
                        info["technologies"].append(f"ASP.NET {value}")

            return info
        except Exception as e:
            return {"error": str(e)}

    def detect_ssh_version(self, host: str, port: int = 22) -> Dict:
        """SSH version detection"""
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            banner = sock.recv(256).decode('utf-8', errors='ignore')
            sock.close()

            info = {"banner": banner.strip(), "product": "", "version": ""}

            for pattern, product in SERVICE_SIGNATURES["ssh"]:
                match = re.search(pattern, banner)
                if match:
                    info["product"] = product
                    if match.groups():
                        info["version"] = match.group(1)
                    break

            return info
        except Exception as e:
            return {"error": str(e)}

    def detect_database(self, host: str, port: int, db_type: str) -> Dict:
        """Database version detection"""
        info = {"type": db_type, "version": "", "status": "unknown"}

        try:
            if db_type == "mysql":
                info = self._detect_mysql(host, port)
            elif db_type == "postgresql":
                info = self._detect_postgresql(host, port)
            elif db_type == "mongodb":
                info = self._detect_mongodb(host, port)
            elif db_type == "redis":
                info = self._detect_redis(host, port)
        except Exception as e:
            info["error"] = str(e)

        return info

    def _detect_mysql(self, host: str, port: int) -> Dict:
        """MySQL version detection"""
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            data = sock.recv(1024)
            sock.close()

            # Parse MySQL handshake packet
            if len(data) > 5:
                version_end = data.find(b'\x00', 5)
                if version_end > 5:
                    version = data[5:version_end].decode('utf-8', errors='ignore')
                    return {"type": "mysql", "version": version, "status": "accessible"}

            return {"type": "mysql", "status": "accessible"}
        except:
            return {"type": "mysql", "status": "closed"}

    def _detect_postgresql(self, host: str, port: int) -> Dict:
        """PostgreSQL version detection"""
        try:
            # Send startup message
            sock = socket.create_connection((host, port), timeout=self.timeout)

            # Version request
            startup = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'  # SSL request
            sock.send(startup)
            response = sock.recv(1)
            sock.close()

            if response == b'N':
                return {"type": "postgresql", "status": "accessible", "ssl": False}
            elif response == b'S':
                return {"type": "postgresql", "status": "accessible", "ssl": True}

            return {"type": "postgresql", "status": "accessible"}
        except:
            return {"type": "postgresql", "status": "closed"}

    def _detect_mongodb(self, host: str, port: int) -> Dict:
        """MongoDB detection"""
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)

            # Send isMaster command
            query = SERVICE_PROBES["MongoDB"]
            sock.send(query)
            response = sock.recv(4096)
            sock.close()

            if b'ismaster' in response.lower() or b'maxBsonObjectSize' in response:
                return {"type": "mongodb", "status": "accessible", "auth": "none"}

            return {"type": "mongodb", "status": "accessible"}
        except:
            return {"type": "mongodb", "status": "closed"}

    def _detect_redis(self, host: str, port: int) -> Dict:
        """Redis detection"""
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            sock.send(b"INFO\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            if "+PONG" in response or "redis_version" in response:
                version_match = re.search(r'redis_version:([\d.]+)', response)
                version = version_match.group(1) if version_match else ""
                auth = "none" if "NOAUTH" not in response else "required"
                return {"type": "redis", "version": version, "status": "accessible", "auth": auth}

            if "NOAUTH" in response or "Authentication required" in response:
                return {"type": "redis", "status": "accessible", "auth": "required"}

            return {"type": "redis", "status": "accessible"}
        except:
            return {"type": "redis", "status": "closed"}


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target> [ports]")
        print("Example: python port_scanner.py 192.168.1.1")
        print("Example: python port_scanner.py example.com 22,80,443")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else None

    # Resolve hostname if needed
    if not is_valid_ip(target):
        ip = resolve_hostname(target)
        if ip:
            print(f"Resolved {target} to {ip}")
            target = ip
        else:
            print(f"Could not resolve hostname: {target}")
            sys.exit(1)

    print(f"\nScanning {target}...")
    scanner = PortScanner(timeout=2.0, max_threads=50)

    start_time = time.time()

    if ports:
        results = scanner.custom_scan(target, ports)
    else:
        results = scanner.quick_scan(target)

    elapsed = time.time() - start_time

    print(f"\nScan completed in {elapsed:.2f} seconds")
    print(f"\nOpen ports:")
    print(scanner.get_services_summary())
