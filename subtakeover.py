#!/usr/bin/env python3
"""
SubTakeover - Subdomain Takeover Detection Tool
A command-line tool for detecting potential subdomain takeover vulnerabilities

Author: Security Researcher
Usage: python3 subtakeover.py -d domain.com OR python3 subtakeover.py -f domains.txt
"""

import argparse
import sys
import os
import time
import concurrent.futures
from urllib.parse import urlparse
import socket
import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import dns.resolver
import threading
from datetime import datetime

from signatures import TAKEOVER_SIGNATURES
from utils import ColorOutput, validate_domain, extract_domain_from_url

class SubTakeoverScanner:
    def __init__(self, threads=10, timeout=10, verbose=False):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.color = ColorOutput()
        self.results = []
        self.lock = threading.Lock()
        
        # Configure requests session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                    SubTakeover v1.0                      ║
║              Subdomain Takeover Detection Tool           ║
║                                                           ║
║  GitHub: https://github.com/yourusername/subtakeover     ║
║  Author: Security Researcher                             ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(self.color.cyan(banner))
        
    def resolve_domain(self, domain):
        """Resolve domain to IP addresses and get CNAME records"""
        try:
            # Get A records
            a_records = []
            try:
                answers = self.resolver.resolve(domain, 'A')
                a_records = [str(rdata) for rdata in answers]
            except Exception:
                pass
                
            # Get CNAME records
            cname_records = []
            try:
                answers = self.resolver.resolve(domain, 'CNAME')
                cname_records = [str(rdata) for rdata in answers]
            except Exception:
                pass
                
            return {
                'a_records': a_records,
                'cname_records': cname_records,
                'resolved': len(a_records) > 0 or len(cname_records) > 0
            }
        except Exception as e:
            if self.verbose:
                print(self.color.red(f"DNS resolution error for {domain}: {str(e)}"))
            return {'a_records': [], 'cname_records': [], 'resolved': False}
            
    def check_http_response(self, domain):
        """Check HTTP response for takeover indicators"""
        results = {'http': None, 'https': None}
        
        for protocol in ['http', 'https']:
            url = f"{protocol}://{domain}"
            try:
                response = self.session.get(
                    url, 
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={'User-Agent': 'SubTakeover Scanner'}
                )
                
                results[protocol] = {
                    'status_code': response.status_code,
                    'content': response.text[:2000],  # First 2000 chars
                    'headers': dict(response.headers),
                    'final_url': response.url
                }
                
            except requests.exceptions.SSLError as e:
                if protocol == 'https':
                    results[protocol] = {'error': 'SSL_ERROR', 'message': str(e)}
            except requests.exceptions.ConnectionError as e:
                results[protocol] = {'error': 'CONNECTION_ERROR', 'message': str(e)}
            except requests.exceptions.Timeout:
                results[protocol] = {'error': 'TIMEOUT', 'message': 'Request timeout'}
            except Exception as e:
                results[protocol] = {'error': 'UNKNOWN', 'message': str(e)}
                
        return results
        
    def check_takeover_signatures(self, domain, dns_info, http_info):
        """Check for known takeover signatures"""
        vulnerabilities = []
        confidence_score = 0
        
        # Check DNS-based signatures
        for cname in dns_info.get('cname_records', []):
            cname_lower = cname.lower().rstrip('.')
            
            for service, signature in TAKEOVER_SIGNATURES.items():
                # Check CNAME patterns
                for pattern in signature.get('cname_patterns', []):
                    if pattern.lower() in cname_lower:
                        # Check if DNS resolution fails (potential takeover)
                        if not dns_info.get('a_records'):
                            vulnerabilities.append({
                                'type': 'DNS_CNAME_TAKEOVER',
                                'service': service,
                                'evidence': f'CNAME points to {cname} but no A record found',
                                'confidence': 'HIGH',
                                'cname': cname,
                                'pattern_matched': pattern
                            })
                            confidence_score += 80
                            
        # Check HTTP-based signatures
        for protocol in ['http', 'https']:
            http_data = http_info.get(protocol)
            if not http_data or 'error' in http_data:
                continue
                
            content = http_data.get('content', '').lower()
            status_code = http_data.get('status_code', 0)
            
            for service, signature in TAKEOVER_SIGNATURES.items():
                # Check content patterns
                for pattern in signature.get('content_patterns', []):
                    if pattern.lower() in content:
                        vulnerabilities.append({
                            'type': 'HTTP_CONTENT_TAKEOVER',
                            'service': service,
                            'evidence': f'Found signature pattern in {protocol.upper()} response',
                            'confidence': 'MEDIUM',
                            'status_code': status_code,
                            'pattern_matched': pattern
                        })
                        confidence_score += 60
                        
                # Check status code patterns
                if status_code in signature.get('status_codes', []):
                    vulnerabilities.append({
                        'type': 'HTTP_STATUS_TAKEOVER',
                        'service': service,
                        'evidence': f'{protocol.upper()} returned status {status_code}',
                        'confidence': 'LOW',
                        'status_code': status_code
                    })
                    confidence_score += 30
                    
        return vulnerabilities, min(confidence_score, 100)
        
    def perform_takeover_poc(self, domain, vulnerabilities):
        """Perform basic proof-of-concept validation"""
        poc_results = []
        
        for vuln in vulnerabilities:
            if vuln['type'] == 'DNS_CNAME_TAKEOVER':
                service = vuln['service']
                cname = vuln['cname']
                
                # Check if the service domain is actually available
                try:
                    # Extract the service domain from CNAME
                    service_domain = cname.rstrip('.')
                    
                    # Try to resolve the service domain
                    service_dns = self.resolve_domain(service_domain)
                    
                    if not service_dns['resolved']:
                        poc_results.append({
                            'type': 'POC_DNS_UNRESOLVED',
                            'message': f'Service domain {service_domain} does not resolve',
                            'action': f'You may be able to register this subdomain on {service}',
                            'confidence': 'HIGH'
                        })
                    else:
                        # Check if we get a 404 or similar
                        http_check = self.check_http_response(service_domain)
                        if http_check.get('http', {}).get('status_code') == 404:
                            poc_results.append({
                                'type': 'POC_HTTP_404',
                                'message': f'Service domain {service_domain} returns 404',
                                'action': f'Check if you can claim this subdomain on {service}',
                                'confidence': 'MEDIUM'
                            })
                            
                except Exception as e:
                    if self.verbose:
                        print(self.color.yellow(f"PoC check error for {domain}: {str(e)}"))
                        
        return poc_results
        
    def scan_domain(self, domain):
        """Main scanning function for a single domain"""
        if self.verbose:
            print(self.color.blue(f"[INFO] Scanning {domain}..."))
            
        # Validate domain
        if not validate_domain(domain):
            return {
                'domain': domain,
                'error': 'Invalid domain format',
                'timestamp': datetime.now().isoformat()
            }
            
        start_time = time.time()
        
        try:
            # DNS Resolution
            dns_info = self.resolve_domain(domain)
            
            # HTTP Checks
            http_info = self.check_http_response(domain)
            
            # Vulnerability Detection
            vulnerabilities, confidence = self.check_takeover_signatures(domain, dns_info, http_info)
            
            # PoC Validation if vulnerabilities found
            poc_results = []
            if vulnerabilities:
                poc_results = self.perform_takeover_poc(domain, vulnerabilities)
            
            result = {
                'domain': domain,
                'dns_info': dns_info,
                'http_info': http_info,
                'vulnerabilities': vulnerabilities,
                'poc_results': poc_results,
                'confidence_score': confidence,
                'scan_time': round(time.time() - start_time, 2),
                'timestamp': datetime.now().isoformat()
            }
            
            # Store result
            with self.lock:
                self.results.append(result)
                
            # Print real-time results
            self.print_domain_result(result)
            
            return result
            
        except Exception as e:
            error_result = {
                'domain': domain,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            with self.lock:
                self.results.append(error_result)
                
            print(self.color.red(f"[ERROR] Failed to scan {domain}: {str(e)}"))
            return error_result
            
    def print_domain_result(self, result):
        """Print formatted result for a single domain"""
        domain = result['domain']
        
        if 'error' in result:
            print(self.color.red(f"[ERROR] {domain}: {result['error']}"))
            return
            
        vulnerabilities = result.get('vulnerabilities', [])
        confidence = result.get('confidence_score', 0)
        
        if vulnerabilities:
            if confidence >= 70:
                print(self.color.red(f"[HIGH] {domain} - Confidence: {confidence}%"))
            elif confidence >= 40:
                print(self.color.yellow(f"[MEDIUM] {domain} - Confidence: {confidence}%"))
            else:
                print(self.color.blue(f"[LOW] {domain} - Confidence: {confidence}%"))
                
            for vuln in vulnerabilities:
                print(f"  └─ {vuln['service']}: {vuln['evidence']}")
                
            # Print PoC results
            poc_results = result.get('poc_results', [])
            if poc_results:
                print(self.color.cyan(f"  [PoC] Validation results:"))
                for poc in poc_results:
                    print(f"    └─ {poc['message']}")
                    print(f"       Action: {poc['action']}")
        else:
            if self.verbose:
                print(self.color.green(f"[SAFE] {domain} - No vulnerabilities detected"))
                
    def scan_domains_from_file(self, filepath):
        """Scan domains from a file"""
        if not os.path.exists(filepath):
            print(self.color.red(f"[ERROR] File not found: {filepath}"))
            return
            
        domains = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle URLs by extracting domain
                        domain = extract_domain_from_url(line)
                        if domain:
                            domains.append(domain)
        except Exception as e:
            print(self.color.red(f"[ERROR] Failed to read file {filepath}: {str(e)}"))
            return
            
        if not domains:
            print(self.color.yellow(f"[WARNING] No valid domains found in {filepath}"))
            return
            
        print(self.color.blue(f"[INFO] Found {len(domains)} domains to scan"))
        
        # Scan domains using thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {executor.submit(self.scan_domain, domain): domain for domain in domains}
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    future.result()
                except Exception as exc:
                    print(self.color.red(f"[ERROR] {domain} generated an exception: {exc}"))
                    
    def generate_report(self, output_file=None):
        """Generate detailed report of scan results"""
        if not self.results:
            print(self.color.yellow("[WARNING] No scan results to report"))
            return
            
        vulnerable_domains = [r for r in self.results if r.get('vulnerabilities')]
        
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("SUBTAKEOVER SCAN REPORT")
        report_lines.append("=" * 60)
        report_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Domains Scanned: {len(self.results)}")
        report_lines.append(f"Potentially Vulnerable: {len(vulnerable_domains)}")
        report_lines.append("")
        
        if vulnerable_domains:
            report_lines.append("VULNERABLE DOMAINS:")
            report_lines.append("-" * 40)
            
            for result in sorted(vulnerable_domains, key=lambda x: x.get('confidence_score', 0), reverse=True):
                domain = result['domain']
                confidence = result.get('confidence_score', 0)
                vulnerabilities = result.get('vulnerabilities', [])
                poc_results = result.get('poc_results', [])
                
                report_lines.append(f"\nDomain: {domain}")
                report_lines.append(f"Confidence Score: {confidence}%")
                report_lines.append(f"Scan Time: {result.get('scan_time', 0)}s")
                
                if vulnerabilities:
                    report_lines.append("Vulnerabilities:")
                    for vuln in vulnerabilities:
                        report_lines.append(f"  - Service: {vuln['service']}")
                        report_lines.append(f"    Type: {vuln['type']}")
                        report_lines.append(f"    Evidence: {vuln['evidence']}")
                        report_lines.append(f"    Confidence: {vuln['confidence']}")
                        
                if poc_results:
                    report_lines.append("PoC Results:")
                    for poc in poc_results:
                        report_lines.append(f"  - {poc['message']}")
                        report_lines.append(f"    Action: {poc['action']}")
                        
                # DNS Info
                dns_info = result.get('dns_info', {})
                if dns_info.get('cname_records'):
                    report_lines.append(f"CNAME Records: {', '.join(dns_info['cname_records'])}")
                    
        report_content = "\n".join(report_lines)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                print(self.color.green(f"[SUCCESS] Report saved to {output_file}"))
            except Exception as e:
                print(self.color.red(f"[ERROR] Failed to save report: {str(e)}"))
        else:
            print(report_content)

def main():
    parser = argparse.ArgumentParser(
        description="SubTakeover - Subdomain Takeover Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subtakeover.py -d example.com
  python3 subtakeover.py -f domains.txt
  python3 subtakeover.py -f domains.txt -t 20 -o report.txt
  python3 subtakeover.py -d sub.example.com -v --timeout 15
        """
    )
    
    parser.add_argument('-d', '--domain', help='Single domain to scan')
    parser.add_argument('-f', '--file', help='File containing list of domains')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='HTTP timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner display')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.domain and not args.file:
        parser.error("Must specify either -d/--domain or -f/--file")
        
    if args.domain and args.file:
        parser.error("Cannot specify both -d/--domain and -f/--file")
        
    # Initialize scanner
    scanner = SubTakeoverScanner(
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Display banner
    if not args.no_banner:
        scanner.print_banner()
        
    try:
        # Start scanning
        start_time = time.time()
        
        if args.domain:
            print(scanner.color.blue(f"[INFO] Starting scan for domain: {args.domain}"))
            scanner.scan_domain(args.domain)
        else:
            print(scanner.color.blue(f"[INFO] Starting scan from file: {args.file}"))
            scanner.scan_domains_from_file(args.file)
            
        total_time = round(time.time() - start_time, 2)
        print(scanner.color.green(f"\n[COMPLETE] Scan finished in {total_time}s"))
        
        # Generate report
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print(scanner.color.yellow("\n[INFO] Scan interrupted by user"))
        sys.exit(1)
    except Exception as e:
        print(scanner.color.red(f"[ERROR] Unexpected error: {str(e)}"))
        sys.exit(1)

if __name__ == "__main__":
    main()
