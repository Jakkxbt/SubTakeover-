"""
Utility functions for SubTakeover tool
"""

import re
import sys
from urllib.parse import urlparse
import socket

class ColorOutput:
    """Handle colored terminal output"""
    
    def __init__(self):
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'end': '\033[0m',
            'bold': '\033[1m'
        }
        
        # Disable colors on Windows if not supported
        if sys.platform == 'win32':
            try:
                import colorama
                colorama.init()
            except ImportError:
                # Disable colors if colorama not available
                self.colors = {key: '' for key in self.colors}
    
    def red(self, text):
        return f"{self.colors['red']}{text}{self.colors['end']}"
    
    def green(self, text):
        return f"{self.colors['green']}{text}{self.colors['end']}"
    
    def yellow(self, text):
        return f"{self.colors['yellow']}{text}{self.colors['end']}"
    
    def blue(self, text):
        return f"{self.colors['blue']}{text}{self.colors['end']}"
    
    def magenta(self, text):
        return f"{self.colors['magenta']}{text}{self.colors['end']}"
    
    def cyan(self, text):
        return f"{self.colors['cyan']}{text}{self.colors['end']}"
    
    def white(self, text):
        return f"{self.colors['white']}{text}{self.colors['end']}"
    
    def bold(self, text):
        return f"{self.colors['bold']}{text}{self.colors['end']}"

def validate_domain(domain):
    """Validate if a string is a valid domain name"""
    if not domain or len(domain) > 253:
        return False
        
    # Remove protocol if present
    domain = domain.lower()
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
        
    # Basic domain regex
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_regex.match(domain))

def extract_domain_from_url(url_or_domain):
    """Extract domain from URL or return domain if already a domain"""
    if not url_or_domain:
        return None
        
    url_or_domain = url_or_domain.strip()
    
    # If it looks like a URL, parse it
    if url_or_domain.startswith(('http://', 'https://')):
        try:
            parsed = urlparse(url_or_domain)
            return parsed.netloc.lower()
        except:
            return None
    
    # Otherwise treat as domain
    domain = url_or_domain.lower()
    
    # Remove common prefixes that might be included
    if domain.startswith('www.'):
        domain = domain[4:]
        
    return domain if validate_domain(domain) else None

def is_ip_address(address):
    """Check if string is an IP address"""
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

def normalize_domain(domain):
    """Normalize domain for consistent comparison"""
    if not domain:
        return None
        
    domain = domain.lower().strip()
    
    # Remove trailing dot
    if domain.endswith('.'):
        domain = domain[:-1]
        
    # Remove protocol
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
        
    # Remove www prefix for normalization
    if domain.startswith('www.'):
        domain = domain[4:]
        
    return domain

def format_confidence(confidence_score):
    """Format confidence score with color"""
    color = ColorOutput()
    
    if confidence_score >= 70:
        return color.red(f"{confidence_score}% (HIGH)")
    elif confidence_score >= 40:
        return color.yellow(f"{confidence_score}% (MEDIUM)")
    else:
        return color.blue(f"{confidence_score}% (LOW)")

def sanitize_filename(filename):
    """Sanitize filename for safe file operations"""
    # Remove dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
        
    return sanitized

def parse_domain_list(text):
    """Parse domain list from text, handling various formats"""
    domains = []
    
    for line in text.split('\n'):
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
            
        # Handle comma-separated domains
        if ',' in line:
            for domain in line.split(','):
                domain = extract_domain_from_url(domain.strip())
                if domain:
                    domains.append(domain)
        else:
            domain = extract_domain_from_url(line)
            if domain:
                domains.append(domain)
                
    return list(set(domains))  # Remove duplicates

def format_bytes(bytes_val):
    """Format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}TB"

def create_progress_bar(current, total, width=50):
    """Create a simple progress bar"""
    if total == 0:
        return "[" + "=" * width + "] 100%"
        
    progress = int(width * current / total)
    bar = "=" * progress + "-" * (width - progress)
    percentage = int(100 * current / total)
    
    return f"[{bar}] {percentage}% ({current}/{total})"

def get_domain_info_summary(domain_result):
    """Generate a summary string for domain scan result"""
    if 'error' in domain_result:
        return f"ERROR: {domain_result['error']}"
        
    vulnerabilities = domain_result.get('vulnerabilities', [])
    if not vulnerabilities:
        return "No vulnerabilities detected"
        
    vuln_count = len(vulnerabilities)
    confidence = domain_result.get('confidence_score', 0)
    
    return f"{vuln_count} vulnerabilities found (Confidence: {confidence}%)"

def validate_file_path(filepath):
    """Validate if file path is accessible and readable"""
    try:
        with open(filepath, 'r') as f:
            # Try to read first line
            f.readline()
        return True
    except IOError:
        return False
    except Exception:
        return False

def get_user_agents():
    """Return list of common user agents for HTTP requests"""
    return [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'SubTakeover Scanner/1.0'
    ]

def rate_limit_delay(delay_seconds=1):
    """Simple rate limiting delay"""
    import time
    time.sleep(delay_seconds)

def safe_json_dump(obj, indent=2):
    """Safely dump object to JSON string"""
    import json
    try:
        return json.dumps(obj, indent=indent, ensure_ascii=False)
    except Exception:
        return str(obj)

def timestamp_to_readable(timestamp_str):
    """Convert ISO timestamp to readable format"""
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return timestamp_str

# Error handling utilities
class SubTakeoverError(Exception):
    """Custom exception for SubTakeover errors"""
    pass

class DomainValidationError(SubTakeoverError):
    """Domain validation specific error"""
    pass

class NetworkError(SubTakeoverError):
    """Network related error"""
    pass

class FileError(SubTakeoverError):
    """File operation error"""
    pass
