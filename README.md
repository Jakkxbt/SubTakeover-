# SubTakeover - Subdomain Takeover Detection Tool

A powerful command-line tool for detecting potential subdomain takeover vulnerabilities. This tool is designed for cybersecurity researchers and penetration testers to identify misconfigured DNS records that could lead to subdomain takeovers.

## Features

- **Multi-Domain Support**: Scan single domains or batch process from files
- **Comprehensive Detection**: Supports 25+ cloud services and platforms
- **DNS Analysis**: Detailed CNAME and A record resolution
- **HTTP Fingerprinting**: Analyzes HTTP responses for takeover indicators  
- **Proof of Concept**: Basic PoC validation for high-confidence findings
- **Threaded Scanning**: Fast concurrent scanning with configurable thread count
- **Detailed Reporting**: Generate comprehensive reports with actionable insights
- **Color Output**: Easy-to-read colored terminal output
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Supported Services

The tool can detect potential takeover vulnerabilities for:

- GitHub Pages
- Heroku
- Amazon S3
- Shopify
- Fastly
- Ghost
- Pantheon
- Tumblr
- WordPress.com
- Bitbucket
- Squarespace
- Surge.sh
- Zendesk
- UserVoice
- Webflow
- Landingi
- Netlify
- Vercel
- Azure
- Firebase
- ClickFunnels
- Intercom
- Webnode
- Unbounce

## Installation

### Prerequisites

```bash
# Install required Python packages
pip3 install requests dnspython

# For colored output on Windows (optional)
pip3 install colorama
```

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover

# Install dependencies
pip3 install -r deps.txt

# Run the tool
python3 subtakeover.py --help
```

## Usage

### Basic Usage

```bash
# Scan a single domain
python3 subtakeover.py -d subdomain.example.com

# Scan domains from a file
python3 subtakeover.py -f domains.txt

# Scan with verbose output
python3 subtakeover.py -d example.com -v

# Save report to file
python3 subtakeover.py -f domains.txt -o report.txt
```

### Advanced Options

```bash
# Use custom number of threads (default: 10)
python3 subtakeover.py -f domains.txt -t 20

# Custom timeout (default: 10 seconds)
python3 subtakeover.py -d example.com --timeout 15

# Skip banner display
python3 subtakeover.py -d example.com --no-banner

# Full example with all options
python3 subtakeover.py -f domains.txt -t 25 --timeout 20 -o detailed_report.txt -v
```

### Domain File Format

The tool accepts domain lists in text files with the following format:

```
# Comments start with #
subdomain1.example.com
subdomain2.example.com
https://api.example.com
http://old.example.com

# URLs are automatically converted to domains
www.legacy.example.com
```

## How It Works

SubTakeover performs the following checks:

1. **DNS Resolution**: Resolves A and CNAME records for the target domain
2. **Service Detection**: Identifies the cloud service based on CNAME patterns
3. **HTTP Analysis**: Sends HTTP/HTTPS requests to analyze response content
4. **Signature Matching**: Compares responses against known takeover signatures
5. **Proof of Concept**: Validates potential vulnerabilities with additional checks
6. **Risk Assessment**: Calculates confidence scores based on findings

### Confidence Levels

- **HIGH (70-100%)**: Strong indicators of subdomain takeover vulnerability
- **MEDIUM (40-69%)**: Potential vulnerability requiring manual verification
- **LOW (1-39%)**: Weak indicators, likely false positive

## Understanding the Output

### Sample Output

```
[HIGH] blog.vulnerable-site.com - Confidence: 85%
  └─ GitHub Pages: CNAME points to username.github.io but no A record found
  [PoC] Validation results:
    └─ Service domain username.github.io does not resolve
       Action: You may be able to register this subdomain on GitHub Pages
```

### What to Look For

- **CNAME pointing to unregistered services**: High priority findings
- **404 responses with service-specific messages**: Medium priority
- **DNS resolution failures on service domains**: High priority for PoC

## Proof of Concept Validation

The tool automatically performs basic validation:

- Checks if the target service domain resolves
- Attempts HTTP requests to service endpoints
- Provides actionable steps for manual verification

## Supported Platforms

- **Operating Systems**: Linux, macOS, Windows
- **Python Version**: Python 3.6+
- **Network**: Requires internet access for DNS queries and HTTP requests

## Security Considerations

⚠️ **Important**: This tool is for authorized security testing only. Always ensure you have explicit permission to test the target domains.

### Best Practices

1. Only test domains you own or have written permission to test
2. Use reasonable thread counts to avoid overwhelming target servers
3. Respect rate limits and implement delays if scanning large lists
4. Verify findings manually before claiming vulnerabilities
5. Report findings responsibly through proper disclosure channels

## Contributing

Contributions are welcome! Areas for improvement:

- Additional service signatures
- Enhanced PoC validation
- Better reporting formats
- Performance optimizations
- New detection techniques

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before testing any domains.

## Troubleshooting

### Common Issues

**SSL Warnings**: The tool disables SSL verification by default to handle misconfigured certificates. This is expected behavior.

**DNS Resolution Errors**: Some DNS servers may block rapid queries. Try reducing thread count with `-t` option.

**Connection Timeouts**: Increase timeout with `--timeout` option for slow networks.

**Permission Errors**: Ensure you have write permissions when using `-o` output option.

### Kali Linux Installation

For Kali Linux users:

```bash
# Update package lists
sudo apt update

# Install Python and pip if not already installed
sudo apt install python3 python3-pip

# Clone and install
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover
pip3 install -r deps.txt

# Run the tool
python3 subtakeover.py --help
```

## Examples in Action

### Single Domain Scan
```bash
$ python3 subtakeover.py -d test.example.com -v

[INFO] Starting scan for domain: test.example.com
[INFO] Scanning test.example.com...
[HIGH] test.example.com - Confidence: 90%
  └─ GitHub Pages: CNAME points to testuser.github.io but no A record found
```

### Batch Domain Scan
```bash
$ python3 subtakeover.py -f subdomains.txt -t 15 -o results.txt

[INFO] Found 25 domains to scan
[HIGH] api.example.com - Confidence: 85%
[MEDIUM] blog.example.com - Confidence: 60%
[SAFE] www.example.com - No vulnerabilities detected
[SUCCESS] Report saved to results.txt
```
