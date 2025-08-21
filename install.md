# Installation Guide

This guide provides detailed installation instructions for SubTakeover across different operating systems.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover

# Install dependencies
pip3 install -r deps.txt

# Test installation
python3 subtakeover.py --help
```

## System Requirements

- **Python**: 3.6 or higher
- **Operating System**: Linux, macOS, or Windows
- **Network**: Internet connection for DNS queries and HTTP requests
- **Memory**: Minimum 512MB RAM (more recommended for large domain lists)

## Platform-Specific Instructions

### Kali Linux

```bash
# Update package lists
sudo apt update

# Install Python and pip (if not already installed)
sudo apt install python3 python3-pip git

# Clone the repository
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover

# Install Python dependencies
pip3 install -r deps.txt

# Optional: Create alias for easier access
echo 'alias subtakeover="python3 /path/to/subtakeover/subtakeover.py"' >> ~/.bashrc
source ~/.bashrc
```

### Ubuntu/Debian

```bash
# Install prerequisites
sudo apt update
sudo apt install python3 python3-pip git

# Clone and install
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover
pip3 install -r deps.txt

# Test installation
python3 subtakeover.py --help
```

### CentOS/RHEL/Fedora

```bash
# For CentOS/RHEL
sudo yum install python3 python3-pip git

# For Fedora
sudo dnf install python3 python3-pip git

# Clone and install
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover
pip3 install -r deps.txt
```

### macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python3 git

# Clone and install
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover
pip3 install -r deps.txt
```

### Windows

#### Option 1: Using Git Bash

```bash
# Install Python from https://python.org/downloads/
# Install Git from https://git-scm.com/downloads

# Clone repository
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover

# Install dependencies
pip install -r deps.txt

# Run the tool
python subtakeover.py --help
```

#### Option 2: Using WSL (Windows Subsystem for Linux)

```bash
# Enable WSL and install Ubuntu
wsl --install Ubuntu

# Follow Ubuntu installation steps above
```

## Dependency Details

The tool requires the following Python packages:

- **requests** (≥2.25.1): HTTP client library
- **dnspython** (≥2.1.0): DNS resolution functionality
- **colorama** (≥0.4.4): Cross-platform colored terminal output
- **urllib3** (≥1.26.0): HTTP client utilities and retry logic

## Manual Installation

If you prefer to install dependencies manually:

```bash
pip3 install requests>=2.25.1
pip3 install dnspython>=2.1.0
pip3 install colorama>=0.4.4
pip3 install urllib3>=1.26.0
```

## Virtual Environment Installation

For isolated installation using virtual environments:

```bash
# Create virtual environment
python3 -m venv subtakeover-env

# Activate virtual environment
# On Linux/macOS:
source subtakeover-env/bin/activate

# On Windows:
# subtakeover-env\Scripts\activate

# Clone and install
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover
pip install -r deps.txt

# Run the tool
python subtakeover.py --help
```

## Docker Installation (Optional)

For containerized deployment:

```dockerfile
FROM python:3.9-alpine

WORKDIR /app

COPY deps.txt .
RUN pip install -r deps.txt

COPY . .

ENTRYPOINT ["python", "subtakeover.py"]
```

```bash
# Build and run
docker build -t subtakeover .
docker run -v $(pwd)/results:/app/results subtakeover -d example.com
```

## Post-Installation Verification

After installation, verify everything works:

```bash
# Test basic functionality
python3 subtakeover.py --help

# Test with a safe domain (should show no vulnerabilities)
python3 subtakeover.py -d google.com -v

# Test file input with example file
python3 subtakeover.py -f example_domains.txt -v
```

## Troubleshooting Installation

### Common Issues

**Python not found**:
```bash
# Check Python installation
python3 --version

# If not found, install Python 3.6+
# Use your system's package manager or download from python.org
```

**Permission denied errors**:
```bash
# Try with --user flag
pip3 install --user -r deps.txt

# Or use sudo (not recommended)
sudo pip3 install -r deps.txt
```

**SSL certificate errors**:
```bash
# Upgrade pip and certificates
pip3 install --upgrade pip
pip3 install --upgrade certifi
```

**DNS resolution issues**:
- Check your internet connection
- Verify DNS servers are accessible
- Some corporate networks may block DNS queries

### Performance Optimization

For better performance on large domain lists:

```bash
# Increase thread count (be careful not to overwhelm targets)
python3 subtakeover.py -f large_list.txt -t 25

# Reduce timeout for faster scanning
python3 subtakeover.py -f list.txt --timeout 5

# Use verbose mode to monitor progress
python3 subtakeover.py -f list.txt -v
```

## Uninstallation

To remove SubTakeover:

```bash
# Remove the directory
rm -rf subtakeover

# Remove Python packages (if not used by other tools)
pip3 uninstall requests dnspython colorama urllib3
```

## Getting Help

If you encounter installation issues:

1. Check the troubleshooting section above
2. Verify system requirements are met
3. Check the GitHub issues page
4. Create a new issue with detailed error information

## Security Notes

- The tool makes network requests to target domains
- DNS queries and HTTP requests are logged by network infrastructure
- Use only on domains you own or have permission to test
- Consider using VPN or proxy for sensitive testing scenarios
