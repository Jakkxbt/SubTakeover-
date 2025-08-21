# Contributing to SubTakeover

Thank you for your interest in contributing to SubTakeover! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment
- Use the tool only for authorized security testing

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include detailed reproduction steps
4. Provide system information and error messages

### Suggesting Features

1. Check existing feature requests
2. Describe the use case and expected behavior
3. Explain why this feature would benefit users
4. Consider implementation complexity

### Contributing Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes following our coding standards
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/subtakeover.git
cd subtakeover

# Create virtual environment
python3 -m venv dev-env
source dev-env/bin/activate  # On Windows: dev-env\Scripts\activate

# Install dependencies
pip install -r deps.txt

# Run tests
python3 -m pytest tests/  # (when test suite is added)
```

## Coding Standards

### Python Style Guide

Follow PEP 8 with these specific guidelines:

- Use 4 spaces for indentation (no tabs)
- Maximum line length: 88 characters
- Use type hints where appropriate
- Write descriptive docstrings
- Use f-strings for string formatting

### Example Code Style

```python
def scan_domain(self, domain: str) -> Dict[str, Any]:
    """
    Scan a single domain for takeover vulnerabilities.
    
    Args:
        domain: The domain to scan
        
    Returns:
        Dictionary containing scan results
        
    Raises:
        DomainValidationError: If domain format is invalid
    """
    if not validate_domain(domain):
        raise DomainValidationError(f"Invalid domain format: {domain}")
    
    result = {
        'domain': domain,
        'vulnerabilities': [],
        'timestamp': datetime.now().isoformat()
    }
    
    return result
```

### File Structure

```
subtakeover/
├── subtakeover.py          # Main application
├── signatures.py           # Service signatures database
├── utils.py               # Utility functions
├── tests/                 # Test suite (future)
│   ├── test_scanner.py
│   ├── test_signatures.py
│   └── test_utils.py
├── docs/                  # Additional documentation
├── examples/              # Usage examples
└── scripts/               # Helper scripts
```

## Adding New Service Signatures

To add support for a new cloud service:

1. Research the service's subdomain takeover indicators
2. Add the signature to `signatures.py`:

```python
'ServiceName': {
    'cname_patterns': [
        '.service.com',
        'service.com'
    ],
    'content_patterns': [
        'service specific error message',
        'another indicator'
    ],
    'status_codes': [404, 403]
}
```

3. Update the README with the new service
4. Add test cases if possible
5. Update CHANGELOG.md

## Testing Guidelines

### Manual Testing

Before submitting changes:

1. Test with various domain formats
2. Verify thread safety with high thread counts
3. Check error handling with invalid inputs
4. Test on different operating systems if possible

### Test Cases to Cover

- Valid and invalid domain formats
- Network timeout scenarios
- DNS resolution failures
- HTTP request errors
- File input/output operations
- Thread pool behavior

### Future Automated Testing

We plan to add:
- Unit tests for core functions
- Integration tests with mock services
- Performance benchmarks
- Cross-platform compatibility tests

## Documentation

### Code Documentation

- Use clear, descriptive function and variable names
- Add docstrings to all public functions
- Include type hints
- Comment complex logic

### User Documentation

When adding features:
- Update README.md with new options
- Add examples to USAGE.md
- Update help text in argument parser
- Document any breaking changes

## Performance Considerations

### Optimization Guidelines

- Use connection pooling for HTTP requests
- Implement proper timeout handling
- Consider memory usage with large domain lists
- Optimize DNS query efficiency
- Profile code for bottlenecks

### Thread Safety

- Use locks for shared resources
- Avoid race conditions
- Test with high concurrency
- Document thread-safe functions

## Security Considerations

### Responsible Disclosure

- Never include real vulnerable domains in examples
- Avoid detailed exploitation instructions
- Focus on detection, not exploitation
- Include security warnings

### Code Security

- Validate all user inputs
- Sanitize file operations
- Handle network errors gracefully
- Avoid information disclosure in error messages

## Submission Process

### Pull Request Checklist

- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Changes are tested
- [ ] Commit messages are clear
- [ ] No sensitive information is included
- [ ] CHANGELOG.md is updated

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Tested on Linux
- [ ] Tested on macOS
- [ ] Tested on Windows
- [ ] Manual testing performed

## Screenshots/Output
(If applicable)

## Related Issues
Fixes #123
```

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Tag release: `git tag v1.1.0`
4. Push tags: `git push --tags`
5. Create GitHub release
6. Update documentation

## Community

### Getting Help

- Check documentation first
- Search existing issues
- Ask in discussions section
- Join security community channels

### Staying Updated

- Watch the repository for updates
- Follow security research communities
- Monitor subdomain takeover research

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in relevant documentation

## Legal Considerations

### License Agreement

By contributing, you agree that your contributions will be licensed under the MIT License.

### Security Testing Ethics

- Only test domains you own or have permission to test
- Report vulnerabilities responsibly
- Respect rate limits and terms of service
- Follow responsible disclosure practices

---

Thank you for contributing to SubTakeover! Your help makes the security community stronger.
