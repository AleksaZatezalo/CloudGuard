# AWS Security Scanner

A modular AWS security assessment tool extracted from Prowler, designed with clean architecture and comprehensive CLI interface.

## Features

- **Modular Architecture**: Clean separation of concerns with pluggable security checks
- **Comprehensive Coverage**: Security checks for S3, EC2, IAM, and more AWS services
- **Multiple Auth Methods**: Support for access keys, profiles, IAM roles, and environment variables
- **JSON Output**: Structured JSON reports compatible with OCSF format
- **Parallel Execution**: Fast scanning with concurrent check execution
- **Compliance Frameworks**: Built-in support for CIS, NIST, PCI-DSS, GDPR, and more

## Installation

### From PyPI (Recommended)
```bash
pip install aws-security-scanner
```

### From Source
```bash
git clone https://github.com/example/aws-security-scanner.git
cd aws-security-scanner
pip install -e .
```

## Quick Start

### Using Environment Variables
Set your AWS credentials as environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1

aws-security-scanner
```

### Using CLI Arguments
```bash
aws-security-scanner --access-key YOUR_KEY --secret-key YOUR_SECRET --region us-east-1
```

### Using AWS Profile
```bash
aws-security-scanner --profile production --region us-east-1
```

## Usage Examples

### List Available Checks
```bash
aws-security-scanner --list-checks
```

### Scan Specific Services
```bash
aws-security-scanner --services s3 iam ec2
```

### Run Specific Checks
```bash
aws-security-scanner --checks s3_bucket_public_read iam_user_no_mfa
```

### Custom Output File
```bash
aws-security-scanner --output-file my-security-report.json
```

### Verbose Output
```bash
aws-security-scanner --verbose --pretty-print
```

## Architecture Overview

The tool follows a top-down modular architecture:

```
├── Core Framework (base classes, interfaces)
├── AWS Provider (authentication, service discovery)
├── Check Engine (security rule implementations)
├── Output Engine (JSON formatting, reporting)
└── CLI Interface (command handling, credential management)
```

### Core Components

1. **SecurityCheck**: Abstract base class for implementing security rules
2. **AWSProvider**: Handles AWS authentication and service client management
3. **ScanEngine**: Orchestrates check execution with parallel processing
4. **OutputEngine**: Formats results into structured JSON reports
5. **CheckRegistry**: Manages and organizes available security checks

## Built-in Security Checks

### S3 Security
- `s3_bucket_public_read`: Detects S3 buckets with public read access

### EC2 Security
- `ec2_sg_open_ports`: Finds security groups with unrestricted access

### IAM Security
- `iam_user_no_mfa`: Identifies IAM users without MFA enabled

## Output Format

The tool generates JSON reports with the following structure:

```json
{
  "metadata": {
    "tool": "aws-security-scanner",
    "version": "1.0.0",
    "scan_timestamp": "2025-01-15T10:30:00Z",
    "account_id": "123456789012"
  },
  "summary": {
    "total_findings": 15,
    "by_status": {"PASS": 10, "FAIL": 4, "ERROR": 1},
    "by_severity": {"HIGH": 3, "MEDIUM": 8, "LOW": 4},
    "by_service": {"s3": 5, "ec2": 7, "iam": 3}
  },
  "findings": [...]
}
```

## Extending the Tool

### Adding Custom Checks

Create a new security check by extending the `SecurityCheck` class:

```python
from aws_security_scanner.core import SecurityCheck, Finding

class MyCustomCheck(SecurityCheck):
    def __init__(self):
        super().__init__()
        self.check_id = "my_custom_check"
        self.check_title = "My Custom Security Check"
        self.severity = "HIGH"
        self.compliance_frameworks = ["CIS", "NIST"]
        self.service = "ec2"
    
    def execute(self, aws_provider) -> List[Finding]:
        findings = []
        # Implement your check logic here
        return findings
```

### Registering Custom Checks

```python
from aws_security_scanner.registry import CheckRegistry

registry = CheckRegistry()
registry.register_check(MyCustomCheck())
```

## AWS Permissions

The tool requires the following AWS permissions:

### S3 Checks
- `s3:ListAllMyBuckets`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`

### EC2 Checks
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeRegions`

### IAM Checks
- `iam:ListUsers`
- `iam:GetLoginProfile`
- `iam:ListMFADevices`

### Basic Operations
- `sts:GetCallerIdentity`

## Configuration

### Environment Variables
- `AWS_ACCESS_KEY_ID`: AWS access key
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `AWS_SESSION_TOKEN`: AWS session token (for temporary credentials)
- `AWS_DEFAULT_REGION`: Default AWS region
- `AWS_PROFILE`: AWS profile name

### Config File Support
The tool supports AWS CLI configuration files:
- `~/.aws/credentials`
- `~/.aws/config`

## Development

### Setup Development Environment
```bash
git clone https://github.com/example/aws-security-scanner.git
cd aws-security-scanner
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest
```

### Code Formatting
```bash
black src/ tests/
```

### Type Checking
```bash
mypy src/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Security

This tool is designed to help identify security issues in AWS environments. However:

- Always review findings before taking action
- Test in non-production environments first
- Keep AWS credentials secure
- Follow your organization's security policies

## Support

- Documentation: [GitHub Wiki](https://github.com/example/aws-security-scanner/wiki)
- Issues: [GitHub Issues](https://github.com/example/aws-security-scanner/issues)
- Discussions: [GitHub Discussions](https://github.com/example/aws-security-scanner/discussions)

## Acknowledgments

This tool is inspired by and extracts concepts from the excellent [Prowler](https://github.com/prowler-cloud/prowler) project. We thank the Prowler team for their contributions to cloud security tooling.