# AWS Security Scanner

A tool to scan for AWS security misconfigurations using the AWS CLI and report issues by severity.

## Features

The scanner checks for security misconfigurations across many AWS services, including:

### Critical Severity Issues
- Lack of root MFA
- Presence of root access keys
- S3 buckets publicly readable or writable
- RDS instances publicly accessible
- EBS snapshots publicly restorable
- AWS Config not enabled
- Public AMIs owned by your account

### High Severity Issues
- Multi-Region CloudTrail missing
- SSH/RDP exposed to 0.0.0.0/0
- IAM Access Analyzer disabled
- RDS automatic minor upgrades disabled
- Account not in AWS Organizations
- CloudFront distributions without HTTPS
- ELB/ALB without HTTPS configured
- Lambda functions with public access

### Medium Severity Issues
- IAM access keys not rotated ≤ 90 days
- Weak IAM password policy
- CloudTrail KMS encryption disabled
- IMDSv1 still allowed
- VPC Flow Logs disabled
- S3 encryption disabled
- S3 bucket versioning not enabled
- S3 bucket logging not enabled
- RDS storage not encrypted
- GuardDuty disabled
- ELB/ALB with insecure SSL/TLS policies
- KMS key rotation not enabled
- Lambda functions without VPC configuration
- DynamoDB tables without encryption
- DynamoDB Point-in-Time Recovery disabled
- AWS Shield Advanced not enabled
- EBS encryption by default not enabled

### Low Severity Issues
- Missing resource tags
- CloudTrail log validation disabled
- S3 lifecycle policies missing
- Default security group allows traffic

## Prerequisites

- Python 3.6+
- AWS CLI installed and configured
- AWS credentials with read-only permissions for the services to be scanned

## Setup

1. Make sure the AWS CLI is installed and configured with the account you want to scan:
   ```
   aws configure
   ```

2. Make the script executable:
   ```
   chmod +x aws_security_scanner.py
   ```

## Usage

Simply run the script:

```
./aws_security_scanner.py
```

The script will check each security configuration and:
1. Display issues found in the terminal, grouped by severity
2. Generate a detailed HTML report with findings, including:
   - Finding name and severity
   - Detailed description
   - CLI commands for verification
   - Potential impact
   - Remediation recommendations

The HTML report will automatically open in your default web browser after the scan completes.

## Report Example

The HTML report provides comprehensive information about each finding:

* **Finding details**: Clear description of the issue
* **CLI Command**: AWS CLI commands you can run to verify the finding
* **Impact**: Explanation of the security risks associated with the finding
* **Recommendation**: Specific steps to remediate the issue

## Services Covered

This security scanner checks configurations across these AWS services:
- IAM (Identity and Access Management)
- S3 (Simple Storage Service)
- CloudTrail 
- CloudFront
- EC2 and EBS
- VPC
- RDS (Relational Database Service)
- Lambda
- DynamoDB
- KMS (Key Management Service)
- GuardDuty
- AWS Config
- AWS Organizations
- AWS Shield
- ELB (Elastic Load Balancing)

## Permissions

The script requires read-only permissions to various AWS services. Here's a minimal IAM policy you can use:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "s3:ListAllMyBuckets",
                "s3:GetBucketEncryption",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl",
                "s3:GetBucketTagging",
                "s3:GetBucketLifecycleConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "ec2:DescribeRegions",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "ec2:DescribeImages",
                "ec2:GetEbsEncryptionByDefault",
                "cloudtrail:DescribeTrails",
                "rds:DescribeDBInstances",
                "config:DescribeConfigurationRecorders",
                "organizations:DescribeOrganization",
                "guardduty:ListDetectors",
                "accessanalyzer:ListAnalyzers",
                "lambda:ListFunctions",
                "lambda:GetPolicy",
                "cloudfront:ListDistributions",
                "elb:DescribeLoadBalancers",
                "elb:DescribeLoadBalancerPolicies",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:GetKeyRotationStatus",
                "kms:ListAliases",
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeContinuousBackups",
                "shield:DescribeSubscription",
                "shield:ListProtections"
            ],
            "Resource": "*"
        }
    ]
}
```

## Output

The scan results are grouped by severity level:
- 🔴 Critical issues - Require immediate attention
- 🟠 High issues - Should be addressed soon
- 🟡 Medium issues - Important to address but less urgent
- 🔵 Low issues - Recommended best practices

## Disclaimer

This tool is meant for educational purposes and provides a basic security assessment. It is not a replacement for a comprehensive security audit or continuous security monitoring tools like AWS Security Hub. 
