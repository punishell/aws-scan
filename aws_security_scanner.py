#!/usr/bin/env python3

import json
import subprocess
import sys
import datetime
import os
from datetime import datetime, timezone
import webbrowser
import re
import base64

class AWSSecurityScanner:
    def __init__(self):
        self.issues = []
        self.findings = []
        
    def run_aws_command(self, command):
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True
            )
            if result.returncode != 0:
                print(f"Error executing command: {command}")
                print(f"Error: {result.stderr}")
                return None
            return result.stdout
        except Exception as e:
            print(f"Exception executing command: {command}")
            print(f"Error: {str(e)}")
            return None

    def add_issue(self, message, severity):
        severity_icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵"
        }
        icon = severity_icons.get(severity, "⚠️")
        self.issues.append(f"{icon} [{severity}] {message}")

    def add_finding(self, name, severity, description, cli_command, impact, recommendation):
        self.findings.append({
            "name": name,
            "severity": severity,
            "description": description,
            "cli_command": cli_command,
            "impact": impact,
            "recommendation": recommendation
        })
        
        # Also add to issues list for backwards compatibility
        self.add_issue(name, severity)

    def check_root_mfa(self):
        print("Checking root account MFA status...")
        command = "aws iam get-account-summary"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to check root account MFA status", "Unknown")
            return
        
        data = json.loads(response)
        if data.get("SummaryMap", {}).get("AccountMFAEnabled", 0) != 1:
            self.add_finding(
                name="[IAM] Lack of root MFA",
                severity="Critical",
                description="The AWS root account does not have Multi-Factor Authentication (MFA) enabled, which significantly increases the risk of unauthorized access.",
                cli_command=command,
                impact="If root account credentials are compromised, an attacker would have full access to your AWS account without the additional protection of MFA.",
                recommendation="Enable MFA for the root account immediately. Go to the AWS Management Console, navigate to IAM, select 'Security credentials', and set up MFA using a virtual or hardware token."
            )
        else:
            print("✅ Root account has MFA enabled")

    def check_root_access_keys(self):
        print("Checking for root access keys...")
        command = "aws iam list-access-keys --user-name root"
        response = self.run_aws_command(command)
        
        if "cannot be found" in str(response) or not response:
            print("✅ No root access keys found (good)")
            return
            
        try:
            keys = json.loads(response)
            if keys.get("AccessKeyMetadata", []):
                self.add_finding(
                    name="[IAM] Presence of root access keys",
                    severity="Critical",
                    description="The AWS root account has active access keys, which is against AWS security best practices.",
                    cli_command=command,
                    impact="Root access keys, if compromised, provide full programmatic access to your AWS account without requiring additional authentication.",
                    recommendation="Delete all root account access keys immediately. AWS best practice is to never use root access keys. Instead, create individual IAM users with appropriate permissions for programmatic access."
                )
            else:
                print("✅ No root access keys found (good)")
        except:
            print("✅ No root access keys found (good)")

    def check_password_policy(self):
        print("Checking IAM password policy...")
        command = "aws iam get-account-password-policy"
        response = self.run_aws_command(command)
        if not response:
            self.add_finding(
                name="[IAM] No password policy configured",
                severity="Medium",
                description="No IAM password policy is configured for the AWS account, meaning default minimum password requirements are in effect.",
                cli_command=command,
                impact="Without a strong password policy, users may create weak passwords that are easily guessed or brute-forced, increasing the risk of unauthorized access.",
                recommendation="Configure a strong IAM password policy with minimum length of 14 characters, requiring uppercase, lowercase, numbers and special characters, and enforcing password rotation."
            )
            return
        
        policy = json.loads(response).get("PasswordPolicy", {})
        
        policy_issues = []
        if not policy.get("RequireUppercaseCharacters", False):
            policy_issues.append("No uppercase characters required")
        if not policy.get("RequireLowercaseCharacters", False):
            policy_issues.append("No lowercase characters required")
        if not policy.get("RequireSymbols", False):
            policy_issues.append("No symbols required")
        if not policy.get("RequireNumbers", False):
            policy_issues.append("No numbers required")
        if policy.get("MinimumPasswordLength", 0) < 14:
            policy_issues.append(f"Minimum length less than 14 (current: {policy.get('MinimumPasswordLength', 0)})")
        if policy.get("MaxPasswordAge", 0) <= 0 or policy.get("MaxPasswordAge", 0) > 90:
            policy_issues.append("Password expiration not set or exceeds 90 days")
        if policy.get("PasswordReusePrevention", 0) < 24:
            policy_issues.append(f"Password reuse prevention less than 24 (current: {policy.get('PasswordReusePrevention', 0) or 'not set'})")
        
        if policy_issues:
            self.add_finding(
                name="[IAM] Weak password policy",
                severity="Medium",
                description=f"The current IAM password policy has the following weaknesses: {', '.join(policy_issues)}",
                cli_command=command,
                impact="Weak password policies increase the risk of credential compromise through brute force attacks, password guessing, or credential reuse.",
                recommendation="Strengthen the IAM password policy by requiring a minimum length of 14 characters, uppercase and lowercase letters, numbers, symbols, maximum age of 90 days, and prevention of password reuse."
            )
        else:
            print("✅ Password policy is properly configured")

    def check_aws_config(self):
        print("Checking AWS Config status...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        
        unconfigured_regions = []
        for region in regions:
            config_command = f"aws configservice describe-configuration-recorders --region {region}"
            response = self.run_aws_command(config_command)
            if not response or response.strip() == "{}":
                unconfigured_regions.append(region)
        
        if unconfigured_regions:
            if len(unconfigured_regions) == len(regions):
                self.add_finding(
                    name="[CONFIG] AWS Config not enabled",
                    severity="Critical",
                    description="AWS Config is not enabled in any region. AWS Config is essential for resource inventory, configuration history, and compliance monitoring.",
                    cli_command=f"# Check AWS Config status across regions\n{command}\n\n# For each region:\naws configservice describe-configuration-recorders --region REGION_NAME",
                    impact="Without AWS Config, you lack visibility into resource configuration changes, configuration compliance, and security posture. This makes it difficult to track changes, audit resources, and ensure compliance with policies and standards.",
                    recommendation="1. Enable AWS Config in all regions where you have resources\n2. Configure AWS Config to record all resource types\n3. Set up a central S3 bucket for AWS Config data\n4. Implement AWS Config Rules to automatically evaluate resource compliance\n5. Integrate with AWS Security Hub for comprehensive security monitoring"
                )
            else:
                regions_list = ", ".join(unconfigured_regions[:5])
                self.add_finding(
                    name="[CONFIG] AWS Config not enabled in all regions",
                    severity="Critical",
                    description=f"AWS Config is not enabled in the following regions: {regions_list}" + (", and more..." if len(unconfigured_regions) > 5 else ""),
                    cli_command=f"# Check AWS Config status across regions\n{command}\n\n# For each region:\naws configservice describe-configuration-recorders --region REGION_NAME",
                    impact="Inconsistent AWS Config deployment creates visibility gaps in your infrastructure, making it difficult to ensure comprehensive security monitoring and compliance across all regions where you operate.",
                    recommendation="1. Enable AWS Config in all regions where you have resources\n2. Implement multi-account AWS Config aggregation\n3. Use AWS Organizations and CloudFormation StackSets to ensure consistent AWS Config deployment\n4. Set up centralized monitoring of AWS Config findings"
                )
        else:
            print("✅ AWS Config is enabled in all regions")

    def check_aws_organizations(self):
        print("Checking AWS Organizations status...")
        command = "aws organizations describe-organization"
        response = self.run_aws_command(command)
        
        if not response or "organization" not in response.lower():
            self.add_finding(
                name="[ORGANIZATION] Account not in AWS Organizations",
                severity="High",
                description="This AWS account is not part of AWS Organizations, which helps centrally manage and govern multiple AWS accounts.",
                cli_command=command,
                impact="Without AWS Organizations, you miss out on centralized account management, consolidated billing, hierarchical organization of accounts, and service control policies that can enforce security guardrails across accounts.",
                recommendation="1. Set up AWS Organizations to manage your AWS accounts centrally\n2. Implement service control policies (SCPs) for security guardrails\n3. Use Organizations features like consolidated billing and account hierarchy\n4. Consider integrating with AWS Control Tower for additional governance"
            )
        else:
            print("✅ Account is part of AWS Organizations")

    def check_s3_encryption(self):
        print("Checking S3 bucket encryption...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        unencrypted_buckets = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            encryption_command = f"aws s3api get-bucket-encryption --bucket {bucket_name}"
            encryption_response = self.run_aws_command(f"{encryption_command} 2>&1")
            if not encryption_response or "ServerSideEncryptionConfiguration" not in encryption_response:
                unencrypted_buckets.append(bucket_name)
        
        if unencrypted_buckets:
            buckets_list = ", ".join(unencrypted_buckets[:5])
            self.add_finding(
                name="[S3] Bucket encryption disabled",
                severity="Medium",
                description=f"The following S3 buckets do not have default encryption enabled: {buckets_list}" + (", and more..." if len(unencrypted_buckets) > 5 else ""),
                cli_command=f"# List all buckets\n{command}\n\n# Check bucket encryption\naws s3api get-bucket-encryption --bucket BUCKET_NAME",
                impact="Unencrypted S3 buckets could lead to data exposure if unauthorized access occurs. Encryption at rest is a security best practice and may be required for compliance with regulations like GDPR, HIPAA, or PCI-DSS.",
                recommendation="1. Enable default encryption for all S3 buckets using either SSE-S3 or SSE-KMS\n2. Consider using AWS KMS customer managed keys for stronger control\n3. Implement a bucket policy that requires encrypted uploads\n4. Use AWS Config rules to monitor and enforce encryption"
            )
        else:
            print(f"✅ All {len(buckets)} S3 buckets have encryption enabled")

    def check_s3_public_access(self):
        print("Checking S3 bucket public access...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        public_buckets = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            policy_command = f"aws s3api get-bucket-policy-status --bucket {bucket_name}"
            policy_response = self.run_aws_command(f"{policy_command} 2>&1")
            
            if policy_response and "PolicyStatus" in policy_response:
                policy_status = json.loads(policy_response)
                if policy_status.get("PolicyStatus", {}).get("IsPublic", False):
                    public_buckets.append(bucket_name)
            
            # Also check ACLs
            acl_command = f"aws s3api get-bucket-acl --bucket {bucket_name}"
            acl_response = self.run_aws_command(f"{acl_command}")
            if acl_response:
                try:
                    acl = json.loads(acl_response)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers" and grant.get("Permission") in ["READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"]:
                            if bucket_name not in public_buckets:
                                public_buckets.append(bucket_name)
                except:
                    pass
        
        if public_buckets:
            buckets_list = ", ".join(public_buckets)
            self.add_finding(
                name="[S3] Buckets publicly readable or writable",
                severity="Critical",
                description=f"The following S3 buckets are configured with public read or write access: {buckets_list}",
                cli_command=f"# List all buckets\n{command}\n\n# Check bucket policy status\naws s3api get-bucket-policy-status --bucket BUCKET_NAME\n\n# Check bucket ACL\naws s3api get-bucket-acl --bucket BUCKET_NAME",
                impact="Public S3 buckets can expose sensitive data to the internet, potentially resulting in data leaks, unauthorized access, or modification of your data. This can lead to compliance violations and security breaches.",
                recommendation="Remove public access from these buckets by:\n1. Enable S3 Block Public Access at the account level\n2. Review and update bucket policies to remove public access\n3. Set bucket ACLs to private\n4. Use AWS IAM roles and policies for controlled access instead of public permissions"
            )
        else:
            print(f"✅ No public S3 buckets found among {len(buckets)} buckets")

    def check_s3_lifecycle(self):
        print("Checking S3 bucket lifecycle policies...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        no_lifecycle_buckets = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            lifecycle_command = f"aws s3api get-bucket-lifecycle-configuration --bucket {bucket_name}"
            lifecycle_response = self.run_aws_command(f"{lifecycle_command} 2>&1")
            if not lifecycle_response or "Rules" not in lifecycle_response:
                no_lifecycle_buckets.append(bucket_name)
        
        if no_lifecycle_buckets:
            buckets_list = ", ".join(no_lifecycle_buckets[:5])
            self.add_finding(
                name="[S3] Bucket lifecycle policies missing",
                severity="Low",
                description=f"The following S3 buckets do not have lifecycle policies configured: {buckets_list}" + (", and more..." if len(no_lifecycle_buckets) > 5 else ""),
                cli_command=f"# List all buckets\n{command}\n\n# Check bucket lifecycle configuration\n{lifecycle_command}",
                impact="Without lifecycle policies, objects may be stored indefinitely, increasing storage costs and potentially violating data retention requirements. This can also impact performance and data management efficiency.",
                recommendation="1. Implement S3 lifecycle policies to automate transitions between storage classes\n2. Configure rules to expire or archive old objects based on your retention requirements\n3. Consider transitioning infrequently accessed data to lower-cost storage tiers\n4. Align lifecycle policies with your organization's data retention policies"
            )
        else:
            print(f"✅ All {len(buckets)} S3 buckets have lifecycle policies")

    def check_s3_versioning(self):
        print("Checking S3 bucket versioning...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        no_versioning_buckets = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            versioning_command = f"aws s3api get-bucket-versioning --bucket {bucket_name}"
            versioning_response = self.run_aws_command(versioning_command)
            
            if not versioning_response or "Status" not in versioning_response or "Enabled" not in versioning_response:
                no_versioning_buckets.append(bucket_name)
        
        if no_versioning_buckets:
            buckets_list = ", ".join(no_versioning_buckets[:5])
            self.add_finding(
                name="[S3] Bucket versioning not enabled",
                severity="Medium",
                description=f"The following S3 buckets do not have versioning enabled: {buckets_list}" + (", and more..." if len(no_versioning_buckets) > 5 else ""),
                cli_command=f"# List all buckets\n{command}\n\n# Check bucket versioning\n{versioning_command}",
                impact="Without versioning, accidental deletions or overwrites cannot be easily recovered. This increases the risk of data loss and makes it difficult to recover from unintended changes or malicious actions.",
                recommendation="1. Enable versioning on all important S3 buckets\n2. Implement lifecycle policies to manage the cost of storing multiple versions\n3. Consider using S3 Object Lock for critical data that requires immutability\n4. Set up notifications for delete operations on critical buckets"
            )
        else:
            print(f"✅ All {len(buckets)} S3 buckets have versioning enabled")

    def check_s3_logging(self):
        print("Checking S3 bucket logging...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        no_logging_buckets = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            logging_command = f"aws s3api get-bucket-logging --bucket {bucket_name}"
            logging_response = self.run_aws_command(logging_command)
            
            if not logging_response or "LoggingEnabled" not in logging_response:
                no_logging_buckets.append(bucket_name)
        
        if no_logging_buckets:
            buckets_list = ", ".join(no_logging_buckets[:5])
            self.add_finding(
                name="[S3] Bucket logging not enabled",
                severity="Medium",
                description=f"The following S3 buckets do not have access logging enabled: {buckets_list}" + (", and more..." if len(no_logging_buckets) > 5 else ""),
                cli_command=f"# List all buckets\n{command}\n\n# Check bucket logging\n{logging_command}",
                impact="Without access logging, you cannot track who accessed your S3 buckets, what actions were performed, or investigate potential security incidents. This hinders security monitoring and forensic capabilities.",
                recommendation="1. Enable server access logging for all important S3 buckets\n2. Configure a dedicated logging bucket with appropriate access controls\n3. Analyze logs regularly for unauthorized access attempts\n4. Consider integrating with AWS CloudTrail for more comprehensive logging"
            )
        else:
            print(f"✅ All {len(buckets)} S3 buckets have logging enabled")

    def check_access_keys(self):
        print("Checking IAM access keys rotation...")
        command = "aws iam list-users"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM users", "Unknown")
            return
        
        users = json.loads(response).get("Users", [])
        old_keys = []
        
        for user in users:
            username = user["UserName"]
            keys_command = f"aws iam list-access-keys --user-name {username}"
            keys_response = self.run_aws_command(keys_command)
            
            if keys_response:
                keys = json.loads(keys_response).get("AccessKeyMetadata", [])
                for key in keys:
                    create_date = key["CreateDate"]
                    if isinstance(create_date, str):
                        create_date = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                    
                    age_days = (datetime.now(timezone.utc) - create_date).days
                    
                    if age_days > 90:
                        old_keys.append(f"{username} ({age_days} days)")
        
        if old_keys:
            keys_list = ", ".join(old_keys[:5])
            self.add_finding(
                name="[IAM] Access keys not rotated ≤ 90 days",
                severity="Medium",
                description=f"The following IAM users have access keys older than 90 days: {keys_list}" + (", and more..." if len(old_keys) > 5 else ""),
                cli_command=f"# List IAM users\n{command}\n\n# Check access keys for a user\n{keys_command}",
                impact="Long-lived access keys increase the risk of credential compromise. If a key is leaked or stolen, it could be used for unauthorized access until it is deactivated.",
                recommendation="1. Implement a 90-day key rotation policy\n2. Create a process for seamless key rotation without service disruption\n3. Use AWS IAM Access Analyzer to monitor for unused keys\n4. Consider using temporary credentials via AWS STS instead of long-term access keys"
            )
        else:
            print("✅ All access keys are rotated regularly")

    def check_cloudtrail(self):
        print("Checking CloudTrail logging status...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        cloudtrail_disabled_regions = []
        multi_region_trails = []
        
        for region in regions:
            trail_command = f"aws cloudtrail describe-trails --region {region}"
            response = self.run_aws_command(trail_command)
            
            if response:
                trails = json.loads(response).get("trailList", [])
                for trail in trails:
                    if trail.get("IsMultiRegionTrail", False):
                        multi_region_trails.append(trail.get("Name"))
                
                if not trails:
                    cloudtrail_disabled_regions.append(region)
        
        if not multi_region_trails:
            self.add_finding(
                name="[CLOUDTRAIL] Multi-Region trail missing",
                severity="High",
                description="No multi-region CloudTrail trails were found. Multi-region trails are essential for comprehensive logging across your AWS infrastructure.",
                cli_command=f"# Check CloudTrail status across regions\n{command}\n\n# For each region:\n{trail_command}",
                impact="Without multi-region CloudTrail, you lack visibility into API activities across all regions, creating blind spots in your security monitoring and audit capabilities.",
                recommendation="1. Create a multi-region CloudTrail that logs events from all regions\n2. Ensure the trail is configured to log management events, data events, and insights events as needed\n3. Configure CloudTrail to deliver logs to a secure, centralized S3 bucket\n4. Enable log file validation and encryption for your CloudTrail logs"
            )
        
        if cloudtrail_disabled_regions:
            regions_list = ", ".join(cloudtrail_disabled_regions[:5])
            self.add_finding(
                name="[CLOUDTRAIL] Not enabled in all regions",
                severity="High",
                description=f"CloudTrail is not enabled in the following regions: {regions_list}" + (", and more..." if len(cloudtrail_disabled_regions) > 5 else ""),
                cli_command=f"# Check CloudTrail status across regions\n{command}\n\n# For each region:\n{trail_command}",
                impact="Regions without CloudTrail logging create security blind spots that could allow unauthorized activity to go undetected.",
                recommendation="1. Enable CloudTrail in all regions where you have or might have resources\n2. Consider using a multi-region trail to simplify management\n3. Ensure logs are delivered to a centralized, secure location\n4. Set up alerting for CloudTrail configuration changes"
            )
        else:
            print("✅ CloudTrail is enabled in all regions")
        
        # Check CloudTrail KMS encryption
        for region in regions:
            trail_command = f"aws cloudtrail describe-trails --region {region}"
            response = self.run_aws_command(trail_command)
            if response:
                trails = json.loads(response).get("trailList", [])
                for trail in trails:
                    trail_name = trail.get("Name")
                    if not trail.get("KmsKeyId"):
                        self.add_finding(
                            name="[CLOUDTRAIL] KMS encryption disabled",
                            severity="Medium",
                            description=f"CloudTrail trail '{trail_name}' in region {region} is not encrypted with KMS.",
                            cli_command=f"# Check trail encryption\n{trail_command}",
                            impact="Unencrypted CloudTrail logs could potentially be accessed or modified if the S3 bucket permissions are compromised, reducing the reliability of your audit logs.",
                            recommendation="1. Configure KMS encryption for all CloudTrail trails\n2. Use a customer managed KMS key with appropriate key policies\n3. Ensure the CloudTrail service has permission to use the KMS key\n4. Monitor for any changes to the encryption settings"
                        )
        
        # Check log validation
        for region in regions:
            trail_command = f"aws cloudtrail describe-trails --region {region}"
            response = self.run_aws_command(trail_command)
            if response:
                trails = json.loads(response).get("trailList", [])
                for trail in trails:
                    trail_name = trail.get("Name")
                    if not trail.get("LogFileValidationEnabled", False):
                        self.add_finding(
                            name="[CLOUDTRAIL] Log validation disabled",
                            severity="Low",
                            description=f"CloudTrail log file validation is not enabled for trail '{trail_name}' in region {region}.",
                            cli_command=f"# Check log validation status\n{trail_command}",
                            impact="Without log file validation, you cannot verify if CloudTrail log files have been tampered with, reducing the reliability of audit logs for forensic purposes.",
                            recommendation="1. Enable log file validation for all CloudTrail trails\n2. Regularly validate log file integrity using the AWS CLI\n3. Consider implementing additional security controls for CloudTrail logs\n4. Set up alerts for any changes to the log validation settings"
                        )

    def check_iam_access_analyzer(self):
        print("Checking IAM Access Analyzer status...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        access_analyzer_disabled_regions = []
        
        for region in regions:
            analyzer_command = f"aws accessanalyzer list-analyzers --region {region}"
            response = self.run_aws_command(analyzer_command)
            
            if not response or "analyzers" not in response or json.loads(response).get("analyzers", []) == []:
                access_analyzer_disabled_regions.append(region)
        
        if access_analyzer_disabled_regions:
            regions_list = ", ".join(access_analyzer_disabled_regions[:5])
            self.add_finding(
                name="[IAM] Access Analyzer disabled",
                severity="High",
                description=f"IAM Access Analyzer is not enabled in the following regions: {regions_list}" + (", and more..." if len(access_analyzer_disabled_regions) > 5 else ""),
                cli_command=f"# Check IAM Access Analyzer status\n{analyzer_command}",
                impact="Without IAM Access Analyzer, you may have resources with policies that grant unintended public or cross-account access, increasing the risk of unauthorized access to your resources.",
                recommendation="1. Enable IAM Access Analyzer in all regions where you operate\n2. Regularly review findings and remediate issues\n3. Set up notifications for new analyzer findings\n4. Integrate with AWS Security Hub for centralized finding management"
            )
        else:
            print("✅ IAM Access Analyzer is enabled in all regions")

    def check_guardduty(self):
        print("Checking GuardDuty status...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        guardduty_disabled_regions = []
        
        for region in regions:
            guardduty_command = f"aws guardduty list-detectors --region {region}"
            response = self.run_aws_command(guardduty_command)
            
            if not response or "detectorIds" not in response or json.loads(response).get("detectorIds", []) == []:
                guardduty_disabled_regions.append(region)
        
        if guardduty_disabled_regions:
            regions_list = ", ".join(guardduty_disabled_regions[:5])
            self.add_finding(
                name="[GUARDDUTY] Service disabled",
                severity="Medium",
                description=f"Amazon GuardDuty is not enabled in the following regions: {regions_list}" + (", and more..." if len(guardduty_disabled_regions) > 5 else ""),
                cli_command=f"# Check GuardDuty status across regions\n{command}\n\n# For each region:\n{guardduty_command}",
                impact="Without GuardDuty, you lack automated threat detection capabilities that can identify unexpected and potentially unauthorized or malicious activity in your AWS accounts.",
                recommendation="1. Enable GuardDuty in all regions where you have resources\n2. Configure GuardDuty findings to be sent to a SIEM or incident management system\n3. Set up automated remediation for common findings\n4. Consider using GuardDuty master/member setup for multi-account environments"
            )
        else:
            print("✅ GuardDuty is enabled in all regions")

    def check_vpc_flow_logs(self):
        print("Checking VPC Flow Logs...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        vpcs_without_flow_logs = []
        
        for region in regions:
            vpc_command = f"aws ec2 describe-vpcs --region {region}"
            vpc_response = self.run_aws_command(vpc_command)
            
            if vpc_response:
                vpcs = json.loads(vpc_response).get("Vpcs", [])
                
                for vpc in vpcs:
                    vpc_id = vpc["VpcId"]
                    flow_logs_command = f"aws ec2 describe-flow-logs --filter Name=resource-id,Values={vpc_id} --region {region}"
                    flow_logs_response = self.run_aws_command(flow_logs_command)
                    
                    if not flow_logs_response or json.loads(flow_logs_response).get("FlowLogs", []) == []:
                        vpcs_without_flow_logs.append(f"{vpc_id} ({region})")
        
        if vpcs_without_flow_logs:
            vpcs_list = ", ".join(vpcs_without_flow_logs[:5])
            self.add_finding(
                name="[VPC] Flow Logs disabled",
                severity="Medium",
                description=f"The following VPCs do not have Flow Logs enabled: {vpcs_list}" + (", and more..." if len(vpcs_without_flow_logs) > 5 else ""),
                cli_command=f"# List VPCs in a region\n{vpc_command}\n\n# Check Flow Logs for a VPC\n{flow_logs_command}",
                impact="Without VPC Flow Logs, you lack visibility into network traffic patterns, making it difficult to monitor for security issues, troubleshoot connectivity problems, or perform network forensics after a security incident.",
                recommendation="1. Enable Flow Logs for all VPCs\n2. Configure logs to be delivered to CloudWatch Logs or S3\n3. Set up log retention policies\n4. Consider using Amazon Athena or other analytics tools to analyze VPC Flow Logs"
            )
        else:
            print("✅ VPC Flow Logs are enabled for all VPCs")

    def check_imdsv1(self):
        print("Checking for IMDSv1...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        instances_with_imdsv1 = []
        
        for region in regions:
            instances_command = f"aws ec2 describe-instances --region {region}"
            instances_response = self.run_aws_command(instances_command)
            
            if instances_response:
                reservations = json.loads(instances_response).get("Reservations", [])
                
                for reservation in reservations:
                    for instance in reservation.get("Instances", []):
                        instance_id = instance["InstanceId"]
                        metadata_options = instance.get("MetadataOptions", {})
                        
                        if metadata_options.get("HttpTokens", "") == "optional":
                            instances_with_imdsv1.append(f"{instance_id} ({region})")
        
        if instances_with_imdsv1:
            instances_list = ", ".join(instances_with_imdsv1[:5])
            self.add_finding(
                name="[EC2] IMDSv1 still allowed",
                severity="Medium",
                description=f"The following EC2 instances still allow IMDSv1 (metadata service without session tokens): {instances_list}" + (", and more..." if len(instances_with_imdsv1) > 5 else ""),
                cli_command=f"# Check instance metadata options\n{instances_command} | grep -A 10 MetadataOptions",
                impact="IMDSv1 is vulnerable to Server Side Request Forgery (SSRF) attacks that could allow an attacker to access instance metadata, including IAM credentials, from a vulnerable application running on the instance.",
                recommendation="1. Enforce IMDSv2 by setting HttpTokens to 'required' on all instances\n2. Use the ModifyInstanceMetadataOptions API to update existing instances\n3. Configure AMIs and launch templates to use IMDSv2 by default\n4. Create an SCP or IAM policy that requires IMDSv2 for launching new instances"
            )
        else:
            print("✅ IMDSv2 is enforced on all instances")

    def check_rds_instances(self):
        print("Checking RDS instances...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        public_rds_instances = []
        unencrypted_rds_instances = []
        auto_upgrade_disabled_instances = []
        
        for region in regions:
            rds_command = f"aws rds describe-db-instances --region {region}"
            rds_response = self.run_aws_command(rds_command)
            
            if rds_response:
                instances = json.loads(rds_response).get("DBInstances", [])
                
                for instance in instances:
                    instance_id = instance["DBInstanceIdentifier"]
                    
                    # Check public accessibility
                    if instance.get("PubliclyAccessible", False):
                        public_rds_instances.append(f"{instance_id} ({region})")
                    
                    # Check encryption
                    if not instance.get("StorageEncrypted", False):
                        unencrypted_rds_instances.append(f"{instance_id} ({region})")
                    
                    # Check automatic minor upgrades
                    if not instance.get("AutoMinorVersionUpgrade", False):
                        auto_upgrade_disabled_instances.append(f"{instance_id} ({region})")
        
        if public_rds_instances:
            instances_list = ", ".join(public_rds_instances[:5])
            self.add_finding(
                name="[RDS] Instances publicly accessible",
                severity="Critical",
                description=f"The following RDS database instances are publicly accessible: {instances_list}" + (", and more..." if len(public_rds_instances) > 5 else ""),
                cli_command=f"# List RDS instances in a region\n{rds_command}\n\n# Check if a specific instance is publicly accessible\naws rds describe-db-instances --db-instance-identifier INSTANCE_ID --region REGION_NAME | grep PubliclyAccessible",
                impact="Publicly accessible databases are exposed to the internet, significantly increasing the risk of unauthorized access, data breaches, and potential exploitation of database vulnerabilities.",
                recommendation="1. Modify the RDS instances to disable public accessibility\n2. Use AWS PrivateLink or VPC peering for secure database access\n3. Implement proper security groups that restrict access to specific IP ranges\n4. Consider using an application-tier proxy or bastion host for database access"
            )
        else:
            print("✅ No publicly accessible RDS instances")
        
        if unencrypted_rds_instances:
            instances_list = ", ".join(unencrypted_rds_instances[:5])
            self.add_finding(
                name="[RDS] Storage not encrypted",
                severity="Medium",
                description=f"The following RDS database instances do not have storage encryption enabled: {instances_list}" + (", and more..." if len(unencrypted_rds_instances) > 5 else ""),
                cli_command=f"# Check encryption status of RDS instances\n{rds_command} | grep StorageEncrypted",
                impact="Unencrypted database storage could potentially expose sensitive data if storage media is compromised, discarded, or improperly decommissioned. This may also violate compliance requirements like GDPR, HIPAA, or PCI-DSS.",
                recommendation="1. For existing unencrypted instances, create encrypted snapshots and restore to new encrypted instances\n2. Enable encryption by default for all new RDS instances\n3. Use AWS KMS for managing encryption keys\n4. Consider database-level encryption for sensitive data columns"
            )
        
        if auto_upgrade_disabled_instances:
            instances_list = ", ".join(auto_upgrade_disabled_instances[:5])
            self.add_finding(
                name="[RDS] Automatic minor upgrades disabled",
                severity="High",
                description=f"The following RDS instances have automatic minor version upgrades disabled: {instances_list}" + (", and more..." if len(auto_upgrade_disabled_instances) > 5 else ""),
                cli_command=f"# Check automatic minor upgrade setting\n{rds_command} | grep AutoMinorVersionUpgrade",
                impact="Disabling automatic minor version upgrades can leave databases vulnerable to known security issues that are fixed in patch releases. This increases the risk of exploitation and service disruption.",
                recommendation="1. Enable automatic minor version upgrades for all RDS instances\n2. Establish a regular maintenance window for upgrades\n3. Implement a database patching policy to ensure security updates are applied promptly\n4. Monitor AWS security bulletins for critical database vulnerabilities"
            )

    def check_ebs_snapshots(self):
        print("Checking EBS snapshots...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        public_snapshots = []
        
        for region in regions:
            snapshots_command = f"aws ec2 describe-snapshots --owner-ids self --region {region}"
            snapshots_response = self.run_aws_command(snapshots_command)
            
            if snapshots_response:
                snapshots = json.loads(snapshots_response).get("Snapshots", [])
                
                for snapshot in snapshots:
                    snapshot_id = snapshot["SnapshotId"]
                    
                    # Check if snapshot is public
                    perms_command = f"aws ec2 describe-snapshot-attribute --snapshot-id {snapshot_id} --attribute createVolumePermission --region {region}"
                    perms_response = self.run_aws_command(perms_command)
                    
                    if perms_response:
                        perms = json.loads(perms_response)
                        for permission in perms.get("CreateVolumePermissions", []):
                            if permission.get("Group") == "all":
                                public_snapshots.append(f"{snapshot_id} ({region})")
                                break
        
        if public_snapshots:
            snapshots_list = ", ".join(public_snapshots[:5])
            self.add_finding(
                name="[EBS] Snapshots publicly restorable",
                severity="Critical",
                description=f"The following EBS snapshots are publicly restorable: {snapshots_list}" + (", and more..." if len(public_snapshots) > 5 else ""),
                cli_command=f"# List your snapshots\n{snapshots_command}\n\n# Check snapshot permissions\n{perms_command}",
                impact="Publicly accessible EBS snapshots could expose sensitive data to anyone on the internet. Attackers can create volumes from these snapshots and access all the data they contain.",
                recommendation="1. Remove public access permissions from all EBS snapshots\n2. Audit all snapshots regularly for unintended public access\n3. Implement a snapshot management policy that includes access control\n4. Use AWS Config rules to monitor for and prevent public snapshots"
            )
        else:
            print("✅ No publicly restorable EBS snapshots")

    def check_resource_tags(self):
        print("Checking for missing resource tags...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        untagged_resources_count = 0
        resources_checked = 0
        
        # Check EC2 instances
        for region in regions:
            instances_command = f"aws ec2 describe-instances --region {region}"
            instances_response = self.run_aws_command(instances_command)
            
            if instances_response:
                reservations = json.loads(instances_response).get("Reservations", [])
                
                for reservation in reservations:
                    for instance in reservation.get("Instances", []):
                        resources_checked += 1
                        if not instance.get("Tags"):
                            untagged_resources_count += 1
        
        # Check S3 buckets
        s3_command = "aws s3api list-buckets"
        buckets_response = self.run_aws_command(s3_command)
        if buckets_response:
            buckets = json.loads(buckets_response).get("Buckets", [])
            
            for bucket in buckets:
                bucket_name = bucket["Name"]
                resources_checked += 1
                
                tags_command = f"aws s3api get-bucket-tagging --bucket {bucket_name}"
                tags_response = self.run_aws_command(f"{tags_command} 2>&1")
                if not tags_response or "TagSet" not in tags_response:
                    untagged_resources_count += 1
        
        if untagged_resources_count > 0:
            self.add_finding(
                name="[GENERAL] Missing resource tags",
                severity="Low",
                description=f"Found {untagged_resources_count} out of {resources_checked} resources without proper tagging.",
                cli_command=f"# Check EC2 instance tags\n{instances_command}\n\n# Check S3 bucket tags\n{s3_command}\naws s3api get-bucket-tagging --bucket BUCKET_NAME",
                impact="Lack of proper resource tagging makes it difficult to track resource ownership, cost allocation, compliance status, and security requirements. It can lead to unmanaged resources and inefficient cost management.",
                recommendation="1. Implement a tagging strategy with mandatory tags (e.g., Owner, Environment, CostCenter, Project)\n2. Use AWS Tag Editor to add tags to multiple resources\n3. Enforce tagging policies using AWS Organizations Tag Policies\n4. Consider using automated solutions to enforce tagging compliance"
            )
        else:
            print("✅ All resources are properly tagged")

    def check_security_groups(self):
        print("Checking for overly permissive security groups...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        risky_security_groups = []
        default_security_groups_with_traffic = []
        
        for region in regions:
            sg_command = f"aws ec2 describe-security-groups --region {region}"
            response = self.run_aws_command(sg_command)
            
            if response:
                security_groups = json.loads(response).get("SecurityGroups", [])
                
                for sg in security_groups:
                    group_id = sg["GroupId"]
                    group_name = sg["GroupName"]
                    
                    # Check for default security groups allowing traffic
                    if group_name == "default" and (sg.get("IpPermissions") or sg.get("IpPermissionsEgress")):
                        default_security_groups_with_traffic.append(f"{group_id} ({region})")
                    
                    for permission in sg.get("IpPermissions", []):
                        for ip_range in permission.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                from_port = permission.get("FromPort", "All")
                                to_port = permission.get("ToPort", "All")
                                protocol = permission.get("IpProtocol", "All")
                                
                                # SSH (22) or RDP (3389) exposed to the internet
                                if protocol != "-1" and ((from_port == 22 and to_port == 22) or (from_port == 3389 and to_port == 3389)):
                                    risky_security_groups.append(f"{group_id} ({region}: {protocol}/{from_port})")
                                # All protocols and ports
                                elif protocol == "-1":
                                    risky_security_groups.append(f"{group_id} ({region}: All traffic)")
        
        if risky_security_groups:
            groups_list = ", ".join(risky_security_groups[:5])
            self.add_finding(
                name="[EC2] SSH/RDP exposed to 0.0.0.0/0",
                severity="High",
                description=f"The following security groups allow SSH (port 22) or RDP (port 3389) access from any IP address (0.0.0.0/0): {groups_list}" + (", and more..." if len(risky_security_groups) > 5 else ""),
                cli_command=f"# List security groups in region\naws ec2 describe-security-groups --region REGION_NAME\n\n# Get details for a specific security group\naws ec2 describe-security-groups --group-ids SECURITY_GROUP_ID --region REGION_NAME",
                impact="Exposing management ports like SSH and RDP to the internet significantly increases the risk of brute force attacks, unauthorized access, and potential compromise of your EC2 instances.",
                recommendation="1. Restrict SSH/RDP access to specific trusted IP addresses or CIDR ranges\n2. Implement a bastion host or VPN for secure remote access\n3. Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP access\n4. Use security group rules that limit access to known IP addresses only"
            )
        else:
            print("✅ No security groups exposing SSH/RDP to the internet")
        
        if default_security_groups_with_traffic:
            groups_list = ", ".join(default_security_groups_with_traffic[:5])
            self.add_finding(
                name="[EC2] Default security group allows traffic",
                severity="Low",
                description=f"Default security groups that allow traffic detected: {groups_list}" + (", and more..." if len(default_security_groups_with_traffic) > 5 else ""),
                cli_command=f"# Check default security groups\naws ec2 describe-security-groups --filters Name=group-name,Values=default --region REGION_NAME",
                impact="Using default security groups with permissive rules can lead to unintended network access between resources. This doesn't follow the principle of least privilege.",
                recommendation="1. Configure default security groups to deny all traffic by removing all inbound and outbound rules\n2. Create purpose-specific security groups with appropriate rules for each application or service\n3. Follow the principle of least privilege for all security group rules"
            )

    def check_cloudfront_https(self):
        print("Checking CloudFront HTTPS configuration...")
        command = "aws cloudfront list-distributions"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list CloudFront distributions", "Unknown")
            return
        
        try:
            distributions = json.loads(response).get("DistributionList", {}).get("Items", [])
            insecure_distributions = []
            
            for distribution in distributions:
                dist_id = distribution["Id"]
                if not distribution.get("ViewerCertificate", {}).get("CloudFrontDefaultCertificate", False) and \
                   not distribution.get("ViewerCertificate", {}).get("Certificate") and \
                   distribution.get("Enabled", False):
                    insecure_distributions.append(dist_id)
                
                # Check if HTTPS is not required
                if distribution.get("ViewerCertificate", {}).get("MinimumProtocolVersion", "") == "SSLv3" or \
                   distribution.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy", "") != "https-only":
                    if dist_id not in insecure_distributions:
                        insecure_distributions.append(dist_id)
            
            if insecure_distributions:
                self.add_finding(
                    name="[CLOUDFRONT] HTTPS not enforced",
                    severity="High",
                    description=f"The following CloudFront distributions don't enforce HTTPS: {', '.join(insecure_distributions[:5])}" + 
                               (", and more..." if len(insecure_distributions) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="Without enforced HTTPS, your users' connections to your distribution may be subject to eavesdropping, tampering, and man-in-the-middle attacks.",
                    recommendation="1. Update the CloudFront distribution to use a valid SSL/TLS certificate\n2. Set the Viewer Protocol Policy to 'HTTPS Only' or 'Redirect HTTP to HTTPS'\n3. Set the Minimum Protocol Version to TLSv1.2_2019 or higher"
                )
            else:
                print("✅ All CloudFront distributions enforce HTTPS")
        except Exception as e:
            print(f"Error checking CloudFront HTTPS: {str(e)}")

    def check_elb_https(self):
        print("Checking ELB HTTPS configuration...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        insecure_elbs = []
        
        for region in regions:
            # Check Classic Load Balancers
            elb_command = f"aws elb describe-load-balancers --region {region}"
            elb_response = self.run_aws_command(elb_command)
            
            if elb_response:
                try:
                    elbs = json.loads(elb_response).get("LoadBalancerDescriptions", [])
                    for elb in elbs:
                        elb_name = elb["LoadBalancerName"]
                        secure_listener = False
                        
                        for listener in elb.get("ListenerDescriptions", []):
                            listener_config = listener.get("Listener", {})
                            if listener_config.get("Protocol") in ["HTTPS", "SSL"] or listener_config.get("SSLCertificateId"):
                                secure_listener = True
                                break
                        
                        if not secure_listener and len(elb.get("ListenerDescriptions", [])) > 0:
                            insecure_elbs.append(f"{elb_name} (Classic LB in {region})")
                except Exception as e:
                    print(f"Error checking Classic ELB HTTPS in region {region}: {str(e)}")
            
            # Check Application/Network Load Balancers
            elbv2_command = f"aws elbv2 describe-load-balancers --region {region}"
            elbv2_response = self.run_aws_command(elbv2_command)
            
            if elbv2_response:
                try:
                    elbsv2 = json.loads(elbv2_response).get("LoadBalancers", [])
                    for elb in elbsv2:
                        elb_arn = elb["LoadBalancerArn"]
                        elb_name = elb["LoadBalancerName"]
                        
                        # Skip Network Load Balancers (they operate at layer 4)
                        if elb.get("Type") == "network":
                            continue
                        
                        # Check listeners for HTTPS
                        listeners_command = f"aws elbv2 describe-listeners --load-balancer-arn {elb_arn} --region {region}"
                        listeners_response = self.run_aws_command(listeners_command)
                        
                        if listeners_response:
                            listeners = json.loads(listeners_response).get("Listeners", [])
                            secure_listener = False
                            
                            for listener in listeners:
                                if listener.get("Protocol") in ["HTTPS", "TLS"] or listener.get("Certificates"):
                                    secure_listener = True
                                    break
                            
                            if not secure_listener and len(listeners) > 0:
                                insecure_elbs.append(f"{elb_name} (ALB in {region})")
                except Exception as e:
                    print(f"Error checking ALB/NLB HTTPS in region {region}: {str(e)}")
        
        if insecure_elbs:
            self.add_finding(
                name="[ELB] HTTPS not configured",
                severity="High",
                description=f"The following load balancers don't have HTTPS configured: {', '.join(insecure_elbs[:5])}" + 
                           (", and more..." if len(insecure_elbs) > 5 else ""),
                cli_command=f"# List Classic Load Balancers\naws elb describe-load-balancers --region REGION_NAME\n\n# List Application Load Balancers\naws elbv2 describe-load-balancers --region REGION_NAME\n\n# List Listeners\naws elbv2 describe-listeners --load-balancer-arn LOAD_BALANCER_ARN --region REGION_NAME",
                impact="Without HTTPS, user traffic to your applications is sent in plaintext, exposing sensitive data to potential interception and tampering.",
                recommendation="1. Configure HTTPS listeners on all Internet-facing load balancers\n2. Use ACM to provision and manage certificates\n3. Implement a redirection from HTTP to HTTPS\n4. Use security policies with strong ciphers"
            )
        else:
            print("✅ All load balancers have HTTPS configured")

    def check_elb_security_policy(self):
        print("Checking ELB security policies...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        weak_policy_elbs = []
        
        for region in regions:
            # Check Classic Load Balancers
            elb_command = f"aws elb describe-load-balancers --region {region}"
            elb_response = self.run_aws_command(elb_command)
            
            if elb_response:
                try:
                    elbs = json.loads(elb_response).get("LoadBalancerDescriptions", [])
                    for elb in elbs:
                        elb_name = elb["LoadBalancerName"]
                        
                        # Get the SSL policy for each HTTPS/SSL listener
                        for listener in elb.get("ListenerDescriptions", []):
                            listener_config = listener.get("Listener", {})
                            if listener_config.get("Protocol") in ["HTTPS", "SSL"]:
                                policy_command = f"aws elb describe-load-balancer-policies --load-balancer-name {elb_name} --region {region}"
                                policy_response = self.run_aws_command(policy_command)
                                
                                if policy_response:
                                    policies = json.loads(policy_response).get("PolicyDescriptions", [])
                                    for policy in policies:
                                        if policy.get("PolicyTypeName") == "SSLNegotiationPolicyType":
                                            policy_name = policy.get("PolicyName")
                                            # Check if it's a secure policy (specific to what you consider secure)
                                            if policy_name in ["ELBSecurityPolicy-2011-08", "ELBSecurityPolicy-2014-01"]:
                                                weak_policy_elbs.append(f"{elb_name} (Classic LB in {region}: {policy_name})")
                except Exception as e:
                    print(f"Error checking Classic ELB policies in region {region}: {str(e)}")
            
            # Check Application Load Balancers
            elbv2_command = f"aws elbv2 describe-load-balancers --region {region}"
            elbv2_response = self.run_aws_command(elbv2_command)
            
            if elbv2_response:
                try:
                    elbsv2 = json.loads(elbv2_response).get("LoadBalancers", [])
                    for elb in elbsv2:
                        if elb.get("Type") != "application":
                            continue  # Skip Network Load Balancers
                            
                        elb_arn = elb["LoadBalancerArn"]
                        elb_name = elb["LoadBalancerName"]
                        
                        # Check listeners for HTTPS
                        listeners_command = f"aws elbv2 describe-listeners --load-balancer-arn {elb_arn} --region {region}"
                        listeners_response = self.run_aws_command(listeners_command)
                        
                        if listeners_response:
                            listeners = json.loads(listeners_response).get("Listeners", [])
                            for listener in listeners:
                                if listener.get("Protocol") == "HTTPS":
                                    ssl_policy = listener.get("SslPolicy")
                                    # Check if it's a secure policy
                                    if ssl_policy in ["ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04"]:
                                        weak_policy_elbs.append(f"{elb_name} (ALB in {region}: {ssl_policy})")
                except Exception as e:
                    print(f"Error checking ALB policies in region {region}: {str(e)}")
        
        if weak_policy_elbs:
            self.add_finding(
                name="[ELB] Insecure SSL/TLS policy",
                severity="Medium",
                description=f"The following load balancers use outdated or insecure SSL/TLS policies: {', '.join(weak_policy_elbs[:5])}" + 
                           (", and more..." if len(weak_policy_elbs) > 5 else ""),
                cli_command=f"# For Classic Load Balancers:\naws elb describe-load-balancer-policies --load-balancer-name ELB_NAME --region REGION_NAME\n\n# For Application Load Balancers:\naws elbv2 describe-listeners --load-balancer-arn LOAD_BALANCER_ARN --region REGION_NAME",
                impact="Outdated SSL/TLS policies may include weak ciphers or protocols that are vulnerable to known attacks like POODLE, BEAST, or Heartbleed.",
                recommendation="1. Update SSL policies to use ELBSecurityPolicy-TLS-1-2-2017-01 or ELBSecurityPolicy-FS-1-2-Res-2020-10 at minimum\n2. For Application Load Balancers, use the AWS Console or CLI to modify the listener security policy\n3. For Classic Load Balancers, create a new security policy or update the existing one"
            )
        else:
            print("✅ All load balancers use secure SSL/TLS policies")

    def check_kms_rotation(self):
        print("Checking KMS key rotation...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        non_rotating_keys = []
        
        for region in regions:
            # List customer-managed KMS keys (exclude AWS-managed keys)
            kms_command = f"aws kms list-keys --region {region}"
            kms_response = self.run_aws_command(kms_command)
            
            if kms_response:
                keys = json.loads(kms_response).get("Keys", [])
                for key in keys:
                    key_id = key["KeyId"]
                    
                    # Get key details
                    key_command = f"aws kms describe-key --key-id {key_id} --region {region}"
                    key_response = self.run_aws_command(key_command)
                    
                    if key_response:
                        key_metadata = json.loads(key_response).get("KeyMetadata", {})
                        
                        # Skip AWS managed keys and imported keys (which can't be rotated)
                        if key_metadata.get("KeyManager") == "AWS" or key_metadata.get("Origin") != "AWS_KMS":
                            continue
                        
                        # Check if key rotation is enabled
                        rotation_command = f"aws kms get-key-rotation-status --key-id {key_id} --region {region}"
                        rotation_response = self.run_aws_command(rotation_command)
                        
                        if rotation_response:
                            rotation_status = json.loads(rotation_response)
                            if not rotation_status.get("KeyRotationEnabled", False) and key_metadata.get("KeyState") == "Enabled":
                                key_alias = ""
                                # Try to get alias for better identification
                                alias_command = f"aws kms list-aliases --key-id {key_id} --region {region}"
                                alias_response = self.run_aws_command(alias_command)
                                if alias_response:
                                    aliases = json.loads(alias_response).get("Aliases", [])
                                    if aliases:
                                        key_alias = aliases[0].get("AliasName", "")
                                
                                key_info = key_alias if key_alias else key_id
                                non_rotating_keys.append(f"{key_info} ({region})")
        
        if non_rotating_keys:
            self.add_finding(
                name="[KMS] Key rotation not enabled",
                severity="Medium",
                description=f"The following KMS keys do not have automatic key rotation enabled: {', '.join(non_rotating_keys[:5])}" + 
                           (", and more..." if len(non_rotating_keys) > 5 else ""),
                cli_command=f"# List KMS keys\naws kms list-keys --region REGION_NAME\n\n# Check key rotation status\naws kms get-key-rotation-status --key-id KEY_ID --region REGION_NAME",
                impact="Without key rotation, your encryption keys remain in use for extended periods, increasing the risk of compromise. Long-term use of the same cryptographic key violates cryptographic best practices.",
                recommendation="1. Enable automatic key rotation for all customer-managed KMS keys\n2. Use the AWS Console or CLI to enable key rotation\n3. Implement a rotation period of 1 year or less\n4. For imported key material (which can't be automatically rotated), establish a manual rotation process"
            )
        else:
            print("✅ All customer-managed KMS keys have rotation enabled")

    def check_lambda_permissions(self):
        print("Checking Lambda function permissions...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        public_functions = []
        
        for region in regions:
            lambda_command = f"aws lambda list-functions --region {region}"
            lambda_response = self.run_aws_command(lambda_command)
            
            if lambda_response:
                functions = json.loads(lambda_response).get("Functions", [])
                for function in functions:
                    function_name = function["FunctionName"]
                    
                    # Check function policy
                    policy_command = f"aws lambda get-policy --function-name {function_name} --region {region}"
                    policy_response = self.run_aws_command(policy_command)
                    
                    if policy_response and "Policy" in policy_response:
                        try:
                            policy = json.loads(json.loads(policy_response)["Policy"])
                            
                            # Check for public access
                            for statement in policy.get("Statement", []):
                                principal = statement.get("Principal", {})
                                if isinstance(principal, str) and principal == "*":
                                    public_functions.append(f"{function_name} ({region})")
                                elif isinstance(principal, dict) and principal.get("AWS") == "*":
                                    public_functions.append(f"{function_name} ({region})")
                                elif isinstance(principal, dict) and principal.get("Service") == "*":
                                    public_functions.append(f"{function_name} ({region})")
                        except Exception as e:
                            print(f"Error parsing policy for function {function_name}: {str(e)}")
        
        if public_functions:
            self.add_finding(
                name="[LAMBDA] Functions with public access",
                severity="High",
                description=f"The following Lambda functions have policies that allow public access: {', '.join(public_functions[:5])}" + 
                           (", and more..." if len(public_functions) > 5 else ""),
                cli_command=f"# List Lambda functions\naws lambda list-functions --region REGION_NAME\n\n# Get function policy\naws lambda get-policy --function-name FUNCTION_NAME --region REGION_NAME",
                impact="Lambda functions with public access policies can be invoked by anyone on the internet, potentially leading to unauthorized access, abuse of your resources, or unexpected charges.",
                recommendation="1. Revise the resource-based policies of your Lambda functions to restrict access\n2. Use IAM roles for service-to-service invocation instead of making functions public\n3. If public access is required, implement proper request validation and authorization\n4. Consider using AWS API Gateway with proper authorization for public-facing Lambda functions"
            )
        else:
            print("✅ No Lambda functions with public access detected")

    def check_lambda_vpc_config(self):
        print("Checking Lambda VPC configuration...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        no_vpc_functions = []
        
        for region in regions:
            lambda_command = f"aws lambda list-functions --region {region}"
            lambda_response = self.run_aws_command(lambda_command)
            
            if lambda_response:
                functions = json.loads(lambda_response).get("Functions", [])
                for function in functions:
                    function_name = function["FunctionName"]
                    
                    # Check if the function has a VPC configuration
                    if not function.get("VpcConfig") or not function.get("VpcConfig", {}).get("VpcId"):
                        # We'll be selective about which functions really need VPC connectivity
                        # For this check, we'll look at environment variables or descriptions that hint at DB access
                        env_vars = function.get("Environment", {}).get("Variables", {})
                        description = function.get("Description", "").lower()
                        
                        env_keys = [key.lower() for key in env_vars.keys()]
                        
                        # Words that might indicate a need for VPC connectivity
                        vpc_indicators = ["db", "database", "rds", "sql", "mongo", "redis", "elasticache", "internal"]
                        
                        # Check if any indicators are present in env vars or description
                        needs_vpc = any(indicator in " ".join(env_keys).lower() for indicator in vpc_indicators) or \
                                    any(indicator in description for indicator in vpc_indicators)
                        
                        if needs_vpc:
                            no_vpc_functions.append(f"{function_name} ({region})")
        
        if no_vpc_functions:
            self.add_finding(
                name="[LAMBDA] Functions without VPC configuration",
                severity="Medium",
                description=f"The following Lambda functions that may need internal resources access don't have VPC configuration: {', '.join(no_vpc_functions[:5])}" + 
                           (", and more..." if len(no_vpc_functions) > 5 else ""),
                cli_command=f"# List Lambda functions\naws lambda list-functions --region REGION_NAME",
                impact="Lambda functions without VPC configuration cannot access resources in private VPCs (like RDS databases or ElastiCache clusters). This might lead to deployment of additional proxies or exposure of services publicly.",
                recommendation="1. Configure Lambda functions to run within a VPC when they need to access private resources\n2. Assign proper security groups and subnets with appropriate route tables\n3. Ensure Lambda execution role has the required permissions (AWSLambdaVPCAccessExecutionRole)\n4. For truly public services without VPC resources, it's okay to not have VPC configuration"
            )
        else:
            print("✅ All Lambda functions that need internal access have VPC configuration")

    def generate_html_report(self, output_file="aws_security_report.html"):
        """Generate a detailed HTML report of all findings."""
        
        # Define severity colors for the report
        severity_colors = {
            "Critical": "#FF5252",  # Red
            "High": "#FF9800",      # Orange
            "Medium": "#FFEB3B",    # Yellow
            "Low": "#2196F3",       # Blue
            "Unknown": "#9E9E9E"    # Gray
        }
        
        # Count issues by severity
        severity_counts = {
            "Critical": len([f for f in self.findings if f["severity"] == "Critical"]),
            "High": len([f for f in self.findings if f["severity"] == "High"]),
            "Medium": len([f for f in self.findings if f["severity"] == "Medium"]),
            "Low": len([f for f in self.findings if f["severity"] == "Low"]),
            "Unknown": len([f for f in self.findings if f["severity"] == "Unknown"])
        }
        
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Define the HTML content
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
            padding: 20px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #eaecef;
            padding-bottom: 0.3em;
            margin-top: 0;
        }}
        .summary-box {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0;
        }}
        .severity-count {{
            padding: 15px;
            border-radius: 5px;
            flex: 1;
            min-width: 120px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
        .finding {{
            margin-bottom: 30px;
            border-left: 4px solid #ddd;
            padding-left: 15px;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .severity-badge {{
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }}
        .finding-name {{
            font-size: 18px;
            font-weight: bold;
            margin: 0;
        }}
        .section {{
            margin-bottom: 10px;
        }}
        .section-title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        pre {{
            background-color: #f6f8fa;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 10px;
            overflow-x: auto;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }}
        .no-findings {{
            background-color: #e8f5e9;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            margin: 30px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AWS Security Scan Report</h1>
        <p>Date: {report_date}</p>
        
        <h2>Summary</h2>
        <div class="summary-box">
            <div class="severity-count" style="background-color: {severity_colors['Critical']}">
                Critical<br>{severity_counts['Critical']}
            </div>
            <div class="severity-count" style="background-color: {severity_colors['High']}">
                High<br>{severity_counts['High']}
            </div>
            <div class="severity-count" style="background-color: {severity_colors['Medium']}">
                Medium<br>{severity_counts['Medium']}
            </div>
            <div class="severity-count" style="background-color: {severity_colors['Low']}">
                Low<br>{severity_counts['Low']}
            </div>
        </div>
        """
        
        if not self.findings:
            html_content += """
        <div class="no-findings">
            <h3>🎉 No security issues found!</h3>
            <p>Your AWS account appears to be well-configured according to the security checks performed.</p>
        </div>
            """
        else:
            # Group findings by severity
            for severity in ["Critical", "High", "Medium", "Low", "Unknown"]:
                severity_findings = [f for f in self.findings if f["severity"] == severity]
                if severity_findings:
                    html_content += f'<h2>{severity} Findings</h2>'
                    
                    for finding in severity_findings:
                        html_content += f"""
        <div class="finding">
            <div class="finding-header">
                <h3 class="finding-name">{finding["name"]}</h3>
                <span class="severity-badge" style="background-color: {severity_colors[severity]}">
                    {severity}
                </span>
            </div>
            
            <div class="section">
                <div class="section-title">Description</div>
                <p>{finding["description"]}</p>
            </div>
            
            <div class="section">
                <div class="section-title">CLI Command for Verification</div>
                <pre>{finding["cli_command"]}</pre>
            </div>
            
            <div class="section">
                <div class="section-title">Impact</div>
                <p>{finding["impact"]}</p>
            </div>
            
            <div class="section">
                <div class="section-title">Recommendation</div>
                <p>{finding["recommendation"]}</p>
            </div>
        </div>
                        """
        
        html_content += """
        <div class="footer">
            <p>This report is provided for informational purposes only. It is not a substitute for a professional security assessment.</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Write to file
        with open(output_file, "w") as f:
            f.write(html_content)
        
        print(f"\nHTML report generated: {output_file}")
        
        # Try to open the report in a browser
        try:
            webbrowser.open("file://" + os.path.abspath(output_file))
        except:
            print("Could not automatically open the report in a browser.")
        
        return output_file

    def run_all_checks(self):
        print("Starting AWS Security Scanner...\n")
        
        # Critical severity checks
        self.check_root_mfa()
        self.check_root_access_keys()
        self.check_s3_public_access()
        self.check_rds_instances()
        self.check_ebs_snapshots()
        self.check_aws_config()
        self.check_ec2_public_amis()
        self.check_iam_excessive_permissions()
        self.check_secrets_in_lambda()
        self.check_inactive_admin_users()
        self.check_sensitive_files_in_s3()
        self.check_privileged_users_without_mfa()  
        self.check_iam_privilege_escalation_paths()  
        self.check_root_account_usage()  
        self.check_iam_group_excessive_privileges()
        self.check_root_hardware_mfa()
        self.check_ec2_instance_attribute_manipulation()
        
        # High severity checks
        self.check_cloudtrail()
        self.check_security_groups()
        self.check_iam_access_analyzer()
        self.check_aws_organizations()
        self.check_cloudfront_https()
        self.check_cloudfront_security()  
        self.check_elb_https()
        self.check_lambda_permissions()
        self.check_acm_certificates()
        self.check_auto_scaling_groups()
        self.check_rds_ssl_enforcement()
        self.check_hardware_mfa()
        self.check_security_hub()
        self.check_eks_cluster_security()
        self.check_ec2_imdsv2_requirement()
        self.check_sg_non_web_ports()
        self.check_aws_account_organization()
        self.check_s3_secure_transport()
        self.check_cloudfront_origin_groups()
        self.check_s3_account_block_public_access()
        
        # Medium severity checks
        self.check_access_keys()
        self.check_password_policy()
        self.check_imdsv1()
        self.check_vpc_flow_logs()
        self.check_s3_encryption()
        self.check_s3_versioning()
        self.check_s3_logging()
        self.check_guardduty()
        self.check_elb_security_policy()
        self.check_kms_rotation()
        self.check_lambda_vpc_config()
        self.check_dynamodb_encryption()
        self.check_dynamodb_point_in_time_recovery()
        self.check_shield_advanced()
        self.check_ec2_ebs_encryption_by_default()
        self.check_api_gateway()
        self.check_sqs_encryption()
        self.check_rds_deletion_protection()
        self.check_cloudwatch_logs_encryption()
        self.check_s3_mfa_delete()
        self.check_organization_scps()
        self.check_ecr_tag_immutability()
        self.check_rds_single_az()
        self.check_cmk_usage()
        self.check_iam_direct_attached_policies()
        self.check_secrets_manager_rotation()
        self.check_ecr_scanning()
        self.check_api_gateway_logging()
        self.check_aws_backup()
        self.check_alb_access_logs()
        self.check_ebs_snapshots_recent()
        self.check_cloudwatch_metric_filters()
        self.check_s3_cross_region_replication()
        
        # Low severity checks
        self.check_resource_tags()
        self.check_s3_lifecycle()
        self.check_elb_deletion_protection()
        self.check_ec2_detailed_monitoring()
        self.check_unused_security_groups()
        self.check_s3_event_notifications()
        self.check_org_tag_policies()
        self.check_org_security_contact()
        self.check_rds_enhanced_monitoring()

    def check_dynamodb_encryption(self):
        print("Checking DynamoDB table encryption...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unencrypted_tables = []
        
        for region in regions:
            ddb_command = f"aws dynamodb list-tables --region {region}"
            ddb_response = self.run_aws_command(ddb_command)
            
            if ddb_response:
                tables = json.loads(ddb_response).get("TableNames", [])
                for table_name in tables:
                    desc_command = f"aws dynamodb describe-table --table-name {table_name} --region {region}"
                    desc_response = self.run_aws_command(desc_command)
                    
                    if desc_response:
                        table_info = json.loads(desc_response).get("Table", {})
                        sse_desc = table_info.get("SSEDescription", {})
                        
                        # Check if SSE is enabled
                        if not sse_desc or sse_desc.get("Status") != "ENABLED":
                            unencrypted_tables.append(f"{table_name} ({region})")
        
        if unencrypted_tables:
            self.add_finding(
                name="[DYNAMODB] Tables without encryption",
                severity="Medium",
                description=f"The following DynamoDB tables are not encrypted: {', '.join(unencrypted_tables[:5])}" + 
                           (", and more..." if len(unencrypted_tables) > 5 else ""),
                cli_command=f"# List DynamoDB tables\naws dynamodb list-tables --region REGION_NAME\n\n# Describe table\naws dynamodb describe-table --table-name TABLE_NAME --region REGION_NAME",
                impact="Unencrypted DynamoDB tables may expose sensitive data if the underlying storage is compromised. Encryption at rest is a security best practice and may be required for compliance with regulations like GDPR, HIPAA, or PCI-DSS.",
                recommendation="1. Enable encryption for all DynamoDB tables using either AWS owned or customer managed CMKs\n2. For existing tables, encryption can be enabled without downtime\n3. Configure CloudTrail to monitor for changes to table encryption settings\n4. Consider using AWS Backup for encrypted backups of your DynamoDB tables"
            )
        else:
            print("✅ All DynamoDB tables have encryption enabled")

    def check_dynamodb_point_in_time_recovery(self):
        print("Checking DynamoDB point-in-time recovery...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        no_pitr_tables = []
        
        for region in regions:
            ddb_command = f"aws dynamodb list-tables --region {region}"
            ddb_response = self.run_aws_command(ddb_command)
            
            if ddb_response:
                tables = json.loads(ddb_response).get("TableNames", [])
                for table_name in tables:
                    pitr_command = f"aws dynamodb describe-continuous-backups --table-name {table_name} --region {region}"
                    pitr_response = self.run_aws_command(pitr_command)
                    
                    if pitr_response:
                        backup_info = json.loads(pitr_response).get("ContinuousBackupsDescription", {})
                        pitr_status = backup_info.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus", "")
                        
                        if pitr_status != "ENABLED":
                            no_pitr_tables.append(f"{table_name} ({region})")
        
        if no_pitr_tables:
            self.add_finding(
                name="[DYNAMODB] Point-in-Time Recovery disabled",
                severity="Medium",
                description=f"The following DynamoDB tables do not have Point-in-Time Recovery enabled: {', '.join(no_pitr_tables[:5])}" + 
                           (", and more..." if len(no_pitr_tables) > 5 else ""),
                cli_command=f"# Check PITR status\naws dynamodb describe-continuous-backups --table-name TABLE_NAME --region REGION_NAME",
                impact="Without Point-in-Time Recovery, you risk permanent data loss in case of accidental writes or deletes. You would only be able to restore to your last backup, potentially losing hours or days of data changes.",
                recommendation="1. Enable Point-in-Time Recovery for all production DynamoDB tables\n2. PITR allows you to restore data to any point in time within the last 35 days\n3. Use AWS Backup for longer-term retention if needed\n4. Consider implementing application-level validation to prevent accidental data modifications"
            )
        else:
            print("✅ All DynamoDB tables have Point-in-Time Recovery enabled")

    def check_ec2_public_amis(self):
        print("Checking for public EC2 AMIs...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        public_amis = []
        
        for region in regions:
            ami_command = f"aws ec2 describe-images --owners self --region {region}"
            ami_response = self.run_aws_command(ami_command)
            
            if ami_response:
                images = json.loads(ami_response).get("Images", [])
                for image in images:
                    ami_id = image["ImageId"]
                    if image.get("Public", False):
                        public_amis.append(f"{ami_id} ({region}: {image.get('Name', 'No Name')})")
        
        if public_amis:
            self.add_finding(
                name="[EC2] Public AMIs owned by account",
                severity="High",
                description=f"The following AMIs are publicly accessible: {', '.join(public_amis[:5])}" + 
                           (", and more..." if len(public_amis) > 5 else ""),
                cli_command=f"# List your owned AMIs\naws ec2 describe-images --owners self --region REGION_NAME",
                impact="Public AMIs can be used by anyone on the internet. If these AMIs contain sensitive data, proprietary software, or configurations, they could lead to data exposure or intellectual property theft.",
                recommendation="1. Make all AMIs private unless they are specifically intended to be shared publicly\n2. Remove any sensitive data, credentials, or configurations before making AMIs public\n3. Regularly audit your AMIs and their permissions\n4. Consider using AWS Organizations to prevent accidental public sharing"
            )
        else:
            print("✅ No public AMIs detected")

    def check_shield_advanced(self):
        print("Checking AWS Shield Advanced subscription...")
        command = "aws shield describe-subscription"
        response = self.run_aws_command(command)
        
        if not response or "StartTime" not in response:
            self.add_finding(
                name="[SHIELD] AWS Shield Advanced not enabled",
                severity="Medium",
                description="AWS Shield Advanced is not enabled for this account. Shield Advanced provides enhanced DDoS protection for your AWS resources.",
                cli_command=command,
                impact="Without Shield Advanced, your AWS resources are more vulnerable to sophisticated DDoS attacks that could impact availability. You also miss out on 24/7 access to the AWS DDoS Response Team and cost protection for scaling during DDoS events.",
                recommendation="1. Consider subscribing to AWS Shield Advanced for enhanced DDoS protection\n2. Shield Advanced is especially recommended for public-facing applications, websites, or APIs\n3. Enable Shield Advanced protections for specific resources like CloudFront distributions, Route 53 hosted zones, and ALBs\n4. Implement AWS WAF in conjunction with Shield Advanced for more comprehensive protection"
            )
        else:
            print("✅ AWS Shield Advanced is enabled")
            
            # Check if all resources are protected
            protected_resource_count = 0
            
            # Check CloudFront distributions
            cf_command = "aws cloudfront list-distributions"
            cf_response = self.run_aws_command(cf_command)
            if cf_response:
                cf_count = len(json.loads(cf_response).get("DistributionList", {}).get("Items", []))
                
                # Get protected CloudFront distributions
                shield_cf_command = "aws shield list-protections"
                shield_cf_response = self.run_aws_command(shield_cf_command)
                if shield_cf_response:
                    protections = json.loads(shield_cf_response).get("Protections", [])
                    protected_cf = [p for p in protections if p.get("ResourceArn", "").startswith("arn:aws:cloudfront")]
                    protected_resource_count += len(protected_cf)
                    
                    if len(protected_cf) < cf_count:
                        self.add_finding(
                            name="[SHIELD] Not all CloudFront distributions protected",
                            severity="Medium",
                            description=f"Only {len(protected_cf)} out of {cf_count} CloudFront distributions are protected by Shield Advanced.",
                            cli_command=f"# List Shield protections\naws shield list-protections",
                            impact="Unprotected CloudFront distributions may be vulnerable to DDoS attacks, potentially impacting availability of your content delivery.",
                            recommendation="1. Enable Shield Advanced protection for all public-facing CloudFront distributions\n2. Configure automatic application layer DDoS mitigation\n3. Set up CloudWatch alarms for DDoS detection metrics\n4. Consider implementing rate-based rules in AWS WAF for additional protection"
                        )

    def check_ec2_ebs_encryption_by_default(self):
        print("Checking for EBS encryption by default...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unencrypted_regions = []
        
        for region in regions:
            ebs_command = f"aws ec2 get-ebs-encryption-by-default --region {region}"
            ebs_response = self.run_aws_command(ebs_command)
            
            if ebs_response and "EbsEncryptionByDefault" in ebs_response:
                if not json.loads(ebs_response).get("EbsEncryptionByDefault", False):
                    unencrypted_regions.append(region)
        
        if unencrypted_regions:
            self.add_finding(
                name="[EC2] EBS encryption by default not enabled",
                severity="Medium",
                description=f"EBS encryption by default is not enabled in these regions: {', '.join(unencrypted_regions)}",
                cli_command=f"# Check EBS encryption by default\naws ec2 get-ebs-encryption-by-default --region REGION_NAME",
                impact="Without default encryption, new EBS volumes and snapshots created from volumes may be unencrypted, potentially exposing sensitive data if accessed by unauthorized users.",
                recommendation="1. Enable EBS encryption by default in all regions where you operate\n2. Use the AWS Console or CLI to enable encryption by default\n3. Configure CloudTrail to monitor for changes to encryption settings\n4. Consider using customer managed KMS keys for stronger control over your encryption"
            )
        else:
            print("✅ EBS encryption by default is enabled in all regions")

    # ACM (AWS Certificate Manager) Checks
    def check_acm_certificates(self):
        print("Checking ACM certificates...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        expired_certs = []
        renewal_needed_certs = []
        invalid_certs = []
        
        for region in regions:
            acm_command = f"aws acm list-certificates --region {region}"
            acm_response = self.run_aws_command(acm_command)
            
            if not acm_response:
                continue
                
            try:
                certificates = json.loads(acm_response).get("CertificateSummaryList", [])
                
                for cert in certificates:
                    cert_arn = cert.get("CertificateArn")
                    
                    # Get detailed certificate info
                    cert_detail_command = f"aws acm describe-certificate --certificate-arn {cert_arn} --region {region}"
                    cert_detail_response = self.run_aws_command(cert_detail_command)
                    
                    if not cert_detail_response:
                        continue
                        
                    cert_details = json.loads(cert_detail_response).get("Certificate", {})
                    
                    # Check for expired certificates
                    not_after = cert_details.get("NotAfter")
                    if not_after:
                        expiry_date = datetime.fromtimestamp(not_after/1000, tz=timezone.utc)
                        current_date = datetime.now(timezone.utc)
                        
                        if expiry_date < current_date:
                            expired_certs.append(f"{cert.get('DomainName')} ({region})")
                        # Check for certificates that need renewal (less than 30 days until expiry)
                        elif (expiry_date - current_date).days < 30:
                            renewal_needed_certs.append(f"{cert.get('DomainName')} ({region})")
                    
                    # Check for certificates with validation issues
                    domain_validation = cert_details.get("DomainValidationOptions", [])
                    for validation in domain_validation:
                        validation_status = validation.get("ValidationStatus")
                        if validation_status != "SUCCESS":
                            invalid_certs.append(f"{cert.get('DomainName')} ({region})")
                            break
            except Exception as e:
                print(f"Error checking ACM certificates in region {region}: {str(e)}")
        
        # Report findings
        if expired_certs:
            self.add_finding(
                name="[ACM] Expired certificates",
                severity="High",
                description=f"The following SSL/TLS certificates in ACM are expired: {', '.join(expired_certs[:5])}" + 
                           (", and more..." if len(expired_certs) > 5 else ""),
                cli_command=f"# List certificates\naws acm list-certificates --region REGION\n\n# Get certificate details\naws acm describe-certificate --certificate-arn CERTIFICATE_ARN --region REGION",
                impact="Expired certificates can cause service disruptions, browser warnings, and prevent users from accessing your applications securely.",
                recommendation="Delete the expired certificates and replace them with new valid certificates. For AWS managed renewals, ensure the DNS validation records are properly configured."
            )
        
        if renewal_needed_certs:
            self.add_finding(
                name="[ACM] Certificates requiring renewal",
                severity="Medium",
                description=f"The following SSL/TLS certificates in ACM will expire within 30 days: {', '.join(renewal_needed_certs[:5])}" + 
                           (", and more..." if len(renewal_needed_certs) > 5 else ""),
                cli_command=f"# List certificates\naws acm list-certificates --region REGION\n\n# Get certificate details\naws acm describe-certificate --certificate-arn CERTIFICATE_ARN --region REGION",
                impact="Certificates that are about to expire could cause unexpected service disruptions and security warnings if not renewed in time.",
                recommendation="Renew the certificates before they expire. For ACM-issued certificates, ensure DNS validation is properly configured to allow automatic renewal."
            )
        
        if invalid_certs:
            self.add_finding(
                name="[ACM] Certificate validation issues",
                severity="High",
                description=f"The following SSL/TLS certificates in ACM have validation issues: {', '.join(invalid_certs[:5])}" + 
                           (", and more..." if len(invalid_certs) > 5 else ""),
                cli_command=f"# List certificates\naws acm list-certificates --region REGION\n\n# Get certificate details\naws acm describe-certificate --certificate-arn CERTIFICATE_ARN --region REGION",
                impact="Certificates with validation issues cannot be used for securing your services, potentially leaving them vulnerable or inaccessible.",
                recommendation="Resend the domain validation email or update DNS validation records for these certificates to complete the validation process."
            )
            
        if not expired_certs and not renewal_needed_certs and not invalid_certs:
            print("✅ All ACM certificates are valid and not approaching expiration")

    # API Gateway checks
    def check_api_gateway(self):
        print("Checking API Gateway configurations...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        apis_without_logging = []
        apis_without_metrics = []
        apis_without_private_endpoints = []
        
        for region in regions:
            # Get REST APIs
            rest_api_command = f"aws apigateway get-rest-apis --region {region}"
            rest_api_response = self.run_aws_command(rest_api_command)
            
            if rest_api_response:
                try:
                    rest_apis = json.loads(rest_api_response).get("items", [])
                    
                    for api in rest_apis:
                        api_id = api.get("id")
                        api_name = api.get("name")
                        
                        # Check API stages for logging configuration
                        stages_command = f"aws apigateway get-stages --rest-api-id {api_id} --region {region}"
                        stages_response = self.run_aws_command(stages_command)
                        
                        if stages_response:
                            stages = json.loads(stages_response).get("item", [])
                            
                            for stage in stages:
                                stage_name = stage.get("stageName")
                                
                                # Check for CloudWatch logs
                                method_settings = stage.get("methodSettings", {}).get("*/*", {})
                                if not stage.get("accessLogSettings") and not method_settings.get("loggingLevel"):
                                    apis_without_logging.append(f"{api_name}/{stage_name} ({region})")
                                
                                # Check for detailed metrics
                                if not method_settings.get("metricsEnabled", False):
                                    apis_without_metrics.append(f"{api_name}/{stage_name} ({region})")
                        
                        # Check for endpoint type (whether it's private)
                        endpoint_config = api.get("endpointConfiguration", {})
                        endpoint_types = endpoint_config.get("types", [])
                        
                        # If endpoint types include 'EDGE' or 'REGIONAL' but not 'PRIVATE'
                        if ("EDGE" in endpoint_types or "REGIONAL" in endpoint_types) and "PRIVATE" not in endpoint_types:
                            apis_without_private_endpoints.append(f"{api_name} ({region})")
                
                except Exception as e:
                    print(f"Error checking API Gateway in region {region}: {str(e)}")
            
            # Check HTTP APIs (API Gateway v2)
            http_api_command = f"aws apigatewayv2 get-apis --region {region}"
            http_api_response = self.run_aws_command(http_api_command)
            
            if http_api_response:
                try:
                    http_apis = json.loads(http_api_response).get("Items", [])
                    
                    for api in http_apis:
                        api_id = api.get("ApiId")
                        api_name = api.get("Name")
                        
                        # Check API stages for logging configuration
                        stages_command = f"aws apigatewayv2 get-stages --api-id {api_id} --region {region}"
                        stages_response = self.run_aws_command(stages_command)
                        
                        if stages_response:
                            stages = json.loads(stages_response).get("Items", [])
                            
                            for stage in stages:
                                stage_name = stage.get("StageName")
                                
                                # Check for CloudWatch logs
                                if not stage.get("AccessLogSettings") and not stage.get("DefaultRouteSettings", {}).get("LoggingLevel"):
                                    apis_without_logging.append(f"{api_name}/{stage_name} (HTTP API, {region})")
                                
                                # Check for detailed metrics
                                if not stage.get("DefaultRouteSettings", {}).get("DetailedMetricsEnabled", False):
                                    apis_without_metrics.append(f"{api_name}/{stage_name} (HTTP API, {region})")
                
                except Exception as e:
                    print(f"Error checking HTTP API Gateway in region {region}: {str(e)}")
        
        # Report findings
        if apis_without_logging:
            self.add_finding(
                name="[API Gateway] CloudWatch logs not enabled",
                severity="Medium",
                description=f"The following API Gateway APIs do not have CloudWatch logs enabled: {', '.join(apis_without_logging[:5])}" + 
                           (", and more..." if len(apis_without_logging) > 5 else ""),
                cli_command=f"# Get REST APIs\naws apigateway get-rest-apis --region REGION\n\n# Get stages for an API\naws apigateway get-stages --rest-api-id API_ID --region REGION",
                impact="Without API Gateway logging, you cannot monitor and troubleshoot API requests and responses, making it difficult to investigate security incidents or performance issues.",
                recommendation="Enable CloudWatch logs for all API Gateway stages. This can be done through the AWS Console or CLI by updating the stage settings to include log settings."
            )
        
        if apis_without_metrics:
            self.add_finding(
                name="[API Gateway] Detailed metrics not enabled",
                severity="Medium",
                description=f"The following API Gateway APIs do not have detailed CloudWatch metrics enabled: {', '.join(apis_without_metrics[:5])}" + 
                           (", and more..." if len(apis_without_metrics) > 5 else ""),
                cli_command=f"# Get REST APIs\naws apigateway get-rest-apis --region REGION\n\n# Get stages for an API\naws apigateway get-stages --rest-api-id API_ID --region REGION",
                impact="Without detailed metrics, you cannot effectively monitor API performance, usage patterns, or detect anomalies that might indicate security issues.",
                recommendation="Enable detailed CloudWatch metrics for all API Gateway stages. This can be done through the AWS Console or CLI by updating the stage settings."
            )
        
        if apis_without_private_endpoints:
            self.add_finding(
                name="[API Gateway] APIs not using private endpoints",
                severity="Medium",
                description=f"The following API Gateway APIs are not configured to use private endpoints: {', '.join(apis_without_private_endpoints[:5])}" + 
                           (", and more..." if len(apis_without_private_endpoints) > 5 else ""),
                cli_command=f"# Get REST APIs and their endpoint configurations\naws apigateway get-rest-apis --region REGION",
                impact="APIs without private endpoints are potentially exposed to the public internet, increasing the attack surface and risk of unauthorized access.",
                recommendation="Consider converting appropriate APIs to use private endpoints. This limits API access to within your VPC, improving security by reducing exposure to the internet."
            )
            
        if not apis_without_logging and not apis_without_metrics and not apis_without_private_endpoints:
            print("✅ All API Gateway configurations follow security best practices")

    # Auto Scaling Group checks
    def check_auto_scaling_groups(self):
        print("Checking Auto Scaling Groups configurations...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        asgs_without_cooldown = []
        asgs_without_notifications = []
        app_tier_asgs_without_elb = []
        empty_asgs = []
        asgs_with_missing_ami = []
        asgs_with_missing_sg = []
        unused_launch_configs = []
        
        for region in regions:
            # Get Auto Scaling Groups
            asg_command = f"aws autoscaling describe-auto-scaling-groups --region {region}"
            asg_response = self.run_aws_command(asg_command)
            
            if not asg_response:
                continue
                
            try:
                asgs = json.loads(asg_response).get("AutoScalingGroups", [])
                
                for asg in asgs:
                    asg_name = asg.get("AutoScalingGroupName")
                    
                    # Check for cooldown period
                    if asg.get("DefaultCooldown", 0) < 300:  # Less than 5 minutes
                        asgs_without_cooldown.append(f"{asg_name} ({region})")
                    
                    # Check for notifications
                    if not asg.get("NotificationConfigurations"):
                        asgs_without_notifications.append(f"{asg_name} ({region})")
                    
                    # Check for app-tier ASGs without ELB
                    # This is a heuristic check - assuming app-tier ASGs are identifiable by name
                    if "app" in asg_name.lower() and not asg.get("LoadBalancerNames") and not asg.get("TargetGroupARNs"):
                        app_tier_asgs_without_elb.append(f"{asg_name} ({region})")
                    
                    # Check for empty ASGs
                    if asg.get("Instances", []) == [] and asg.get("DesiredCapacity", 0) > 0:
                        empty_asgs.append(f"{asg_name} ({region})")
                    
                    # Check for missing AMI or Security Group in Launch Configuration/Template
                    if "LaunchConfigurationName" in asg:
                        launch_config_name = asg.get("LaunchConfigurationName")
                        lc_command = f"aws autoscaling describe-launch-configurations --launch-configuration-names {launch_config_name} --region {region}"
                        lc_response = self.run_aws_command(lc_command)
                        
                        if lc_response:
                            launch_configs = json.loads(lc_response).get("LaunchConfigurations", [])
                            if launch_configs:
                                lc = launch_configs[0]
                                
                                # Check AMI
                                ami_id = lc.get("ImageId")
                                ami_command = f"aws ec2 describe-images --image-ids {ami_id} --region {region}"
                                ami_response = self.run_aws_command(ami_command)
                                
                                if not ami_response or "Images" not in ami_response or json.loads(ami_response).get("Images", []) == []:
                                    asgs_with_missing_ami.append(f"{asg_name} ({region})")
                                
                                # Check Security Groups
                                for sg_id in lc.get("SecurityGroups", []):
                                    sg_command = f"aws ec2 describe-security-groups --group-ids {sg_id} --region {region}"
                                    sg_response = self.run_aws_command(sg_command)
                                    
                                    if not sg_response or "SecurityGroups" not in sg_response:
                                        asgs_with_missing_sg.append(f"{asg_name} ({region})")
                                        break
                    elif "LaunchTemplate" in asg:
                        # Similar checks for Launch Templates could be implemented here
                        pass
                
                # Check for unused Launch Configurations
                lc_command = f"aws autoscaling describe-launch-configurations --region {region}"
                lc_response = self.run_aws_command(lc_command)
                
                if lc_response:
                    launch_configs = json.loads(lc_response).get("LaunchConfigurations", [])
                    used_lcs = [asg.get("LaunchConfigurationName") for asg in asgs if "LaunchConfigurationName" in asg]
                    
                    for lc in launch_configs:
                        lc_name = lc.get("LaunchConfigurationName")
                        if lc_name not in used_lcs:
                            unused_launch_configs.append(f"{lc_name} ({region})")
                
            except Exception as e:
                print(f"Error checking Auto Scaling Groups in region {region}: {str(e)}")
        
        # Report findings
        if asgs_without_cooldown:
            self.add_finding(
                name="[ASG] Insufficient cooldown period",
                severity="High",
                description=f"The following Auto Scaling Groups have insufficient cooldown periods (<5 minutes): {', '.join(asgs_without_cooldown[:5])}" + 
                           (", and more..." if len(asgs_without_cooldown) > 5 else ""),
                cli_command=f"# Get Auto Scaling Groups\naws autoscaling describe-auto-scaling-groups --region REGION",
                impact="Without an adequate cooldown period, Auto Scaling might continue scaling out or in without allowing time for previous scaling activities to take effect, potentially leading to excessive scaling and increased costs.",
                recommendation="Configure an appropriate cooldown period (at least 5 minutes) for your Auto Scaling Groups to allow newly launched instances to start handling application traffic."
            )
        
        if asgs_without_notifications:
            self.add_finding(
                name="[ASG] Notifications not enabled",
                severity="Low",
                description=f"The following Auto Scaling Groups do not have notifications configured: {', '.join(asgs_without_notifications[:5])}" + 
                           (", and more..." if len(asgs_without_notifications) > 5 else ""),
                cli_command=f"# Get Auto Scaling Groups\naws autoscaling describe-auto-scaling-groups --region REGION",
                impact="Without notifications, you may not be aware of scaling events, making it difficult to monitor and respond to changes in your environment.",
                recommendation="Configure Auto Scaling Group notifications to send email alerts via SNS when scaling events occur."
            )
        
        if app_tier_asgs_without_elb:
            self.add_finding(
                name="[ASG] App-tier ASGs without associated ELB",
                severity="High",
                description=f"The following app-tier Auto Scaling Groups do not have associated Elastic Load Balancers: {', '.join(app_tier_asgs_without_elb[:5])}" + 
                           (", and more..." if len(app_tier_asgs_without_elb) > 5 else ""),
                cli_command=f"# Get Auto Scaling Groups\naws autoscaling describe-auto-scaling-groups --region REGION",
                impact="Without an associated load balancer, traffic may not be evenly distributed across instances, potentially leading to performance issues or service disruptions.",
                recommendation="Associate Elastic Load Balancers with app-tier Auto Scaling Groups to ensure even traffic distribution and improved high availability."
            )
        
        if empty_asgs:
            self.add_finding(
                name="[ASG] Empty Auto Scaling Groups",
                severity="Low",
                description=f"The following Auto Scaling Groups are empty despite a non-zero desired capacity: {', '.join(empty_asgs[:5])}" + 
                           (", and more..." if len(empty_asgs) > 5 else ""),
                cli_command=f"# Get Auto Scaling Groups\naws autoscaling describe-auto-scaling-groups --region REGION",
                impact="Empty Auto Scaling Groups may indicate configuration issues preventing instances from launching, potentially affecting application availability.",
                recommendation="Investigate and fix the issues preventing instances from launching in these Auto Scaling Groups, or remove them if no longer needed."
            )
        
        if asgs_with_missing_ami:
            self.add_finding(
                name="[ASG] Launch Configuration referencing missing AMI",
                severity="High",
                description=f"The following Auto Scaling Groups have launch configurations referencing missing AMIs: {', '.join(asgs_with_missing_ami[:5])}" + 
                           (", and more..." if len(asgs_with_missing_ami) > 5 else ""),
                cli_command=f"# Get Launch Configurations\naws autoscaling describe-launch-configurations --region REGION",
                impact="Auto Scaling Groups with missing AMIs will fail to launch new instances, potentially affecting application availability during scaling events.",
                recommendation="Update the launch configurations to use valid AMIs that exist in your account."
            )
        
        if asgs_with_missing_sg:
            self.add_finding(
                name="[ASG] Launch Configuration referencing missing Security Group",
                severity="High",
                description=f"The following Auto Scaling Groups have launch configurations referencing missing Security Groups: {', '.join(asgs_with_missing_sg[:5])}" + 
                           (", and more..." if len(asgs_with_missing_sg) > 5 else ""),
                cli_command=f"# Get Launch Configurations\naws autoscaling describe-launch-configurations --region REGION",
                impact="Auto Scaling Groups with missing Security Groups will fail to launch new instances, affecting application availability during scaling events.",
                recommendation="Update the launch configurations to use valid Security Groups that exist in your account."
            )
        
        if unused_launch_configs:
            self.add_finding(
                name="[ASG] Unused Launch Configuration templates",
                severity="Low",
                description=f"The following Launch Configurations are not used by any Auto Scaling Group: {', '.join(unused_launch_configs[:5])}" + 
                           (", and more..." if len(unused_launch_configs) > 5 else ""),
                cli_command=f"# Get Launch Configurations\naws autoscaling describe-launch-configurations --region REGION",
                impact="Unused Launch Configurations consume resources and can lead to confusion and management complexity.",
                recommendation="Remove unused Launch Configurations to maintain a clean environment and avoid hitting service limits."
            )
            
        if not any([asgs_without_cooldown, asgs_without_notifications, app_tier_asgs_without_elb, 
                   empty_asgs, asgs_with_missing_ami, asgs_with_missing_sg, unused_launch_configs]):
            print("✅ Auto Scaling Groups are properly configured")

    def check_cloudfront_security(self):
        print("Checking CloudFront security configurations...")
        command = "aws cloudfront list-distributions"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list CloudFront distributions", "Unknown")
            return
        
        try:
            distributions = json.loads(response).get("DistributionList", {}).get("Items", [])
            insecure_distributions = []
            geo_restriction_missing = []
            waf_missing = []
            field_level_encryption_missing = []
            origin_access_identity_missing = []
            
            for distribution in distributions:
                dist_id = distribution["Id"]
                domain_name = distribution.get("DomainName", "Unknown")
                
                # Check HTTPS enforcement (this is already covered in check_cloudfront_https)
                if distribution.get("ViewerCertificate", {}).get("CloudFrontDefaultCertificate", False) or \
                   not distribution.get("ViewerCertificate", {}).get("Certificate") or \
                   distribution.get("ViewerCertificate", {}).get("MinimumProtocolVersion", "") == "SSLv3" or \
                   distribution.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy", "") != "https-only":
                    insecure_distributions.append(f"{domain_name} ({dist_id})")
                
                # Check for geo restrictions
                if not distribution.get("Restrictions", {}).get("GeoRestriction", {}).get("Quantity", 0) > 0:
                    geo_restriction_missing.append(f"{domain_name} ({dist_id})")
                
                # Check for WAF Web ACL association
                if not distribution.get("WebACLId"):
                    waf_missing.append(f"{domain_name} ({dist_id})")
                
                # Check for field-level encryption
                if distribution.get("DefaultCacheBehavior", {}).get("FieldLevelEncryptionId", "") == "":
                    field_level_encryption_missing.append(f"{domain_name} ({dist_id})")
                
                # Check S3 origins for OAI
                for origin in distribution.get("Origins", {}).get("Items", []):
                    if "s3.amazonaws.com" in origin.get("DomainName", ""):
                        if not origin.get("S3OriginConfig", {}).get("OriginAccessIdentity"):
                            origin_access_identity_missing.append(f"{domain_name} ({dist_id})")
            
            # Report findings
            if insecure_distributions:
                self.add_finding(
                    name="[CLOUDFRONT] HTTPS not enforced",
                    severity="High",
                    description=f"The following CloudFront distributions don't enforce HTTPS: {', '.join(insecure_distributions[:5])}" + 
                               (", and more..." if len(insecure_distributions) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="Without enforced HTTPS, your users' connections to your distribution may be subject to eavesdropping, tampering, and man-in-the-middle attacks.",
                    recommendation="1. Update the CloudFront distribution to use a valid SSL/TLS certificate\n2. Set the Viewer Protocol Policy to 'HTTPS Only' or 'Redirect HTTP to HTTPS'\n3. Set the Minimum Protocol Version to TLSv1.2_2019 or higher"
                )
            
            if geo_restriction_missing:
                self.add_finding(
                    name="[CLOUDFRONT] Geo-restriction not configured",
                    severity="Medium",
                    description=f"The following CloudFront distributions don't have geo-restrictions configured: {', '.join(geo_restriction_missing[:5])}" + 
                               (", and more..." if len(geo_restriction_missing) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="Without geo-restrictions, your content may be accessible from countries where you don't do business or from locations known for malicious activities.",
                    recommendation="Configure geo-restrictions for CloudFront distributions to limit access to your content from specific countries, especially if your services are only intended for specific regions."
                )
            
            if waf_missing:
                self.add_finding(
                    name="[CLOUDFRONT] WAF not enabled",
                    severity="Medium",
                    description=f"The following CloudFront distributions don't have AWS WAF enabled: {', '.join(waf_missing[:5])}" + 
                               (", and more..." if len(waf_missing) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="Without AWS WAF, your CloudFront distribution may be vulnerable to common web exploits that could affect application availability or security.",
                    recommendation="Enable AWS WAF for CloudFront distributions to protect against common web exploits like SQL injection, cross-site scripting (XSS), and other OWASP Top 10 vulnerabilities."
                )
            
            if field_level_encryption_missing:
                self.add_finding(
                    name="[CLOUDFRONT] Field-level encryption not configured",
                    severity="Low",
                    description=f"The following CloudFront distributions don't have field-level encryption configured: {', '.join(field_level_encryption_missing[:5])}" + 
                               (", and more..." if len(field_level_encryption_missing) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="Without field-level encryption, sensitive data like credit card numbers or social security numbers may be exposed during transit to your origin server.",
                    recommendation="Consider implementing field-level encryption for CloudFront distributions that handle sensitive data to ensure that this data is encrypted all the way to your application."
                )
            
            if origin_access_identity_missing:
                self.add_finding(
                    name="[CLOUDFRONT] S3 origin without Origin Access Identity",
                    severity="High",
                    description=f"The following CloudFront distributions with S3 origins don't use Origin Access Identity: {', '.join(origin_access_identity_missing[:5])}" + 
                               (", and more..." if len(origin_access_identity_missing) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="When S3 origins don't use Origin Access Identity, your S3 bucket might need to be publicly accessible, increasing the risk of unauthorized direct access to your content.",
                    recommendation="Configure Origin Access Identity for CloudFront distributions with S3 origins to ensure that content is only accessible through CloudFront and not directly from the S3 bucket."
                )
                
            if not any([insecure_distributions, geo_restriction_missing, waf_missing, 
                        field_level_encryption_missing, origin_access_identity_missing]):
                print("✅ All CloudFront distributions follow security best practices")
            
        except Exception as e:
            print(f"Error checking CloudFront security: {str(e)}")

    def check_iam_excessive_permissions(self):
        print("Checking for overly permissive IAM policies...")
        command = "aws iam list-policies --scope Local"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM policies", "Unknown")
            return
        
        policies = json.loads(response).get("Policies", [])
        overly_permissive_policies = []
        
        for policy in policies:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            
            version_command = f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {policy['DefaultVersionId']}"
            version_response = self.run_aws_command(version_command)
            
            if version_response:
                policy_doc = json.loads(version_response).get("PolicyVersion", {}).get("Document", {})
                
                # Check for admin-like privileges or wildcard permissions
                for statement in policy_doc.get("Statement", []):
                    effect = statement.get("Effect")
                    action = statement.get("Action", [])
                    resource = statement.get("Resource", [])
                    
                    # Convert to list if it's a string
                    if isinstance(action, str):
                        action = [action]
                    if isinstance(resource, str):
                        resource = [resource]
                    
                    # Check for wildcard actions with wildcard resources
                    if effect == "Allow" and ("*" in action or any("*" in a for a in action)) and \
                       ("*" in resource or any("*" in r for r in resource)):
                        overly_permissive_policies.append(f"{policy_name} ({policy_arn})")
                        break
        
        if overly_permissive_policies:
            self.add_finding(
                name="[IAM] Overly permissive policies",
                severity="Critical",
                description=f"The following IAM policies grant excessive permissions: {', '.join(overly_permissive_policies[:5])}" + 
                           (", and more..." if len(overly_permissive_policies) > 5 else ""),
                cli_command=f"# List policies\n{command}\n\n# Get policy details\n{version_command}",
                impact="Overly permissive policies violate the principle of least privilege and could allow unauthorized actions, potentially leading to data breaches, unauthorized access to resources, or account compromise.",
                recommendation="1. Review and restrict the permissions in these policies following the principle of least privilege\n2. Replace wildcard permissions with specific actions\n3. Implement resource constraints rather than allowing access to all resources\n4. Consider using AWS IAM Access Analyzer to identify unused permissions"
            )
        else:
            print("✅ No overly permissive IAM policies detected")

    def check_secrets_in_lambda(self):
        print("Checking for potential secrets in Lambda environment variables...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        lambdas_with_secrets = []
        
        # Patterns that might indicate secrets in environment variables
        secret_patterns = [
            r'key',
            r'secret',
            r'password',
            r'passwd',
            r'token',
            r'credential',
            r'api[-_]?key',
        ]
        
        for region in regions:
            lambda_command = f"aws lambda list-functions --region {region}"
            lambda_response = self.run_aws_command(lambda_command)
            
            if lambda_response:
                functions = json.loads(lambda_response).get("Functions", [])
                for function in functions:
                    function_name = function["FunctionName"]
                    env_vars = function.get("Environment", {}).get("Variables", {})
                    
                    for key, value in env_vars.items():
                        # Check if key matches any secret pattern
                        if any(re.search(pattern, key, re.IGNORECASE) for pattern in secret_patterns):
                            # Check if value looks like a secret (not a reference to a secure parameter store)
                            if not value.startswith("${") and not value.startswith("{{") and not value.startswith("arn:"):
                                lambdas_with_secrets.append(f"{function_name} ({region})")
                                break
        
        if lambdas_with_secrets:
            self.add_finding(
                name="[LAMBDA] Potential secrets in environment variables",
                severity="Critical",
                description=f"The following Lambda functions may have secrets directly in their environment variables: {', '.join(lambdas_with_secrets[:5])}" + 
                           (", and more..." if len(lambdas_with_secrets) > 5 else ""),
                cli_command=f"# List Lambda functions\naws lambda list-functions --region REGION\n\n# Get function configuration\naws lambda get-function-configuration --function-name FUNCTION_NAME --region REGION",
                impact="Hardcoded secrets in Lambda environment variables are accessible to anyone with Lambda function access and may be exposed in logs, increasing the risk of credential theft and unauthorized access.",
                recommendation="1. Replace hardcoded secrets with references to AWS Secrets Manager or Parameter Store\n2. Use IAM roles for Lambda function permissions instead of access keys\n3. Implement secret rotation\n4. Use environment variable encryption with KMS"
            )
        else:
            print("✅ No Lambda functions with potential secrets in environment variables detected")

    def check_rds_ssl_enforcement(self):
        print("Checking for RDS instances without SSL/TLS enforcement...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        non_ssl_instances = []
        non_ssl_clusters = []
        
        for region in regions:
            # Check RDS DB instances
            rds_command = f"aws rds describe-db-instances --region {region}"
            rds_response = self.run_aws_command(rds_command)
            
            if rds_response:
                instances = json.loads(rds_response).get("DBInstances", [])
                for instance in instances:
                    instance_id = instance["DBInstanceIdentifier"]
                    
                    # For PostgreSQL, check if rds.force_ssl parameter is enabled
                    if instance.get("Engine") == "postgres":
                        param_group = instance.get("DBParameterGroups", [{}])[0].get("DBParameterGroupName")
                        if param_group:
                            param_command = f"aws rds describe-db-parameters --db-parameter-group-name {param_group} --region {region}"
                            param_response = self.run_aws_command(param_command)
                            
                            if param_response:
                                parameters = json.loads(param_response).get("Parameters", [])
                                force_ssl_param = next((p for p in parameters if p.get("ParameterName") == "rds.force_ssl"), None)
                                
                                if not force_ssl_param or force_ssl_param.get("ParameterValue") != "1":
                                    non_ssl_instances.append(f"{instance_id} ({region})")
                    
                    # For MySQL, check if require_secure_transport is enabled
                    elif instance.get("Engine") in ["mysql", "mariadb"]:
                        param_group = instance.get("DBParameterGroups", [{}])[0].get("DBParameterGroupName")
                        if param_group:
                            param_command = f"aws rds describe-db-parameters --db-parameter-group-name {param_group} --region {region}"
                            param_response = self.run_aws_command(param_command)
                            
                            if param_response:
                                parameters = json.loads(param_response).get("Parameters", [])
                                require_ssl_param = next((p for p in parameters if p.get("ParameterName") == "require_secure_transport"), None)
                                
                                if not require_ssl_param or require_ssl_param.get("ParameterValue") != "ON":
                                    non_ssl_instances.append(f"{instance_id} ({region})")
            
            # Check Aurora clusters
            aurora_command = f"aws rds describe-db-clusters --region {region}"
            aurora_response = self.run_aws_command(aurora_command)
            
            if aurora_response:
                clusters = json.loads(aurora_response).get("DBClusters", [])
                for cluster in clusters:
                    cluster_id = cluster["DBClusterIdentifier"]
                    
                    # Check if IAM authentication is enabled
                    if not cluster.get("IAMDatabaseAuthenticationEnabled", False):
                        non_ssl_clusters.append(f"{cluster_id} ({region})")
        
        if non_ssl_instances:
            self.add_finding(
                name="[RDS] SSL/TLS not enforced for DB instances",
                severity="High",
                description=f"The following RDS DB instances do not enforce SSL/TLS connections: {', '.join(non_ssl_instances[:5])}" + 
                           (", and more..." if len(non_ssl_instances) > 5 else ""),
                cli_command=f"# List RDS instances\n{rds_command}\n\n# Check parameter group settings\n{param_command}",
                impact="Without enforced SSL/TLS connections, data transmitted between clients and the database is not encrypted, potentially exposing sensitive information to eavesdropping attacks.",
                recommendation="1. For PostgreSQL: Set 'rds.force_ssl' to 1 in the parameter group\n2. For MySQL/MariaDB: Set 'require_secure_transport' to ON\n3. Update application connection strings to use SSL\n4. Consider implementing certificate validation in clients"
            )
            
        if non_ssl_clusters:
            self.add_finding(
                name="[RDS] IAM authentication not enabled for DB clusters",
                severity="Medium",
                description=f"The following RDS DB clusters do not have IAM authentication enabled: {', '.join(non_ssl_clusters[:5])}" + 
                           (", and more..." if len(non_ssl_clusters) > 5 else ""),
                cli_command=f"# List RDS clusters\n{aurora_command}",
                impact="Without IAM authentication, you rely solely on database credentials for authentication rather than leveraging IAM roles and temporary credentials, potentially increasing the risk of credential mismanagement.",
                recommendation="1. Enable IAM database authentication for Aurora clusters\n2. Update applications to use IAM authentication\n3. Implement proper IAM policies to control database access\n4. Rotate database credentials regularly if IAM authentication cannot be enabled"
            )
            
        if not non_ssl_instances and not non_ssl_clusters:
            print("✅ All RDS instances/clusters have proper SSL/TLS enforcement")

    def check_sqs_encryption(self):
        print("Checking for SQS queues without encryption...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unencrypted_queues = []
        
        for region in regions:
            sqs_command = f"aws sqs list-queues --region {region}"
            sqs_response = self.run_aws_command(sqs_command)
            
            if sqs_response and "QueueUrls" in sqs_response:
                queues = json.loads(sqs_response).get("QueueUrls", [])
                for queue_url in queues:
                    attr_command = f"aws sqs get-queue-attributes --queue-url {queue_url} --attribute-names KmsMasterKeyId --region {region}"
                    attr_response = self.run_aws_command(attr_command)
                    
                    if attr_response:
                        attrs = json.loads(attr_response).get("Attributes", {})
                        if "KmsMasterKeyId" not in attrs:
                            queue_name = queue_url.split("/")[-1]
                            unencrypted_queues.append(f"{queue_name} ({region})")
        
        if unencrypted_queues:
            self.add_finding(
                name="[SQS] Queues not encrypted at rest",
                severity="Medium",
                description=f"The following SQS queues are not encrypted at rest with KMS: {', '.join(unencrypted_queues[:5])}" + 
                           (", and more..." if len(unencrypted_queues) > 5 else ""),
                cli_command=f"# List SQS queues\n{sqs_command}\n\n# Get queue attributes\n{attr_command}",
                impact="Unencrypted SQS queues may store sensitive message data in plaintext, potentially exposing it if unauthorized access to the underlying storage is obtained.",
                recommendation="1. Enable server-side encryption with KMS for all SQS queues\n2. Use customer managed KMS keys for stronger control over your encryption\n3. Implement appropriate key policies for your KMS keys\n4. Consider enabling AWS CloudTrail to monitor API calls related to your queues"
            )
        else:
            print("✅ All SQS queues are encrypted at rest")

    def check_elb_deletion_protection(self):
        print("Checking for ELBs without deletion protection...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unprotected_elbs = []
        
        for region in regions:
            elb_command = f"aws elbv2 describe-load-balancers --region {region}"
            elb_response = self.run_aws_command(elb_command)
            
            if elb_response:
                load_balancers = json.loads(elb_response).get("LoadBalancers", [])
                for elb in load_balancers:
                    elb_arn = elb["LoadBalancerArn"]
                    elb_name = elb["LoadBalancerName"]
                    
                    # Check if deletion protection is enabled
                    attr_command = f"aws elbv2 describe-load-balancer-attributes --load-balancer-arn {elb_arn} --region {region}"
                    attr_response = self.run_aws_command(attr_command)
                    
                    if attr_response:
                        attributes = json.loads(attr_response).get("Attributes", [])
                        deletion_protection = next((attr for attr in attributes if attr.get("Key") == "deletion_protection.enabled"), None)
                        
                        if not deletion_protection or deletion_protection.get("Value") != "true":
                            unprotected_elbs.append(f"{elb_name} ({region})")
        
        if unprotected_elbs:
            self.add_finding(
                name="[ELB] Deletion protection not enabled",
                severity="Low",
                description=f"The following load balancers do not have deletion protection enabled: {', '.join(unprotected_elbs[:5])}" + 
                           (", and more..." if len(unprotected_elbs) > 5 else ""),
                cli_command=f"# List load balancers\n{elb_command}\n\n# Get load balancer attributes\n{attr_command}",
                impact="Without deletion protection, load balancers could be accidentally deleted, potentially causing service outages and disruption to your applications.",
                recommendation="1. Enable deletion protection for all production load balancers\n2. Use Infrastructure as Code tools to manage load balancer configurations\n3. Implement proper change management processes for infrastructure changes"
            )
        else:
            print("✅ All load balancers have deletion protection enabled")

    def check_rds_deletion_protection(self):
        print("Checking for RDS instances without deletion protection...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unprotected_instances = []
        unprotected_clusters = []
        
        for region in regions:
            # Check RDS instances
            rds_command = f"aws rds describe-db-instances --region {region}"
            rds_response = self.run_aws_command(rds_command)
            
            if rds_response:
                instances = json.loads(rds_response).get("DBInstances", [])
                for instance in instances:
                    instance_id = instance["DBInstanceIdentifier"]
                    
                    # Check if deletion protection is enabled
                    if not instance.get("DeletionProtection", False):
                        unprotected_instances.append(f"{instance_id} ({region})")
            
            # Check Aurora clusters
            aurora_command = f"aws rds describe-db-clusters --region {region}"
            aurora_response = self.run_aws_command(aurora_command)
            
            if aurora_response:
                clusters = json.loads(aurora_response).get("DBClusters", [])
                for cluster in clusters:
                    cluster_id = cluster["DBClusterIdentifier"]
                    
                    # Check if deletion protection is enabled
                    if not cluster.get("DeletionProtection", False):
                        unprotected_clusters.append(f"{cluster_id} ({region})")
        
        if unprotected_instances:
            self.add_finding(
                name="[RDS] Deletion protection not enabled for DB instances",
                severity="Medium",
                description=f"The following RDS DB instances do not have deletion protection enabled: {', '.join(unprotected_instances[:5])}" + 
                           (", and more..." if len(unprotected_instances) > 5 else ""),
                cli_command=f"# List RDS instances\n{rds_command}",
                impact="Without deletion protection, database instances could be accidentally deleted, potentially resulting in data loss and service outages.",
                recommendation="1. Enable deletion protection for all production database instances\n2. Implement backup strategies including automated snapshots\n3. Use infrastructure as code to manage RDS configurations\n4. Establish change management processes for database changes"
            )
            
        if unprotected_clusters:
            self.add_finding(
                name="[RDS] Deletion protection not enabled for DB clusters",
                severity="Medium",
                description=f"The following RDS DB clusters do not have deletion protection enabled: {', '.join(unprotected_clusters[:5])}" + 
                           (", and more..." if len(unprotected_clusters) > 5 else ""),
                cli_command=f"# List RDS clusters\n{aurora_command}",
                impact="Without deletion protection, database clusters could be accidentally deleted, potentially resulting in data loss and service outages.",
                recommendation="1. Enable deletion protection for all production database clusters\n2. Implement backup strategies including automated snapshots\n3. Use infrastructure as code to manage RDS configurations\n4. Establish change management processes for database changes"
            )
            
        if not unprotected_instances and not unprotected_clusters:
            print("✅ All RDS instances and clusters have deletion protection enabled")

    def check_inactive_admin_users(self):
        print("Checking for inactive admin users...")
        command = "aws iam list-users"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM users", "Unknown")
            return
        
        users = json.loads(response).get("Users", [])
        inactive_admin_users = []
        
        for user in users:
            username = user["UserName"]
            
            # Check last activity
            password_last_used = user.get("PasswordLastUsed", None)
            access_key_command = f"aws iam list-access-keys --user-name {username}"
            access_key_response = self.run_aws_command(access_key_command)
            
            inactive_days = 90  # Consider user inactive if no activity for 90 days
            is_inactive = True
            
            # Check password activity
            if password_last_used:
                last_used_date = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                days_since_use = (datetime.now(timezone.utc) - last_used_date).days
                if days_since_use < inactive_days:
                    is_inactive = False
            
            # Check access key activity
            if access_key_response:
                keys = json.loads(access_key_response).get("AccessKeyMetadata", [])
                for key in keys:
                    key_id = key["AccessKeyId"]
                    last_used_command = f"aws iam get-access-key-last-used --access-key-id {key_id}"
                    last_used_response = self.run_aws_command(last_used_command)
                    
                    if last_used_response:
                        key_last_used = json.loads(last_used_response).get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        if key_last_used:
                            last_used_date = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
                            days_since_use = (datetime.now(timezone.utc) - last_used_date).days
                            if days_since_use < inactive_days:
                                is_inactive = False
            
            # If the user appears inactive, check if they have admin access
            if is_inactive:
                # Check attached policies
                policies_command = f"aws iam list-attached-user-policies --user-name {username}"
                policies_response = self.run_aws_command(policies_command)
                
                has_admin_access = False
                if policies_response:
                    policies = json.loads(policies_response).get("AttachedPolicies", [])
                    for policy in policies:
                        if policy["PolicyName"] in ["AdministratorAccess", "PowerUserAccess"] or "admin" in policy["PolicyName"].lower():
                            has_admin_access = True
                            break
                
                # Check group memberships for admin access
                groups_command = f"aws iam list-groups-for-user --user-name {username}"
                groups_response = self.run_aws_command(groups_command)
                
                if groups_response:
                    groups = json.loads(groups_response).get("Groups", [])
                    for group in groups:
                        group_name = group["GroupName"]
                        group_policies_command = f"aws iam list-attached-group-policies --group-name {group_name}"
                        group_policies_response = self.run_aws_command(group_policies_command)
                        
                        if group_policies_response:
                            group_policies = json.loads(group_policies_response).get("AttachedPolicies", [])
                            for policy in group_policies:
                                if policy["PolicyName"] in ["AdministratorAccess", "PowerUserAccess"] or "admin" in policy["PolicyName"].lower():
                                    has_admin_access = True
                                    break
                
                # Check MFA
                mfa_command = f"aws iam list-mfa-devices --user-name {username}"
                mfa_response = self.run_aws_command(mfa_command)
                has_mfa = mfa_response and len(json.loads(mfa_response).get("MFADevices", [])) > 0
                
                if has_admin_access and not has_mfa:
                    inactive_admin_users.append(f"{username} (inactive {inactive_days}+ days with admin access, no MFA)")
        
        if inactive_admin_users:
            self.add_finding(
                name="[IAM] Inactive users with administrative access and no MFA",
                severity="Critical",
                description=f"The following IAM users appear inactive but have administrator access and no MFA enabled: {', '.join(inactive_admin_users[:5])}" + 
                           (", and more..." if len(inactive_admin_users) > 5 else ""),
                cli_command=f"# List IAM users\n{command}\n\n# Check user policies\naws iam list-attached-user-policies --user-name USERNAME\n\n# Check MFA devices\naws iam list-mfa-devices --user-name USERNAME",
                impact="Inactive administrator accounts without MFA represent a significant security risk. If compromised, these accounts could be used for unauthorized administrative actions without detection.",
                recommendation="1. Remove administrator access from inactive accounts\n2. Enable MFA for all accounts with administrative access\n3. Implement a regular user access review process\n4. Consider deleting or disabling inactive user accounts"
            )
        else:
            print("✅ No inactive users with administrative access detected")

    def check_hardware_mfa(self):
        print("Checking for hardware MFA for privileged users...")
        command = "aws iam list-users"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM users", "Unknown")
            return
        
        users = json.loads(response).get("Users", [])
        privileged_without_hardware_mfa = []
        users_without_mfa = []
        
        for user in users:
            username = user["UserName"]
            
            # Check if user has administrative access
            is_privileged = False
            
            # Check attached policies
            policies_command = f"aws iam list-attached-user-policies --user-name {username}"
            policies_response = self.run_aws_command(policies_command)
            
            if policies_response:
                policies = json.loads(policies_response).get("AttachedPolicies", [])
                for policy in policies:
                    if policy["PolicyName"] in ["AdministratorAccess", "PowerUserAccess"] or "admin" in policy["PolicyName"].lower():
                        is_privileged = True
                        break
            
            # Check group memberships for admin access
            if not is_privileged:
                groups_command = f"aws iam list-groups-for-user --user-name {username}"
                groups_response = self.run_aws_command(groups_command)
                
                if groups_response:
                    groups = json.loads(groups_response).get("Groups", [])
                    for group in groups:
                        group_name = group["GroupName"]
                        group_policies_command = f"aws iam list-attached-group-policies --group-name {group_name}"
                        group_policies_response = self.run_aws_command(group_policies_command)
                        
                        if group_policies_response:
                            group_policies = json.loads(group_policies_response).get("AttachedPolicies", [])
                            for policy in group_policies:
                                if policy["PolicyName"] in ["AdministratorAccess", "PowerUserAccess"] or "admin" in policy["PolicyName"].lower():
                                    is_privileged = True
                                    break
                        
                        if is_privileged:
                            break
            
            # Check MFA devices
            mfa_command = f"aws iam list-mfa-devices --user-name {username}"
            mfa_response = self.run_aws_command(mfa_command)
            
            if mfa_response:
                mfa_devices = json.loads(mfa_response).get("MFADevices", [])
                has_mfa = len(mfa_devices) > 0
                
                if not has_mfa:
                    users_without_mfa.append(username)
                elif is_privileged:
                    # Check for hardware MFA (device serial number starts with "arn:aws:iam")
                    has_hardware_mfa = False
                    for device in mfa_devices:
                        # Hardware MFA typically have serial numbers not starting with "arn:aws:iam"
                        if not device.get("SerialNumber", "").startswith("arn:aws:iam"):
                            has_hardware_mfa = True
                            break
                    
                    if not has_hardware_mfa:
                        privileged_without_hardware_mfa.append(username)
        
        if privileged_without_hardware_mfa:
            self.add_finding(
                name="[IAM] Privileged users without hardware MFA",
                severity="High",
                description=f"The following privileged users are using virtual MFA instead of hardware MFA: {', '.join(privileged_without_hardware_mfa[:5])}" + 
                           (", and more..." if len(privileged_without_hardware_mfa) > 5 else ""),
                cli_command=f"# List MFA devices\naws iam list-mfa-devices --user-name USERNAME",
                impact="Virtual MFA devices can be compromised more easily than hardware MFA devices if the device hosting the virtual MFA is stolen, lost, or compromised.",
                recommendation="1. Provide hardware MFA devices for all privileged users\n2. Enforce a policy requiring hardware MFA for administrative access\n3. Configure CloudTrail alerting for logins without hardware MFA from privileged accounts"
            )
        
        if users_without_mfa:
            self.add_finding(
                name="[IAM] Users without MFA enabled",
                severity="High",
                description=f"The following IAM users do not have MFA enabled: {', '.join(users_without_mfa[:5])}" + 
                           (", and more..." if len(users_without_mfa) > 5 else ""),
                cli_command=f"# List MFA devices\naws iam list-mfa-devices --user-name USERNAME",
                impact="Without MFA, accounts are vulnerable to password-based attacks, significantly increasing the risk of unauthorized access.",
                recommendation="1. Enable MFA for all IAM users\n2. Implement a policy requiring MFA for all users\n3. Consider using IAM conditions to deny access to users not authenticated with MFA"
            )
        
        # Root account MFA check
        root_credentials_command = "aws iam get-account-summary"
        root_response = self.run_aws_command(root_credentials_command)
        
        if root_response:
            account_summary = json.loads(root_response).get("SummaryMap", {})
            if account_summary.get("AccountMFAEnabled", 0) == 1:
                # Additional check for hardware MFA for root
                root_mfa_command = "aws iam list-virtual-mfa-devices --assignment-status Assigned"
                root_mfa_response = self.run_aws_command(root_mfa_command)
                
                if root_mfa_response:
                    devices = json.loads(root_mfa_response).get("VirtualMFADevices", [])
                    root_using_virtual_mfa = False
                    
                    for device in devices:
                        if device.get("User", {}).get("UserName") == "root":
                            root_using_virtual_mfa = True
                            break
                    
                    if root_using_virtual_mfa:
                        self.add_finding(
                            name="[IAM] Root account using virtual MFA instead of hardware MFA",
                            severity="High",
                            description="The AWS root account is protected with a virtual MFA device instead of a hardware MFA device.",
                            cli_command=f"# Check MFA status\n{root_mfa_command}",
                            impact="Virtual MFA devices for the root account are less secure as they can be compromised if the device hosting the virtual MFA is stolen or compromised.",
                            recommendation="1. Purchase a hardware MFA device\n2. Add the hardware MFA device to the root account\n3. Remove the virtual MFA device after confirming the hardware MFA works"
                        )
                    else:
                        print("✅ Root account is protected with hardware MFA")
            else:
                # This should already be caught by check_root_mfa, but adding here for completeness
                self.add_finding(
                    name="[IAM] Root account without MFA",
                    severity="Critical",
                    description="The AWS root account does not have any MFA device enabled.",
                    cli_command=root_credentials_command,
                    impact="Without MFA, the root account is vulnerable to password-based attacks. Compromise of the root account would give attackers complete control over your AWS account with no restrictions.",
                    recommendation="1. Enable hardware MFA for the root account immediately\n2. Purchase at least two hardware MFA devices (for redundancy)\n3. Store the backup hardware MFA device in a secure, separate location\n4. Limit the use of the root account for only the tasks that explicitly require it"
                )
        else:
            self.add_issue("Unable to check root account MFA status", "Unknown")

    def check_sensitive_files_in_s3(self):
        print("Checking for sensitive files in S3 buckets...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        buckets_with_sensitive_files = []
        
        sensitive_patterns = [
            ".env",
            "credentials",
            "password",
            "secret",
            "config.json",
            "connection.json",
            "apikey",
            "id_rsa",
            ".pem",
            "oauth"
        ]
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            # List objects in the bucket
            objects_command = f"aws s3api list-objects-v2 --bucket {bucket_name} --max-items 1000"
            objects_response = self.run_aws_command(objects_command)
            
            if objects_response:
                try:
                    objects = json.loads(objects_response).get("Contents", [])
                    sensitive_files = []
                    
                    for obj in objects:
                        key = obj["Key"]
                        
                        # Check if the file matches sensitive patterns
                        for pattern in sensitive_patterns:
                            if pattern in key.lower():
                                sensitive_files.append(key)
                                break
                    
                    if sensitive_files:
                        file_examples = ", ".join(sensitive_files[:3])
                        buckets_with_sensitive_files.append(f"{bucket_name} ({file_examples}{' and more...' if len(sensitive_files) > 3 else ''})")
                except Exception as e:
                    print(f"Error checking files in bucket {bucket_name}: {str(e)}")
        
        if buckets_with_sensitive_files:
            self.add_finding(
                name="[S3] Sensitive files detected in S3 buckets",
                severity="Critical",
                description=f"The following buckets contain potentially sensitive files like .env, credentials, or key files: {', '.join(buckets_with_sensitive_files[:5])}" + 
                           (", and more..." if len(buckets_with_sensitive_files) > 5 else ""),
                cli_command=f"# List objects in bucket\naws s3api list-objects-v2 --bucket BUCKET_NAME --max-items 1000",
                impact="Sensitive files such as .env files, credential files, or key files in S3 buckets could expose secrets, passwords, or API keys, especially if the bucket has insecure access policies.",
                recommendation="1. Remove sensitive files from S3 buckets\n2. Store secrets in AWS Secrets Manager or Parameter Store\n3. Review bucket access policies\n4. Implement a process to scan for and prevent uploading of sensitive files to S3"
            )
        else:
            print("✅ No sensitive files detected in S3 buckets")
            
    def check_cloudwatch_logs_encryption(self):
        print("Checking for CloudWatch Logs encryption...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unencrypted_log_groups = []
        
        for region in regions:
            log_groups_command = f"aws logs describe-log-groups --region {region}"
            log_groups_response = self.run_aws_command(log_groups_command)
            
            if log_groups_response:
                log_groups = json.loads(log_groups_response).get("logGroups", [])
                
                for log_group in log_groups:
                    log_group_name = log_group["logGroupName"]
                    
                    # Check if log group is encrypted with KMS
                    if "kmsKeyId" not in log_group:
                        unencrypted_log_groups.append(f"{log_group_name} ({region})")
        
        if unencrypted_log_groups:
            self.add_finding(
                name="[CloudWatch] Log groups without at-rest encryption",
                severity="Medium",
                description=f"The following CloudWatch Log groups are not encrypted at rest: {', '.join(unencrypted_log_groups[:5])}" + 
                           (", and more..." if len(unencrypted_log_groups) > 5 else ""),
                cli_command=f"# List log groups\n{log_groups_command}",
                impact="Unencrypted CloudWatch Log groups may contain sensitive data that could be exposed if the underlying storage is compromised. This could violate compliance requirements.",
                recommendation="1. Configure KMS encryption for CloudWatch Logs groups\n2. Use a customer managed KMS key for stronger control\n3. Update log group configurations using AWS CLI or CloudFormation\n4. Implement a policy requiring encryption for new log groups"
            )
        else:
            print("✅ All CloudWatch Log groups are encrypted at rest")
    
    def check_ec2_detailed_monitoring(self):
        print("Checking for EC2 detailed monitoring...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        instances_without_detailed_monitoring = []
        
        for region in regions:
            instances_command = f"aws ec2 describe-instances --region {region}"
            instances_response = self.run_aws_command(instances_command)
            
            if instances_response:
                reservations = json.loads(instances_response).get("Reservations", [])
                
                for reservation in reservations:
                    for instance in reservation.get("Instances", []):
                        instance_id = instance["InstanceId"]
                        monitoring = instance.get("Monitoring", {})
                        
                        if monitoring.get("State") != "enabled":
                            # Get instance name if available
                            instance_name = "Unnamed"
                            for tag in instance.get("Tags", []):
                                if tag["Key"] == "Name":
                                    instance_name = tag["Value"]
                                    break
                            
                            instances_without_detailed_monitoring.append(f"{instance_id} ({instance_name}, {region})")
        
        if instances_without_detailed_monitoring:
            self.add_finding(
                name="[EC2] Detailed monitoring not enabled",
                severity="Low",
                description=f"The following EC2 instances do not have detailed monitoring enabled: {', '.join(instances_without_detailed_monitoring[:5])}" + 
                           (", and more..." if len(instances_without_detailed_monitoring) > 5 else ""),
                cli_command=f"# List instances\n{instances_command}\n\n# Enable detailed monitoring\naws ec2 monitor-instances --instance-ids INSTANCE_ID --region REGION",
                impact="Without detailed monitoring, CloudWatch metrics are collected at 5-minute intervals instead of 1-minute intervals, reducing your ability to quickly detect and respond to performance issues or security incidents.",
                recommendation="1. Enable detailed monitoring for production EC2 instances\n2. Configure appropriate CloudWatch alarms with detailed metrics\n3. Consider using AWS Organizations to enforce detailed monitoring for critical workloads"
            )
        else:
            print("✅ All EC2 instances have detailed monitoring enabled")

    def check_security_hub(self):
        print("Checking AWS Security Hub status...")
        command = "aws securityhub describe-hub"
        response = self.run_aws_command(command)
        
        if not response or "HubArn" not in response:
            self.add_finding(
                name="[Transversal] AWS Security Hub not enabled",
                severity="High",
                description="AWS Security Hub is not enabled for this account. Security Hub provides a comprehensive view of your security posture across AWS accounts.",
                cli_command=command,
                impact="Without Security Hub, you lack centralized security findings, automated compliance checks, and integrated insights from AWS security services, hindering your ability to detect and respond to security threats.",
                recommendation="1. Enable AWS Security Hub in all regions\n2. Configure integration with other AWS security services like GuardDuty and IAM Access Analyzer\n3. Set up organizational Security Hub management if using AWS Organizations\n4. Configure automated remediation for critical findings"
            )
        else:
            # Check if Security Hub is enabled at the organization level
            org_command = "aws organizations describe-organization"
            org_response = self.run_aws_command(org_command)
            
            if org_response and "Organization" in org_response:
                admin_command = "aws securityhub get-administrator-account"
                admin_response = self.run_aws_command(admin_command)
                
                if not admin_response or "AdminstratorAccount" not in admin_response:
                    self.add_finding(
                        name="[Transversal] Security Hub not enabled at organization level",
                        severity="Medium",
                        description="AWS Security Hub is enabled but not configured at the organization level for centralized management.",
                        cli_command=f"{command}\n{admin_command}",
                        impact="Without organization-level Security Hub, you may have inconsistent security findings across your AWS organization and lack a unified view of your security posture.",
                        recommendation="1. Designate a delegated Security Hub administrator account\n2. Enable Security Hub in all member accounts\n3. Configure centralized findings and automated responses\n4. Implement organizational security standards"
                    )
                else:
                    print("✅ AWS Security Hub is properly configured at the organization level")
            else:
                print("✅ AWS Security Hub is enabled")
                
    def check_s3_mfa_delete(self):
        print("Checking for S3 MFA Delete...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        buckets_without_mfa_delete = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            versioning_command = f"aws s3api get-bucket-versioning --bucket {bucket_name}"
            versioning_response = self.run_aws_command(versioning_command)
            
            if versioning_response:
                versioning = json.loads(versioning_response) if versioning_response.strip() else {}
                
                # Check if versioning is enabled and MFA Delete is configured
                if versioning.get("Status") == "Enabled" and versioning.get("MFADelete") != "Enabled":
                    buckets_without_mfa_delete.append(bucket_name)
        
        if buckets_without_mfa_delete:
            self.add_finding(
                name="[S3] MFA Delete not enabled for versioned buckets",
                severity="Medium",
                description=f"The following S3 buckets have versioning enabled but MFA Delete is not configured: {', '.join(buckets_without_mfa_delete[:5])}" + 
                           (", and more..." if len(buckets_without_mfa_delete) > 5 else ""),
                cli_command=f"# Check bucket versioning\naws s3api get-bucket-versioning --bucket BUCKET_NAME",
                impact="Without MFA Delete, versioned objects can be permanently deleted without the additional security of multi-factor authentication, increasing the risk of accidental or malicious deletion.",
                recommendation="1. Enable MFA Delete for critical S3 buckets\n2. Configure an MFA device for the root account\n3. Use the s3api put-bucket-versioning command with the --mfa option\n4. Implement proper IAM policies to restrict who can modify bucket versioning"
            )
        else:
            print("✅ All versioned S3 buckets have appropriate MFA Delete configuration")
            
    def check_organization_scps(self):
        print("Checking AWS Organizations SCPs...")
        command = "aws organizations describe-organization"
        response = self.run_aws_command(command)
        
        if not response or "Organization" not in response:
            # Skip if not using AWS Organizations
            return
        
        # Check if SCPs are enabled
        org_data = json.loads(response).get("Organization", {})
        org_id = org_data.get("Id")
        
        if org_id:
            # Check available policy types
            policy_types_command = f"aws organizations list-roots"
            policy_types_response = self.run_aws_command(policy_types_command)
            
            if policy_types_response:
                roots = json.loads(policy_types_response).get("Roots", [])
                
                if roots:
                    policy_types = roots[0].get("PolicyTypes", [])
                    scp_enabled = any(pt.get("Type") == "SERVICE_CONTROL_POLICY" and pt.get("Status") == "ENABLED" for pt in policy_types)
                    
                    if not scp_enabled:
                        self.add_finding(
                            name="[Org] Service Control Policies (SCPs) disabled",
                            severity="Medium",
                            description=f"Service Control Policies are not enabled in your AWS Organization {org_id}.",
                            cli_command=policy_types_command,
                            impact="Without SCPs, you cannot enforce preventative security guardrails across your organization, making it harder to ensure consistent security controls.",
                            recommendation="1. Enable Service Control Policies in your AWS Organization\n2. Implement baseline SCPs for security guardrails\n3. Apply SCPs to restrict high-risk actions\n4. Create a deny-list SCP for root actions"
                        )
                    else:
                        # Check if member accounts can leave organization
                        policies_command = f"aws organizations list-policies --filter SERVICE_CONTROL_POLICY"
                        policies_response = self.run_aws_command(policies_command)
                        
                        if policies_response:
                            policies = json.loads(policies_response).get("Policies", [])
                            leave_org_prevention_found = False
                            
                            for policy in policies:
                                policy_id = policy.get("Id")
                                policy_detail_command = f"aws organizations describe-policy --policy-id {policy_id}"
                                policy_detail_response = self.run_aws_command(policy_detail_command)
                                
                                if policy_detail_response and "Content" in policy_detail_response:
                                    policy_content = json.loads(policy_detail_response).get("Policy", {}).get("Content", "{}")
                                    
                                    try:
                                        policy_json = json.loads(policy_content)
                                        statements = policy_json.get("Statement", [])
                                        
                                        for statement in statements:
                                            if statement.get("Effect") == "Deny" and "organizations:LeaveOrganization" in statement.get("Action", []):
                                                leave_org_prevention_found = True
                                                break
                                        
                                        if leave_org_prevention_found:
                                            break
                                    except:
                                        continue
                            
                            if not leave_org_prevention_found:
                                self.add_finding(
                                    name="[Org] Missing SCP to restrict accounts from leaving organization",
                                    severity="Medium",
                                    description=f"No SCP found to prevent member accounts from leaving the AWS Organization {org_id}.",
                                    cli_command=policies_command,
                                    impact="Without this restriction, member accounts could leave the organization without approval, bypassing centralized security controls and potentially exposing the organization to security risks.",
                                    recommendation="1. Implement an SCP that denies the organizations:LeaveOrganization action\n2. Apply this SCP to all accounts except the management account\n3. Monitor for attempts to leave the organization\n4. Create a controlled process for account removal when necessary"
                                )
                            else:
                                print("✅ AWS Organizations has SCP to prevent accounts from leaving")
                        
                        # Check if all regions are allowed
                        region_restriction_found = False
                        
                        for policy in policies:
                            policy_id = policy.get("Id")
                            policy_detail_command = f"aws organizations describe-policy --policy-id {policy_id}"
                            policy_detail_response = self.run_aws_command(policy_detail_command)
                            
                            if policy_detail_response and "Content" in policy_detail_response:
                                policy_content = json.loads(policy_detail_response).get("Policy", {}).get("Content", "{}")
                                
                                try:
                                    policy_json = json.loads(policy_content)
                                    statements = policy_json.get("Statement", [])
                                    
                                    for statement in statements:
                                        if "Condition" in statement and "StringNotEquals" in statement.get("Condition", {}) and "aws:RequestedRegion" in statement.get("Condition", {}).get("StringNotEquals", {}):
                                            region_restriction_found = True
                                            break
                                    
                                    if region_restriction_found:
                                        break
                                except:
                                    continue
                        
                        if not region_restriction_found:
                            self.add_finding(
                                name="[Org] Unrestricted AWS regions in SCPs",
                                severity="Low",
                                description=f"No SCP found to restrict AWS regions in the organization {org_id}.",
                                cli_command=policies_command,
                                impact="Without region restrictions, resources can be deployed in any AWS region, potentially increasing your attack surface and complicating compliance efforts for regulated industries.",
                                recommendation="1. Implement an SCP that restricts operations to only required AWS regions\n2. Use the 'aws:RequestedRegion' condition key in your SCPs\n3. Consider different regional restrictions for different OUs based on business needs\n4. Monitor for attempts to use denied regions"
                            )
                        else:
                            print("✅ AWS Organizations has SCP to restrict regions")
        else:
            print("✅ AWS Organizations SCPs are properly configured")

    def check_privileged_users_without_mfa(self):
        print("Checking for privileged users without MFA...")
        command = "aws iam list-users"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM users", "Unknown")
            return
        
        users = json.loads(response).get("Users", [])
        privileged_without_mfa = []
        
        for user in users:
            username = user["UserName"]
            
            # Check if user has MFA enabled
            mfa_command = f"aws iam list-mfa-devices --user-name {username}"
            mfa_response = self.run_aws_command(mfa_command)
            has_mfa = mfa_response and len(json.loads(mfa_response).get("MFADevices", [])) > 0
            
            if not has_mfa:
                # Check for administrative access via groups
                groups_command = f"aws iam list-groups-for-user --user-name {username}"
                groups_response = self.run_aws_command(groups_command)
                
                is_privileged = False
                admin_groups = []
                
                if groups_response:
                    groups = json.loads(groups_response).get("Groups", [])
                    for group in groups:
                        group_name = group["GroupName"]
                        
                        # Check group policies
                        group_policies_command = f"aws iam list-attached-group-policies --group-name {group_name}"
                        group_policies_response = self.run_aws_command(group_policies_command)
                        
                        if group_policies_response:
                            policies = json.loads(group_policies_response).get("AttachedPolicies", [])
                            for policy in policies:
                                policy_name = policy["PolicyName"]
                                if policy_name in ["AdministratorAccess", "PowerUserAccess"] or "admin" in policy_name.lower():
                                    is_privileged = True
                                    admin_groups.append(group_name)
                                    break
                
                # Also check directly attached policies
                policies_command = f"aws iam list-attached-user-policies --user-name {username}"
                policies_response = self.run_aws_command(policies_command)
                
                admin_policies = []
                if policies_response:
                    policies = json.loads(policies_response).get("AttachedPolicies", [])
                    for policy in policies:
                        policy_name = policy["PolicyName"]
                        if policy_name in ["AdministratorAccess", "PowerUserAccess"] or "admin" in policy_name.lower():
                            is_privileged = True
                            admin_policies.append(policy_name)
                
                if is_privileged:
                    privileged_info = f"{username} (Groups: {', '.join(admin_groups) if admin_groups else 'None'}"
                    if admin_policies:
                        privileged_info += f", Policies: {', '.join(admin_policies)}"
                    privileged_info += ")"
                    privileged_without_mfa.append(privileged_info)
        
        if privileged_without_mfa:
            self.add_finding(
                name="[IAM] Privileged users without MFA",
                severity="Critical",
                description=f"The following privileged users do not have MFA enabled: {', '.join(privileged_without_mfa[:5])}" + 
                           (", and more..." if len(privileged_without_mfa) > 5 else ""),
                cli_command=f"# List users\n{command}\n\n# Check MFA status\naws iam list-mfa-devices --user-name USERNAME",
                impact="Privileged users without MFA are at high risk of account compromise. If their password is compromised, attackers would have full administrative access to your AWS account.",
                recommendation="1. Enforce MFA for all privileged users immediately\n2. Implement a policy that requires MFA for all administrative actions\n3. Consider using AWS IAM Access Analyzer to audit permissions\n4. Use SCPs in AWS Organizations to enforce MFA"
            )
        else:
            print("✅ All privileged users have MFA enabled")

    def check_eks_cluster_security(self):
        print("Checking EKS cluster security...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        public_endpoint_clusters = []
        no_encryption_clusters = []
        unpatched_clusters = []
        
        for region in regions:
            eks_command = f"aws eks list-clusters --region {region}"
            eks_response = self.run_aws_command(eks_command)
            
            if not eks_response:
                continue
                
            clusters = json.loads(eks_response).get("clusters", [])
            
            for cluster_name in clusters:
                describe_command = f"aws eks describe-cluster --name {cluster_name} --region {region}"
                describe_response = self.run_aws_command(describe_command)
                
                if not describe_response:
                    continue
                
                cluster = json.loads(describe_response).get("cluster", {})
                
                # Check for public endpoint access
                resources_vpc_config = cluster.get("resourcesVpcConfig", {})
                if resources_vpc_config.get("endpointPublicAccess", False) and not resources_vpc_config.get("publicAccessCidrs", ["0.0.0.0/0"]) != ["0.0.0.0/0"]:
                    public_endpoint_clusters.append(f"{cluster_name} ({region})")
                
                # Check for encryption
                encryption_config = cluster.get("encryptionConfig", [])
                if not encryption_config:
                    no_encryption_clusters.append(f"{cluster_name} ({region})")
                
                # Check for outdated Kubernetes version
                version = cluster.get("version", "")
                if version and version.startswith(("1.20.", "1.21.", "1.22.", "1.23.")):
                    unpatched_clusters.append(f"{cluster_name} ({region}, version {version})")
        
        if public_endpoint_clusters:
            self.add_finding(
                name="[EKS] Cluster API endpoint publicly accessible",
                severity="High",
                description=f"The following EKS clusters have publicly accessible API endpoints without CIDR restrictions: {', '.join(public_endpoint_clusters[:5])}" + 
                           (", and more..." if len(public_endpoint_clusters) > 5 else ""),
                cli_command=f"# Describe EKS cluster\naws eks describe-cluster --name CLUSTER_NAME --region REGION",
                impact="Public API endpoints expose your Kubernetes control plane to the internet, increasing the risk of unauthorized access and potential attacks against the Kubernetes API server.",
                recommendation="1. Disable public endpoint access and use only private endpoints if possible\n2. If public access is required, restrict access to specific IP ranges using publicAccessCidrs\n3. Ensure strong authentication and authorization controls\n4. Enable CloudTrail logging for EKS API calls"
            )
        
        if no_encryption_clusters:
            self.add_finding(
                name="[EKS] Cluster secrets not encrypted with KMS",
                severity="Medium",
                description=f"The following EKS clusters do not have encryption config enabled: {', '.join(no_encryption_clusters[:5])}" + 
                           (", and more..." if len(no_encryption_clusters) > 5 else ""),
                cli_command=f"# Describe EKS cluster\naws eks describe-cluster --name CLUSTER_NAME --region REGION",
                impact="Without KMS encryption, secrets stored in etcd (including service account tokens, ConfigMaps, and Secrets) are encrypted using the default AWS managed keys rather than your own KMS keys.",
                recommendation="1. Create a new EKS cluster with encryption configuration enabled\n2. Use customer-managed KMS keys for stronger control\n3. For existing clusters, you may need to migrate to new clusters as encryption cannot be enabled after creation"
            )
        
        if unpatched_clusters:
            self.add_finding(
                name="[EKS] Cluster running outdated Kubernetes version",
                severity="High",
                description=f"The following EKS clusters are running outdated Kubernetes versions: {', '.join(unpatched_clusters[:5])}" + 
                           (", and more..." if len(unpatched_clusters) > 5 else ""),
                cli_command=f"# Describe EKS cluster\naws eks describe-cluster --name CLUSTER_NAME --region REGION",
                impact="Outdated Kubernetes versions may contain known security vulnerabilities that could be exploited by attackers. Older versions also lack important security features available in newer releases.",
                recommendation="1. Upgrade EKS clusters to a supported Kubernetes version\n2. Implement a regular update schedule for EKS clusters\n3. Test upgrades in a non-production environment first\n4. Review the Kubernetes changelog for security improvements in newer versions"
            )
            
        if not any([public_endpoint_clusters, no_encryption_clusters, unpatched_clusters]):
            print("✅ All EKS clusters follow security best practices")

    def check_iam_privilege_escalation_paths(self):
        print("Checking for IAM privilege escalation risks...")
        command = "aws iam list-groups"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM groups", "Unknown")
            return
        
        groups = json.loads(response).get("Groups", [])
        risky_groups = []
        
        # Policies that could allow privilege escalation
        risky_actions = [
            "iam:Create*",
            "iam:Update*",
            "iam:Put*",
            "iam:Attach*",
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:UpdateFunctionCode",
            "ec2:RunInstances",
            "eks:*",
            "iam:*",
            "lambda:*",
            "cloudformation:*"
        ]
        
        for group in groups:
            group_name = group["GroupName"]
            policies_command = f"aws iam list-attached-group-policies --group-name {group_name}"
            policies_response = self.run_aws_command(policies_command)
            
            if not policies_response:
                continue
                
            policies = json.loads(policies_response).get("AttachedPolicies", [])
            risky_policies = []
            
            for policy in policies:
                policy_arn = policy["PolicyArn"]
                policy_name = policy["PolicyName"]
                
                # Skip AWS managed policies that are known to be safe
                if policy_arn.startswith("arn:aws:iam::aws:policy/") and not any(admin_term in policy_name.lower() for admin_term in ["admin", "power"]):
                    continue
                
                # Get policy details
                policy_version_command = f"aws iam get-policy --policy-arn {policy_arn}"
                policy_version_response = self.run_aws_command(policy_version_command)
                
                if not policy_version_response:
                    continue
                    
                policy_data = json.loads(policy_version_response).get("Policy", {})
                default_version = policy_data.get("DefaultVersionId")
                
                policy_document_command = f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version}"
                policy_document_response = self.run_aws_command(policy_document_command)
                
                if not policy_document_response:
                    continue
                    
                policy_document = json.loads(policy_document_response).get("PolicyVersion", {}).get("Document", {})
                
                # Check for potentially risky permissions
                for statement in policy_document.get("Statement", []):
                    if statement.get("Effect") != "Allow":
                        continue
                        
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                        
                    for action in actions:
                        if any(risky_pattern in action for risky_pattern in risky_actions) or action == "*":
                            risky_policies.append(f"{policy_name} ({action})")
                            break
            
            if risky_policies:
                risky_groups.append(f"{group_name} - Risky policies: {', '.join(risky_policies[:3])}" + 
                                 (", and more..." if len(risky_policies) > 3 else ""))
        
        if risky_groups:
            self.add_finding(
                name="[IAM] Privilege escalation risks in IAM groups",
                severity="Critical",
                description=f"The following IAM groups have policies that could allow privilege escalation: {', '.join(risky_groups[:5])}" + 
                           (", and more..." if len(risky_groups) > 5 else ""),
                cli_command=f"# List groups\n{command}\n\n# List group policies\naws iam list-attached-group-policies --group-name GROUP_NAME",
                impact="Policies with these permissions could allow users to escalate their privileges by creating or modifying IAM roles, running Lambda functions with custom code, or launching EC2 instances with specific profiles.",
                recommendation="1. Review and restrict permissions in the identified policies\n2. Implement least privilege principles\n3. Consider using AWS IAM Access Analyzer to detect privilege escalation paths\n4. Remove unnecessary permissions that could lead to privilege escalation"
            )
        else:
            print("✅ No obvious privilege escalation paths detected in IAM groups")

    def check_iam_direct_attached_policies(self):
        print("Checking for IAM users with directly attached policies...")
        command = "aws iam list-users"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM users", "Unknown")
            return
        
        users = json.loads(response).get("Users", [])
        users_with_direct_policies = []
        
        for user in users:
            username = user["UserName"]
            policies_command = f"aws iam list-attached-user-policies --user-name {username}"
            policies_response = self.run_aws_command(policies_command)
            
            if not policies_response:
                continue
                
            policies = json.loads(policies_response).get("AttachedPolicies", [])
            if policies:
                policy_names = [policy["PolicyName"] for policy in policies]
                users_with_direct_policies.append(f"{username} - Policies: {', '.join(policy_names[:3])}" + 
                                             (", and more..." if len(policy_names) > 3 else ""))
        
        if users_with_direct_policies:
            self.add_finding(
                name="[IAM] Users with directly attached policies",
                severity="Medium",
                description=f"The following IAM users have policies directly attached instead of through groups: {', '.join(users_with_direct_policies[:5])}" + 
                           (", and more..." if len(users_with_direct_policies) > 5 else ""),
                cli_command=f"# List users\n{command}\n\n# Check attached policies\naws iam list-attached-user-policies --user-name USERNAME",
                impact="Directly attaching policies to users makes permission management difficult and error-prone, potentially leading to excessive privileges and policy inconsistencies across similar users.",
                recommendation="1. Create IAM groups for common job functions\n2. Attach policies to groups instead of individual users\n3. Add users to appropriate groups\n4. Remove directly attached policies from users"
            )
        else:
            print("✅ No users with directly attached policies detected")

    def check_ecr_tag_immutability(self):
        print("Checking ECR repositories for tag immutability...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        mutable_repositories = []
        
        for region in regions:
            ecr_command = f"aws ecr describe-repositories --region {region}"
            ecr_response = self.run_aws_command(ecr_command)
            
            if not ecr_response:
                continue
                
            repositories = json.loads(ecr_response).get("repositories", [])
            
            for repo in repositories:
                repo_name = repo["repositoryName"]
                repo_uri = repo["repositoryUri"]
                
                # Check tag mutability setting
                if repo.get("imageTagMutability") != "IMMUTABLE":
                    mutable_repositories.append(f"{repo_name} ({region})")
        
        if mutable_repositories:
            self.add_finding(
                name="[ECR] Repositories without tag immutability",
                severity="Medium",
                description=f"The following ECR repositories do not have tag immutability enabled: {', '.join(mutable_repositories[:5])}" + 
                           (", and more..." if len(mutable_repositories) > 5 else ""),
                cli_command=f"# List ECR repositories\n{ecr_command}",
                impact="Without tag immutability, the same tag can be used for different container image versions, which can lead to unexpected deployments and makes it difficult to track which specific container version is running.",
                recommendation="1. Enable tag immutability for all ECR repositories\n2. Use SHA digests instead of tags for immutable references\n3. Implement proper CI/CD practices that enforce using unique tags\n4. Consider implementing a vulnerability scanning process for container images"
            )
        else:
            print("✅ All ECR repositories have tag immutability enabled")

    def check_ec2_imdsv2_requirement(self):
        print("Checking for EC2 instances not requiring IMDSv2...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        imdsv1_instances = []
        
        for region in regions:
            instances_command = f"aws ec2 describe-instances --region {region}"
            instances_response = self.run_aws_command(instances_command)
            
            if not instances_response:
                continue
                
            reservations = json.loads(instances_response).get("Reservations", [])
            
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    metadata_options = instance.get("MetadataOptions", {})
                    
                    # Check if IMDSv2 is not required
                    if metadata_options.get("HttpTokens") != "required":
                        instance_name = "Unnamed"
                        for tag in instance.get("Tags", []):
                            if tag["Key"] == "Name":
                                instance_name = tag["Value"]
                                break
                                
                        imdsv1_instances.append(f"{instance_id} ({instance_name}, {region})")
        
        if imdsv1_instances:
            self.add_finding(
                name="[EC2] Instances not requiring IMDSv2",
                severity="High",
                description=f"The following EC2 instances do not require IMDSv2 (metadata service tokens): {', '.join(imdsv1_instances[:5])}" + 
                           (", and more..." if len(imdsv1_instances) > 5 else ""),
                cli_command=f"# List instances and their metadata options\naws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,MetadataOptions:MetadataOptions}' --region REGION",
                impact="Without enforcing IMDSv2, instances are vulnerable to SSRF attacks that could allow attackers to access instance metadata, including IAM role credentials, potentially leading to privilege escalation.",
                recommendation="1. Modify existing instances to require IMDSv2 using the ModifyInstanceMetadataOptions API\n2. Update launch templates and AMIs to enforce IMDSv2\n3. Create an SCP or IAM policy that requires IMDSv2 for new instance launches\n4. Consider implementing a backup plan in case instances are sensitive to metadata service changes"
            )
        else:
            print("✅ All EC2 instances require IMDSv2")

    def check_sg_non_web_ports(self):
        print("Checking for security groups with non-web ports open to the internet...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        exposed_sgs = []
        
        # Common non-web ports that should not be exposed
        non_web_ports = [
            22,    # SSH
            3389,  # RDP
            1433,  # MSSQL
            3306,  # MySQL
            5432,  # PostgreSQL
            6379,  # Redis
            11211, # Memcached
            27017, # MongoDB
            9200,  # Elasticsearch
            9300,  # Elasticsearch
            25,    # SMTP
            110,   # POP3
            143,   # IMAP
            445,   # SMB
            1521,  # Oracle
            5601   # Kibana
        ]
        
        for region in regions:
            sg_command = f"aws ec2 describe-security-groups --region {region}"
            sg_response = self.run_aws_command(sg_command)
            
            if not sg_response:
                continue
                
            security_groups = json.loads(sg_response).get("SecurityGroups", [])
            
            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                exposed_ports = []
                
                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")
                    
                    # Skip if the ports are not specified
                    if from_port is None or to_port is None:
                        continue
                        
                    # Check if any CIDR allows all IPs
                    has_public_cidr = False
                    for ip_range in permission.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            has_public_cidr = True
                            break
                            
                    if has_public_cidr:
                        # Check if range includes any non-web ports
                        for port in non_web_ports:
                            if from_port <= port <= to_port:
                                exposed_ports.append(str(port))
                                
                if exposed_ports:
                    exposed_sgs.append(f"{sg_id} ({sg_name}, {region}) - Ports: {', '.join(exposed_ports[:5])}" + 
                                   (", and more..." if len(exposed_ports) > 5 else ""))
        
        if exposed_sgs:
            self.add_finding(
                name="[SecurityGroup] Non-web ports exposed to internet",
                severity="High",
                description=f"The following security groups have non-web ports exposed to the internet (0.0.0.0/0): {', '.join(exposed_sgs[:5])}" + 
                           (", and more..." if len(exposed_sgs) > 5 else ""),
                cli_command=f"# List security groups\n{sg_command}",
                impact="Exposing non-web ports to the internet significantly increases the attack surface of your infrastructure. Services like databases, administration interfaces, and internal services should never be directly accessible from the internet.",
                recommendation="1. Restrict access to known IP addresses or CIDR ranges\n2. Use VPN or bastion hosts for administrative access\n3. Implement Security Group ingress rules to allow traffic only from necessary sources\n4. Consider using AWS Systems Manager Session Manager instead of SSH/RDP"
            )
        else:
            print("✅ No security groups with non-web ports open to the internet")

    def check_aws_account_organization(self):
        print("Checking AWS account organization...")
        command = "aws organizations describe-organization"
        response = self.run_aws_command(command)
        
        if not response or "Organization" not in response:
            self.add_finding(
                name="[ORGANIZATION] Account not in AWS Organization",
                severity="High",
                description="This AWS account is not part of an AWS Organization, which is essential for centralized management and security controls.",
                cli_command=command,
                impact="Without AWS Organizations, you miss out on consolidated billing, service control policies (SCPs), centralized compliance, and the ability to implement consistent security controls across accounts.",
                recommendation="1. Create an AWS Organization for your accounts\n2. Move all standalone accounts into the organization\n3. Implement appropriate OUs (Organizational Units) based on environment, function, or compliance requirements\n4. Configure service control policies (SCPs) to enforce security guardrails"
            )
        else:
            org = json.loads(response).get("Organization", {})
            
            # Check for environment segregation (a proxy is checking for multiple OUs)
            ou_command = "aws organizations list-organizational-units-for-parent --parent-id " + org.get("RootId", "")
            ou_response = self.run_aws_command(ou_command)
            
            if not ou_response or "OrganizationalUnits" not in ou_response or len(json.loads(ou_response).get("OrganizationalUnits", [])) < 2:
                self.add_finding(
                    name="[ORGANIZATION] Lack of environment segregation",
                    severity="High",
                    description="AWS accounts do not appear to be properly segregated by environment (dev, test, prod) within the organization.",
                    cli_command=f"{command}\n{ou_command}",
                    impact="Without proper account segregation, there's an increased risk of development changes affecting production environments, inadequate access controls between environments, and potential compliance violations.",
                    recommendation="1. Create separate AWS accounts for different environments (dev, test, staging, prod)\n2. Organize accounts into appropriate Organizational Units (OUs)\n3. Apply different SCPs to each environment\n4. Implement appropriate cross-account access controls"
                )
            else:
                print("✅ AWS accounts appear to be properly organized")

    def check_root_account_usage(self):
        print("Checking for recent root account usage...")
        command = "aws iam get-credential-report"
        response = self.run_aws_command(command)
        
        if not response or "Content" not in response:
            generate_command = "aws iam generate-credential-report"
            self.run_aws_command(generate_command)
            response = self.run_aws_command(command)
            
        if response and "Content" in response:
            # The credential report is base64 encoded
            import base64
            content = base64.b64decode(json.loads(response)["Content"]).decode("utf-8")
            
            # Parse the CSV content
            lines = content.strip().split("\n")
            headers = lines[0].split(",")
            
            # Find the root account
            for line in lines[1:]:
                user_data = line.split(",")
                user_dict = dict(zip(headers, user_data))
                
                if user_dict["user"] == "<root_account>":
                    # Check for recent console login
                    password_last_used = user_dict.get("password_last_used", "N/A")
                    root_access_key_used = False
                    
                    if password_last_used != "N/A" and password_last_used != "no_information":
                        try:
                            # Parse the date
                            last_used_date = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                            days_since_use = (datetime.now(timezone.utc) - last_used_date).days
                            
                            if days_since_use < 30:
                                self.add_finding(
                                    name="[IAM] Recent root account usage",
                                    severity="Critical",
                                    description=f"The AWS root account was used in the last {days_since_use} days (last used: {password_last_used}).",
                                    cli_command=command,
                                    impact="Regular use of the root account violates the principle of least privilege and increases the risk of accidental or malicious actions that could significantly impact your AWS environment.",
                                    recommendation="1. Lock up root account credentials\n2. Create and use individual IAM users with appropriate permissions\n3. Use AWS Organizations and delegated administration for management tasks\n4. Enable CloudTrail alerts for root account usage"
                                )
                        except Exception as e:
                            print(f"Error parsing root account last used date: {str(e)}")
                    
                    # Also check access key last used
                    access_key_1_last_used = user_dict.get("access_key_1_last_used_date", "N/A")
                    if access_key_1_last_used != "N/A" and access_key_1_last_used != "no_information":
                        root_access_key_used = True
                        
                    access_key_2_last_used = user_dict.get("access_key_2_last_used_date", "N/A")
                    if access_key_2_last_used != "N/A" and access_key_2_last_used != "no_information":
                        root_access_key_used = True
                        
                    if root_access_key_used:
                        self.add_finding(
                            name="[IAM] Root account access keys in use",
                            severity="Critical",
                            description="The AWS root account has active access keys that have been used.",
                            cli_command=command,
                            impact="Root account access keys provide programmatic root access to your AWS account. If these credentials are leaked or stolen, attackers would have unrestricted access to your entire AWS environment.",
                            recommendation="1. Delete all root account access keys immediately\n2. Create individual IAM users with appropriate permissions for programmatic access\n3. Use AWS IAM roles for applications and services\n4. Regularly review and rotate credentials"
                        )
                    
                    break
                    
        else:
            self.add_issue("Unable to get credential report", "Unknown")

    def check_rds_single_az(self):
        print("Checking for RDS instances in a single AZ...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        single_az_instances = []
        
        for region in regions:
            rds_command = f"aws rds describe-db-instances --region {region}"
            rds_response = self.run_aws_command(rds_command)
            
            if not rds_response:
                continue
                
            instances = json.loads(rds_response).get("DBInstances", [])
            
            for instance in instances:
                instance_id = instance["DBInstanceIdentifier"]
                multi_az = instance.get("MultiAZ", False)
                
                if not multi_az:
                    # Check if it's a critical/production instance
                    is_prod = False
                    for tag in instance.get("TagList", []):
                        if tag["Key"].lower() in ["environment", "env"] and "prod" in tag["Value"].lower():
                            is_prod = True
                            break
                    
                    if is_prod:
                        single_az_instances.append(f"{instance_id} (Production, {region})")
                    else:
                        single_az_instances.append(f"{instance_id} ({region})")
        
        if single_az_instances:
            self.add_finding(
                name="[RDS] Single-AZ configuration",
                severity="Medium",
                description=f"The following RDS instances are configured with a single availability zone: {', '.join(single_az_instances[:5])}" + 
                           (", and more..." if len(single_az_instances) > 5 else ""),
                cli_command=f"# List RDS instances\n{rds_command}",
                impact="Single-AZ RDS instances lack high availability and are susceptible to outages if the availability zone experiences issues. This can lead to application downtime and potential data loss.",
                recommendation="1. Modify production RDS instances to enable Multi-AZ deployment\n2. Implement proper backup strategies\n3. Consider using read replicas for increased read capacity and disaster recovery\n4. For non-production environments, ensure there are proper backup procedures"
            )
        else:
            print("✅ All RDS instances are using Multiple AZs")

    def check_cmk_usage(self):
        print("Checking for Customer Managed Key (CMK) usage...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        aws_managed_only = True
        
        for region in regions:
            kms_command = f"aws kms list-keys --region {region}"
            kms_response = self.run_aws_command(kms_command)
            
            if not kms_response:
                continue
                
            keys = json.loads(kms_response).get("Keys", [])
            
            for key in keys:
                key_id = key["KeyId"]
                
                # Get key details
                key_command = f"aws kms describe-key --key-id {key_id} --region {region}"
                key_response = self.run_aws_command(key_command)
                
                if not key_response:
                    continue
                    
                key_metadata = json.loads(key_response).get("KeyMetadata", {})
                
                # Check if it's a customer managed key
                if key_metadata.get("KeyManager") == "CUSTOMER":
                    aws_managed_only = False
                    break
            
            if not aws_managed_only:
                break
        
        if aws_managed_only:
            self.add_finding(
                name="[KMS] No Customer Managed Keys (CMKs) in use",
                severity="Medium",
                description="Your AWS account is not using any Customer Managed Keys (CMKs) for encryption, relying solely on AWS managed keys.",
                cli_command=f"# List KMS keys\naws kms list-keys --region REGION",
                impact="Without Customer Managed Keys, you have limited control over key policies, rotation schedules, and key lifecycle. This may not meet compliance requirements for certain regulated industries.",
                recommendation="1. Create Customer Managed Keys (CMKs) for sensitive data and services\n2. Implement appropriate key policies and access controls\n3. Configure key rotation for CMKs\n4. Use CMKs for encrypting sensitive resources like S3 buckets, RDS instances, and EBS volumes"
            )
        else:
            print("✅ Customer Managed Keys (CMKs) are being used")

    def check_iam_group_excessive_privileges(self):
        print("Checking for IAM groups with excessive privileges...")
        command = "aws iam list-groups"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list IAM groups", "Unknown")
            return
        
        groups = json.loads(response).get("Groups", [])
        high_risk_groups = []
        
        # High-risk groups to pay special attention to
        special_groups = ["devops", "kubernetes", "admin", "security"]
        
        for group in groups:
            group_name = group["GroupName"]
            policies_command = f"aws iam list-attached-group-policies --group-name {group_name}"
            policies_response = self.run_aws_command(policies_command)
            
            if not policies_response:
                continue
                
            policies = json.loads(policies_response).get("AttachedPolicies", [])
            risky_policies = []
            
            for policy in policies:
                policy_arn = policy["PolicyArn"]
                policy_name = policy["PolicyName"]
                
                # Check if policy has admin privileges or other high-risk permissions
                if "Admin" in policy_name or "FullAccess" in policy_name or "PowerUser" in policy_name:
                    risky_policies.append(policy_name)
                
                # Check for specific privilege escalation risks in custom policies
                if not policy_arn.startswith("arn:aws:iam::aws:policy/"):
                    policy_version_command = f"aws iam get-policy --policy-arn {policy_arn}"
                    policy_version_response = self.run_aws_command(policy_version_command)
                    
                    if policy_version_response:
                        policy_data = json.loads(policy_version_response).get("Policy", {})
                        default_version = policy_data.get("DefaultVersionId")
                        
                        if default_version:
                            policy_document_command = f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version}"
                            policy_document_response = self.run_aws_command(policy_document_command)
                            
                            if policy_document_response:
                                policy_document = json.loads(policy_document_response).get("PolicyVersion", {}).get("Document", {})
                                
                                # Check for concerning statements in policy
                                for statement in policy_document.get("Statement", []):
                                    if statement.get("Effect") != "Allow":
                                        continue
                                        
                                    actions = statement.get("Action", [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    # Check for dangerous permissions
                                    dangerous_permissions = [
                                        "iam:*", "iam:Create*", "iam:Put*", "iam:Attach*", "iam:Pass*",
                                        "lambda:*", "lambda:Create*", "lambda:Update*",
                                        "ec2:RunInstances", "eks:*",
                                        "cloudformation:*", "s3:*",
                                    ]
                                    
                                    for action in actions:
                                        if action == "*" or any(action.startswith(perm.replace("*", "")) for perm in dangerous_permissions):
                                            if policy_name not in risky_policies:
                                                risky_policies.append(policy_name)
                                                break
            
            if risky_policies or group_name.lower() in [sg.lower() for sg in special_groups]:
                risk_level = "High" if risky_policies else "Medium"
                group_details = f"{group_name}"
                if risky_policies:
                    group_details += f" - Risky policies: {', '.join(risky_policies)}"
                high_risk_groups.append((group_details, risk_level))
        
        if high_risk_groups:
            groups_by_risk = {}
            for group, risk in high_risk_groups:
                if risk not in groups_by_risk:
                    groups_by_risk[risk] = []
                groups_by_risk[risk].append(group)
                
            for risk_level, groups_list in groups_by_risk.items():
                self.add_finding(
                    name=f"[IAM] {risk_level} risk IAM groups with excessive privileges",
                    severity=risk_level,
                    description=f"The following IAM groups have potentially excessive privileges: {', '.join(groups_list[:5])}" + 
                               (", and more..." if len(groups_list) > 5 else ""),
                    cli_command=f"# List group policies\naws iam list-attached-group-policies --group-name GROUP_NAME\n\n# Get policy details\naws iam get-policy-version --policy-arn POLICY_ARN --version-id VERSION_ID",
                    impact="Groups with excessive privileges can lead to privilege escalation, especially in groups like 'devops' or 'kubernetes' that may have access to run code or manage infrastructure.",
                    recommendation="1. Review the permissions assigned to these groups and apply the principle of least privilege\n2. Break down large groups into smaller, role-specific groups\n3. Regularly audit group memberships\n4. Consider using AWS Organizations SCPs to limit what permissions can be granted"
                )
        else:
            print("✅ No IAM groups with excessive privileges detected")

    def check_unused_security_groups(self):
        print("Checking for unused security groups...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        unused_security_groups = []
        
        for region in regions:
            # Get all security groups
            sg_command = f"aws ec2 describe-security-groups --region {region}"
            sg_response = self.run_aws_command(sg_command)
            
            if not sg_response:
                continue
                
            security_groups = json.loads(sg_response).get("SecurityGroups", [])
            
            # Get all instances
            instances_command = f"aws ec2 describe-instances --region {region}"
            instances_response = self.run_aws_command(instances_command)
            used_sg_ids = set()
            
            if instances_response:
                reservations = json.loads(instances_response).get("Reservations", [])
                for reservation in reservations:
                    for instance in reservation.get("Instances", []):
                        for sg in instance.get("SecurityGroups", []):
                            used_sg_ids.add(sg["GroupId"])
            
            # Get all ENIs (including those used by RDS, Lambda, etc.)
            eni_command = f"aws ec2 describe-network-interfaces --region {region}"
            eni_response = self.run_aws_command(eni_command)
            
            if eni_response:
                enis = json.loads(eni_response).get("NetworkInterfaces", [])
                for eni in enis:
                    for sg in eni.get("Groups", []):
                        used_sg_ids.add(sg["GroupId"])
            
            # Check for unused security groups
            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                
                # Skip default security groups
                if sg_name == "default":
                    continue
                    
                if sg_id not in used_sg_ids:
                    unused_security_groups.append(f"{sg_id} ({sg_name}, {region})")
        
        if unused_security_groups:
            self.add_finding(
                name="[SecurityGroup] Unused security groups",
                severity="Low",
                description=f"The following security groups are not attached to any resources: {', '.join(unused_security_groups[:5])}" + 
                           (", and more..." if len(unused_security_groups) > 5 else ""),
                cli_command=f"# List security groups\naws ec2 describe-security-groups --region REGION\n\n# List network interfaces\naws ec2 describe-network-interfaces --region REGION",
                impact="Unused security groups increase management complexity, can lead to confusion, and may pose a security risk if they're later used inadvertently with overly permissive rules.",
                recommendation="1. Delete unused security groups to maintain a clean environment\n2. Implement a process to regularly review and clean up unused security groups\n3. Consider tagging security groups to track their purpose and lifecycle\n4. Use automation tools to detect and clean up orphaned security groups"
            )
        else:
            print("✅ No unused security groups detected")

    def check_root_hardware_mfa(self):
        print("Checking if root account has hardware MFA...")
        
        # Root account MFA check
        root_credentials_command = "aws iam get-account-summary"
        root_response = self.run_aws_command(root_credentials_command)
        
        if root_response:
            account_summary = json.loads(root_response).get("SummaryMap", {})
            if account_summary.get("AccountMFAEnabled", 0) == 1:
                # Check if root is using hardware or virtual MFA
                root_mfa_command = "aws iam list-virtual-mfa-devices --assignment-status Assigned"
                root_mfa_response = self.run_aws_command(root_mfa_command)
                
                if root_mfa_response:
                    devices = json.loads(root_mfa_response).get("VirtualMFADevices", [])
                    root_using_virtual_mfa = False
                    
                    for device in devices:
                        if device.get("User", {}).get("Arn", "").endswith(":root"):
                            root_using_virtual_mfa = True
                            break
                    
                    if root_using_virtual_mfa:
                        self.add_finding(
                            name="[IAM] Root account using virtual MFA instead of hardware MFA",
                            severity="Critical",
                            description="The AWS root account is protected with a virtual MFA device instead of a hardware MFA device.",
                            cli_command=f"# Check MFA status\n{root_mfa_command}",
                            impact="Virtual MFA devices for the root account are less secure as they can be compromised if the device hosting the virtual MFA is stolen, lost, or compromised. The root account has ultimate control over your AWS account, making it a critical security concern.",
                            recommendation="1. Purchase at least two hardware MFA devices (for redundancy)\n2. Add a hardware MFA device to the root account\n3. Remove the virtual MFA device after confirming the hardware MFA works\n4. Store the backup hardware MFA device in a secure, separate location"
                        )
                    else:
                        print("✅ Root account is protected with hardware MFA")
            else:
                # This should already be caught by check_root_mfa, but adding here for completeness
                self.add_finding(
                    name="[IAM] Root account without MFA",
                    severity="Critical",
                    description="The AWS root account does not have any MFA device enabled.",
                    cli_command=root_credentials_command,
                    impact="Without MFA, the root account is vulnerable to password-based attacks. Compromise of the root account would give attackers complete control over your AWS account with no restrictions.",
                    recommendation="1. Enable hardware MFA for the root account immediately\n2. Purchase at least two hardware MFA devices (for redundancy)\n3. Store the backup hardware MFA device in a secure, separate location\n4. Limit the use of the root account for only the tasks that explicitly require it"
                )
        else:
            self.add_issue("Unable to check root account MFA status", "Unknown")

    def check_ec2_instance_attribute_manipulation(self):
        print("Checking for EC2 instances vulnerable to attribute manipulation...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        vulnerable_instances = []
        risky_policies = []
        
        for region in regions:
            # Check IAM policies that allow modifying instance attributes
            iam_policy_command = f"aws iam list-policies --scope All --region {region}"
            iam_response = self.run_aws_command(iam_policy_command)
            
            if iam_response:
                policies = json.loads(iam_response).get("Policies", [])
                
                for policy in policies:
                    policy_arn = policy["Arn"]
                    policy_name = policy["PolicyName"]
                    
                    # Skip AWS managed policies for efficiency, unless they specifically mention EC2
                    if policy_arn.startswith("arn:aws:iam::aws:policy/") and "EC2" not in policy_name:
                        continue
                        
                    # Get policy details
                    policy_version_command = f"aws iam get-policy --policy-arn {policy_arn}"
                    policy_version_response = self.run_aws_command(policy_version_command)
                    
                    if policy_version_response:
                        policy_data = json.loads(policy_version_response).get("Policy", {})
                        default_version = policy_data.get("DefaultVersionId")
                        
                        if default_version:
                            policy_document_command = f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {default_version}"
                            policy_document_response = self.run_aws_command(policy_document_command)
                            
                            if policy_document_response:
                                policy_document = json.loads(policy_document_response).get("PolicyVersion", {}).get("Document", {})
                                
                                # Check for dangerous EC2 permissions
                                for statement in policy_document.get("Statement", []):
                                    if statement.get("Effect") != "Allow":
                                        continue
                                        
                                    actions = statement.get("Action", [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    
                                    # Check for permissions that could modify instance attributes
                                    dangerous_ec2_actions = [
                                        "ec2:ModifyInstanceAttribute",
                                        "ec2:ModifyInstanceMetadataOptions",
                                        "ec2:RunInstances",
                                        "ec2:*"
                                    ]
                                    
                                    for action in actions:
                                        if action == "*" or any(dangerous_action in action for dangerous_action in dangerous_ec2_actions):
                                            risky_policies.append(policy_name)
                                            break
        
        # Check instances with IAM roles that might have these policies
        instances_command = f"aws ec2 describe-instances --region {region}"
        instances_response = self.run_aws_command(instances_command)
        
        if instances_response:
            reservations = json.loads(instances_response).get("Reservations", [])
            
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    
                    # Check if instance has an IAM role
                    iam_instance_profile = instance.get("IamInstanceProfile", {})
                    if iam_instance_profile:
                        # Get instance name if available
                        instance_name = "Unnamed"
                        for tag in instance.get("Tags", []):
                            if tag["Key"] == "Name":
                                instance_name = tag["Value"]
                                break
                                
                        # Check instance metadata options
                        metadata_options = instance.get("MetadataOptions", {})
                        http_tokens = metadata_options.get("HttpTokens", "optional")
                        
                        if http_tokens == "optional":
                            vulnerable_instances.append(f"{instance_id} ({instance_name}, {region})")
    
        if vulnerable_instances:
            # Add finding for vulnerable instances
            self.add_finding(
                name="[EC2] Instances vulnerable to attribute manipulation",
                severity="High",
                description=f"The following EC2 instances may be vulnerable to instance attribute manipulation: {', '.join(vulnerable_instances[:5])}" + 
                           (", and more..." if len(vulnerable_instances) > 5 else ""),
                cli_command=f"# List instance metadata options\naws ec2 describe-instances --query 'Reservations[].Instances[].{InstanceId:InstanceId,MetadataOptions:MetadataOptions}' --region REGION",
                impact="Attackers could potentially modify instance attributes like user data, IAM roles, or security groups, leading to privilege escalation or unauthorized access.",
                recommendation="1. Enforce IMDSv2 on all instances\n2. Apply least privilege principles to IAM roles attached to EC2 instances\n3. Implement strict security group rules to limit access to instance metadata service\n4. Monitor for suspicious API calls related to instance attribute modifications"
            )
            
            # Add finding for risky policies if any were found
            if risky_policies:
                self.add_finding(
                    name="[IAM] Policies allowing EC2 attribute manipulation",
                    severity="High",
                    description=f"The following IAM policies allow modifying EC2 instance attributes: {', '.join(risky_policies[:5])}" + 
                               (", and more..." if len(risky_policies) > 5 else ""),
                    cli_command=f"# Get policy details\naws iam get-policy-version --policy-arn POLICY_ARN --version-id VERSION_ID",
                    impact="These policies could allow users or roles to modify critical EC2 instance attributes, potentially leading to privilege escalation or unauthorized access.",
                    recommendation="1. Review and restrict permissions in these policies\n2. Apply the principle of least privilege\n3. Consider using AWS Organizations SCPs to prevent risky EC2 actions\n4. Implement CloudTrail alerting for sensitive EC2 API calls"
                )
        else:
            print("✅ No instances vulnerable to attribute manipulation detected")

    def check_s3_event_notifications(self):
        print("Checking S3 buckets for event notifications...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        buckets_without_notifications = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            # Check for notifications
            notification_command = f"aws s3api get-bucket-notification-configuration --bucket {bucket_name}"
            notification_response = self.run_aws_command(notification_command)
            
            if notification_response:
                notification_config = json.loads(notification_response)
                # Check if any notification configuration exists
                if not any(config in notification_config and notification_config[config] for config in 
                          ["TopicConfigurations", "QueueConfigurations", "LambdaFunctionConfigurations", "EventBridgeConfiguration"]):
                    buckets_without_notifications.append(bucket_name)
        
        if buckets_without_notifications:
            self.add_finding(
                name="[S3] Event notifications disabled for buckets",
                severity="Low",
                description=f"The following S3 buckets do not have event notifications configured: {', '.join(buckets_without_notifications[:5])}" + 
                           (", and more..." if len(buckets_without_notifications) > 5 else ""),
                cli_command=f"# Check bucket notification config\n{notification_command}",
                impact="Without event notifications, you cannot monitor and respond to critical events in your S3 buckets, such as object creations or deletions.",
                recommendation="1. Configure S3 event notifications to Lambda, SNS, SQS, or EventBridge\n2. Set up notifications for critical operations like object creation, deletion, or restoration\n3. Use event notifications for automating workflows or security monitoring"
            )
        else:
            print("✅ All S3 buckets have event notifications configured")

    def check_s3_secure_transport(self):
        print("Checking S3 buckets for secure transport enforcement...")
        command = "aws s3api list-buckets"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list S3 buckets", "Unknown")
            return
        
        buckets = json.loads(response).get("Buckets", [])
        buckets_without_secure_transport = []
        
        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            # Check bucket policy
            policy_command = f"aws s3api get-bucket-policy --bucket {bucket_name}"
            policy_response = self.run_aws_command(f"{policy_command} 2>&1")
            
            if policy_response and "Policy" in policy_response:
                policy = json.loads(policy_response).get("Policy", "{}")
                policy_json = json.loads(policy) if isinstance(policy, str) else policy
                
                # Check for secure transport enforcement
                has_secure_transport = False
                for statement in policy_json.get("Statement", []):
                    if statement.get("Effect") == "Deny":
                        condition = statement.get("Condition", {})
                        if condition.get("Bool", {}).get("aws:SecureTransport") == "false":
                            has_secure_transport = True
                            break
                
                if not has_secure_transport:
                    buckets_without_secure_transport.append(bucket_name)
            else:
                # No policy or couldn't retrieve policy
                buckets_without_secure_transport.append(bucket_name)
        
        if buckets_without_secure_transport:
            self.add_finding(
                name="[S3] Bucket policies do not enforce HTTPS",
                severity="Medium",
                description=f"The following S3 buckets do not enforce HTTPS with a bucket policy: {', '.join(buckets_without_secure_transport[:5])}" + 
                           (", and more..." if len(buckets_without_secure_transport) > 5 else ""),
                cli_command=f"# Check bucket policy\n{policy_command}",
                impact="Without enforcing HTTPS, data transferred to and from your S3 buckets could be intercepted in transit, potentially exposing sensitive information.",
                recommendation="1. Implement a bucket policy that denies access when aws:SecureTransport is false\n2. Ensure all applications accessing S3 use HTTPS\n3. Monitor access logs for non-HTTPS requests\n4. Use AWS Config rules to check for HTTPS enforcement"
            )
        else:
            print("✅ All S3 buckets enforce secure transport (HTTPS)")

    def check_secrets_manager_rotation(self):
        print("Checking Secrets Manager for automatic rotation...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        secrets_without_rotation = []
        
        for region in regions:
            # List secrets
            secrets_command = f"aws secretsmanager list-secrets --region {region}"
            secrets_response = self.run_aws_command(secrets_command)
            
            if not secrets_response:
                continue
                
            secrets = json.loads(secrets_response).get("SecretList", [])
            
            for secret in secrets:
                secret_name = secret["Name"]
                
                # Check if automatic rotation is enabled
                if not secret.get("RotationEnabled", False):
                    secrets_without_rotation.append(f"{secret_name} ({region})")
        
        if secrets_without_rotation:
            self.add_finding(
                name="[SECRETS] Automatic rotation not configured",
                severity="Medium",
                description=f"The following secrets in AWS Secrets Manager do not have automatic rotation enabled: {', '.join(secrets_without_rotation[:5])}" + 
                           (", and more..." if len(secrets_without_rotation) > 5 else ""),
                cli_command=f"# List secrets\n{secrets_command}",
                impact="Without automatic rotation, secrets may be used for extended periods, increasing the risk of compromise over time. This violates security best practices for credential management.",
                recommendation="1. Configure automatic rotation for all secrets in AWS Secrets Manager\n2. Set up Lambda functions for custom rotation logic if needed\n3. Test the rotation process to ensure it doesn't disrupt services\n4. Implement monitoring for rotation failures"
            )
        else:
            print("✅ All secrets in Secrets Manager have automatic rotation enabled")

    def check_ecr_scanning(self):
        print("Checking ECR repositories for image scanning...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        repos_without_scanning = []
        
        for region in regions:
            # List ECR repositories
            ecr_command = f"aws ecr describe-repositories --region {region}"
            ecr_response = self.run_aws_command(ecr_command)
            
            if not ecr_response:
                continue
                
            repositories = json.loads(ecr_response).get("repositories", [])
            
            for repo in repositories:
                repo_name = repo["repositoryName"]
                
                # Check if scan on push is enabled
                if not repo.get("imageScanningConfiguration", {}).get("scanOnPush", False):
                    repos_without_scanning.append(f"{repo_name} ({region})")
        
        if repos_without_scanning:
            self.add_finding(
                name="[ECR] Image scanning not enabled",
                severity="Medium",
                description=f"The following ECR repositories do not have image scanning enabled: {', '.join(repos_without_scanning[:5])}" + 
                           (", and more..." if len(repos_without_scanning) > 5 else ""),
                cli_command=f"# List ECR repositories\n{ecr_command}",
                impact="Without image scanning, vulnerabilities in container images may go undetected, potentially leading to compromised containers when deployed.",
                recommendation="1. Enable automatic scanning on push for all ECR repositories\n2. Implement policies to block deployment of images with critical vulnerabilities\n3. Regularly review and remediate vulnerabilities found in container images\n4. Consider implementing additional container security tools for runtime protection"
            )
        else:
            print("✅ All ECR repositories have image scanning enabled")

    def check_cloudfront_origin_groups(self):
        print("Checking CloudFront distributions for origin failover configuration...")
        command = "aws cloudfront list-distributions"
        response = self.run_aws_command(command)
        if not response:
            self.add_issue("Unable to list CloudFront distributions", "Unknown")
            return
        
        try:
            distributions = json.loads(response).get("DistributionList", {}).get("Items", [])
            dists_without_failover = []
            
            for distribution in distributions:
                dist_id = distribution["Id"]
                domain_name = distribution.get("DomainName", "Unknown")
                
                # Check for origin groups (used for failover)
                if not distribution.get("OriginGroups", {}).get("Quantity", 0) > 0:
                    dists_without_failover.append(f"{domain_name} ({dist_id})")
            
            if dists_without_failover:
                self.add_finding(
                    name="[CLOUDFRONT] Distributions without origin failover",
                    severity="Medium",
                    description=f"The following CloudFront distributions are not configured with origin groups for failover: {', '.join(dists_without_failover[:5])}" + 
                               (", and more..." if len(dists_without_failover) > 5 else ""),
                    cli_command=f"# List CloudFront distributions\n{command}",
                    impact="Without origin failover configuration, your distribution has a single point of failure. If the primary origin becomes unavailable, users will experience service disruption.",
                    recommendation="1. Configure origin groups with primary and secondary origins\n2. Set up appropriate failover criteria\n3. Test failover scenarios regularly\n4. Consider using different AWS regions for primary and secondary origins"
                )
            else:
                print("✅ All CloudFront distributions have origin failover configured")
        except Exception as e:
            print(f"Error checking CloudFront origin groups: {str(e)}")

    def check_api_gateway_logging(self):
        print("Checking API Gateway logging and tracing...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        apis_without_logging = []
        
        for region in regions:
            # Check REST APIs
            rest_api_command = f"aws apigateway get-rest-apis --region {region}"
            rest_api_response = self.run_aws_command(rest_api_command)
            
            if rest_api_response:
                try:
                    rest_apis = json.loads(rest_api_response).get("items", [])
                    
                    for api in rest_apis:
                        api_id = api["id"]
                        api_name = api["name"]
                        
                        # Get stages
                        stages_command = f"aws apigateway get-stages --rest-api-id {api_id} --region {region}"
                        stages_response = self.run_aws_command(stages_command)
                        
                        if stages_response:
                            stages = json.loads(stages_response).get("item", [])
                            
                            for stage in stages:
                                stage_name = stage["stageName"]
                                
                                # Check for access logging
                                if not stage.get("accessLogSettings"):
                                    apis_without_logging.append(f"{api_name}/{stage_name} (REST API, {region})")
            except Exception as e:
                print(f"Error checking REST API Gateway in region {region}: {str(e)}")
        
        # Check HTTP APIs (API Gateway v2)
        http_api_command = f"aws apigatewayv2 get-apis --region {region}"
        http_api_response = self.run_aws_command(http_api_command)
        
        if http_api_response:
            try:
                http_apis = json.loads(http_api_response).get("Items", [])
                
                for api in http_apis:
                    api_id = api["ApiId"]
                    api_name = api["Name"]
                    
                    # Get stages
                    stages_command = f"aws apigatewayv2 get-stages --api-id {api_id} --region {region}"
                    stages_response = self.run_aws_command(stages_command)
                    
                    if stages_response:
                        stages = json.loads(stages_response).get("Items", [])
                        
                        for stage in stages:
                            stage_name = stage["StageName"]
                            
                            # Check for access logging
                            if not stage.get("AccessLogSettings"):
                                apis_without_logging.append(f"{api_name}/{stage_name} (HTTP API, {region})")
            except Exception as e:
                print(f"Error checking HTTP API Gateway in region {region}: {str(e)}")
    
        if apis_without_logging:
            self.add_finding(
                name="[API Gateway] Logging disabled for API stages",
                severity="Medium",
                description=f"The following API Gateway stages do not have access logging enabled: {', '.join(apis_without_logging[:5])}" + 
                           (", and more..." if len(apis_without_logging) > 5 else ""),
                cli_command=f"# List API Gateway stages\naws apigateway get-stages --rest-api-id API_ID --region REGION",
                impact="Without access logging, you cannot track API usage, monitor for suspicious activity, or troubleshoot issues effectively.",
                recommendation="1. Enable access logging for all API Gateway stages\n2. Configure logs to be delivered to CloudWatch Logs\n3. Set up log retention policies\n4. Consider implementing API Gateway request validation and AWS WAF"
            )
        else:
            print("✅ All API Gateway stages have logging enabled")

    def check_org_tag_policies(self):
        print("Checking for AWS Organizations tag policies...")
        # First, check if using AWS Organizations
        command = "aws organizations describe-organization"
        response = self.run_aws_command(command)
        
        if not response or "Organization" not in response:
            # Skip if not using AWS Organizations
            return
        
        # Check if tag policies are enabled
        org_data = json.loads(response).get("Organization", {})
        org_id = org_data.get("Id")
        
        if org_id:
            # Check available policy types
            policy_types_command = f"aws organizations list-roots"
            policy_types_response = self.run_aws_command(policy_types_command)
            
            if policy_types_response:
                roots = json.loads(policy_types_response).get("Roots", [])
                
                if roots:
                    policy_types = roots[0].get("PolicyTypes", [])
                    tag_policy_enabled = any(pt.get("Type") == "TAG_POLICY" and pt.get("Status") == "ENABLED" for pt in policy_types)
                    
                    if not tag_policy_enabled:
                        self.add_finding(
                            name="[Org] Tag policies not enabled",
                            severity="Low",
                            description=f"Tag policies are not enabled in your AWS Organization {org_id}.",
                            cli_command=policy_types_command,
                            impact="Without tag policies, you cannot enforce consistent tagging across your organization, making resource management, cost allocation, and security tracking more difficult.",
                            recommendation="1. Enable tag policies in your AWS Organization\n2. Create tag policies to enforce required tags\n3. Apply tag policies to appropriate OUs\n4. Monitor tag policy compliance"
                        )
                    else:
                        # Check if any tag policies exist
                        tag_policies_command = f"aws organizations list-policies --filter TAG_POLICY"
                        tag_policies_response = self.run_aws_command(tag_policies_command)
                        
                        if tag_policies_response and "Policies" in tag_policies_response:
                            policies = json.loads(tag_policies_response).get("Policies", [])
                            
                            if not policies:
                                self.add_finding(
                                    name="[Org] No tag policies created",
                                    severity="Low",
                                    description="Tag policies are enabled but no policies have been created in your AWS Organization.",
                                    cli_command=tag_policies_command,
                                    impact="Although tag policies are enabled, without actual policies defined, you cannot enforce tagging standards across your organization.",
                                    recommendation="1. Create tag policies to enforce required tags\n2. Include essential tags such as Environment, Owner, CostCenter, and Project\n3. Apply tag policies to appropriate OUs\n4. Monitor tag policy compliance"
                                )
                            else:
                                print("✅ AWS Organizations has tag policies configured")
        else:
            print("✅ AWS Organizations tag policies are properly configured")

    def check_org_security_contact(self):
        print("Checking for AWS Organizations security contact information...")
        # Check if AWS account has security contact information
        command = "aws account get-alternate-contact --alternate-contact-type SECURITY"
        response = self.run_aws_command(command)
        
        if not response or "AlternateContact" not in response:
            self.add_finding(
                name="[Org] Security contact information not provided",
                severity="Low",
                description="The AWS account does not have security contact information configured.",
                cli_command=command,
                impact="Without designated security contact information, AWS cannot reach the appropriate person during security events, potentially delaying incident response.",
                recommendation="1. Configure security contact information for your AWS account\n2. Use a role-based email address rather than an individual's email\n3. Ensure the contact information stays current\n4. Set up additional billing and operations contacts"
            )
        else:
            print("✅ AWS account has security contact information configured")

    def check_aws_backup(self):
        print("Checking for AWS Backup vaults...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        regions_without_backup = []
        
        for region in regions:
            backup_command = f"aws backup list-backup-vaults --region {region}"
            backup_response = self.run_aws_command(backup_command)
            
            if not backup_response or "BackupVaultList" not in backup_response or json.loads(backup_response).get("BackupVaultList", []) == []:
                regions_without_backup.append(region)
        
        if regions_without_backup:
            self.add_finding(
                name="[AWS Backup] Absence of backup vaults",
                severity="Medium",
                description=f"AWS Backup vaults are not configured in the following regions: {', '.join(regions_without_backup[:5])}" + 
                          (", and more..." if len(regions_without_backup) > 5 else ""),
                cli_command=f"# Check for backup vaults\naws backup list-backup-vaults --region REGION",
                impact="Without AWS Backup vaults, you may lack a centralized and automated backup solution for your AWS resources, potentially leading to inconsistent backups and difficulty in disaster recovery.",
                recommendation="1. Set up AWS Backup vaults in all regions where you have resources\n2. Configure backup plans with appropriate schedules and retention policies\n3. Include critical resources like EBS volumes, RDS databases, and DynamoDB tables in your backup plans"
            )
        else:
            print("✅ AWS Backup vaults are configured in all regions")

    def check_alb_access_logs(self):
        print("Checking for ALB access logs and settings...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        albs_without_access_logs = []
        albs_without_deletion_protection = []
        albs_allowing_invalid_headers = []
        
        for region in regions:
            # Get ALBs (Application Load Balancers)
            alb_command = f"aws elbv2 describe-load-balancers --region {region}"
            alb_response = self.run_aws_command(alb_command)
            
            if not alb_response:
                continue
                
            load_balancers = json.loads(alb_response).get("LoadBalancers", [])
            
            for lb in load_balancers:
                # Skip if not ALB
                if lb.get("Type") != "application":
                    continue
                    
                lb_arn = lb["LoadBalancerArn"]
                lb_name = lb["LoadBalancerName"]
                
                # Check for access logs
                attrs_command = f"aws elbv2 describe-load-balancer-attributes --load-balancer-arn {lb_arn} --region {region}"
                attrs_response = self.run_aws_command(attrs_command)
                
                if attrs_response:
                    attributes = json.loads(attrs_response).get("Attributes", [])
                    
                    # Check access logging
                    access_logs_enabled = False
                    deletion_protection_enabled = False
                    drop_invalid_headers_enabled = True  # Default to true, set to false if explicitly disabled
                    
                    for attr in attributes:
                        # Check for access logs
                        if attr["Key"] == "access_logs.s3.enabled" and attr["Value"] == "true":
                            access_logs_enabled = True
                        
                        # Check for deletion protection
                        if attr["Key"] == "deletion_protection.enabled" and attr["Value"] == "true":
                            deletion_protection_enabled = True
                        
                        # Check for invalid header handling
                        if attr["Key"] == "routing.http.drop_invalid_header_fields.enabled" and attr["Value"] == "false":
                            drop_invalid_headers_enabled = False
                    
                    if not access_logs_enabled:
                        albs_without_access_logs.append(f"{lb_name} ({region})")
                    
                    if not deletion_protection_enabled:
                        albs_without_deletion_protection.append(f"{lb_name} ({region})")
                    
                    if not drop_invalid_headers_enabled:
                        albs_allowing_invalid_headers.append(f"{lb_name} ({region})")
        
        # Report findings
        if albs_without_access_logs:
            self.add_finding(
                name="[ALB] Access logs not enabled",
                severity="Medium",
                description=f"The following Application Load Balancers do not have access logs enabled: {', '.join(albs_without_access_logs[:5])}" + 
                           (", and more..." if len(albs_without_access_logs) > 5 else ""),
                cli_command=f"# Check ALB attributes\naws elbv2 describe-load-balancer-attributes --load-balancer-arn LB_ARN --region REGION",
                impact="Without access logs, you cannot audit traffic patterns, troubleshoot issues, or detect potential security incidents affecting your applications.",
                recommendation="1. Enable access logs for all Application Load Balancers\n2. Configure an S3 bucket with appropriate permissions to receive the logs\n3. Set up log retention policies\n4. Consider using log analysis tools to monitor for suspicious activity"
            )
        
        if albs_without_deletion_protection:
            self.add_finding(
                name="[ALB] Deletion protection not enabled",
                severity="Low",
                description=f"The following Application Load Balancers do not have deletion protection enabled: {', '.join(albs_without_deletion_protection[:5])}" + 
                           (", and more..." if len(albs_without_deletion_protection) > 5 else ""),
                cli_command=f"# Check ALB attributes\naws elbv2 describe-load-balancer-attributes --load-balancer-arn LB_ARN --region REGION",
                impact="Without deletion protection, load balancers could be accidentally deleted, potentially causing service outages.",
                recommendation="1. Enable deletion protection for all production Application Load Balancers\n2. Implement proper change management processes for infrastructure changes\n3. Use Infrastructure as Code to manage and version load balancer configurations"
            )
        
        if albs_allowing_invalid_headers:
            self.add_finding(
                name="[ALB] Invalid HTTP headers not dropped",
                severity="Medium",
                description=f"The following Application Load Balancers are not configured to drop invalid HTTP headers: {', '.join(albs_allowing_invalid_headers[:5])}" + 
                           (", and more..." if len(albs_allowing_invalid_headers) > 5 else ""),
                cli_command=f"# Check ALB attributes\naws elbv2 describe-load-balancer-attributes --load-balancer-arn LB_ARN --region REGION",
                impact="Allowing invalid HTTP headers may enable HTTP request smuggling and HTTP desync attacks, potentially leading to security vulnerabilities in your application.",
                recommendation="1. Configure ALBs to drop invalid HTTP headers\n2. Use the AWS console or CLI to modify the 'routing.http.drop_invalid_header_fields.enabled' attribute\n3. Consider implementing additional HTTP security headers using Lambda@Edge or response headers in your application"
            )
        
        if not any([albs_without_access_logs, albs_without_deletion_protection, albs_allowing_invalid_headers]):
            print("✅ All Application Load Balancers have proper security configurations")

    def check_ebs_snapshots_recent(self):
        print("Checking for recent EBS volume snapshots...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        volumes_without_recent_snapshots = []
        instances_without_termination_protection = []
        
        # Threshold for "recent" - 7 days
        threshold_days = 7
        now = datetime.now(timezone.utc)
        threshold_date = now - datetime.timedelta(days=threshold_days)
        
        for region in regions:
            # Check volumes and their snapshots
            volumes_command = f"aws ec2 describe-volumes --region {region}"
            volumes_response = self.run_aws_command(volumes_command)
            
            if not volumes_response:
                continue
                
            volumes = json.loads(volumes_response).get("Volumes", [])
            
            for volume in volumes:
                volume_id = volume["VolumeId"]
                
                # Check for snapshots of this volume
                snapshots_command = f"aws ec2 describe-snapshots --filters Name=volume-id,Values={volume_id} --region {region}"
                snapshots_response = self.run_aws_command(snapshots_command)
                
                if not snapshots_response:
                    volumes_without_recent_snapshots.append(f"{volume_id} ({region})")
                    continue
                    
                snapshots = json.loads(snapshots_response).get("Snapshots", [])
                
                # Sort snapshots by start time (newest first)
                if snapshots:
                    snapshots.sort(key=lambda x: x.get("StartTime", ""), reverse=True)
                    newest_snapshot = snapshots[0]
                    start_time_str = newest_snapshot.get("StartTime", "")
                    
                    # Convert the ISO time string to datetime
                    try:
                        start_time = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
                        if start_time < threshold_date:
                            volumes_without_recent_snapshots.append(f"{volume_id} ({region})")
                    except (ValueError, TypeError):
                        # If time parsing fails, consider the snapshot outdated
                        volumes_without_recent_snapshots.append(f"{volume_id} ({region})")
                else:
                    volumes_without_recent_snapshots.append(f"{volume_id} ({region})")
            
            # Check EC2 instance termination protection
            instances_command = f"aws ec2 describe-instances --region {region}"
            instances_response = self.run_aws_command(instances_command)
            
            if not instances_response:
                continue
                
            reservations = json.loads(instances_response).get("Reservations", [])
            
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    
                    # Check termination protection
                    protection_command = f"aws ec2 describe-instance-attribute --instance-id {instance_id} --attribute disableApiTermination --region {region}"
                    protection_response = self.run_aws_command(protection_command)
                    
                    if protection_response:
                        protection = json.loads(protection_response).get("DisableApiTermination", {}).get("Value", False)
                        
                        if not protection:
                            # Get instance name if available
                            instance_name = "Unnamed"
                            for tag in instance.get("Tags", []):
                                if tag["Key"] == "Name":
                                    instance_name = tag["Value"]
                                    break
                                    
                            instances_without_termination_protection.append(f"{instance_id} ({instance_name}, {region})")
        
        # Report findings
        if volumes_without_recent_snapshots:
            self.add_finding(
                name="[EBS] Lack of recent snapshots for EBS volumes",
                severity="Medium",
                description=f"The following EBS volumes do not have recent snapshots (within {threshold_days} days): {', '.join(volumes_without_recent_snapshots[:5])}" + 
                           (", and more..." if len(volumes_without_recent_snapshots) > 5 else ""),
                cli_command=f"# List volumes\naws ec2 describe-volumes --region REGION\n\n# Check snapshots for a volume\naws ec2 describe-snapshots --filters Name=volume-id,Values=VOLUME_ID --region REGION",
                impact="Without recent snapshots, you risk data loss in case of volume failure or accidental deletion. Snapshots are essential for point-in-time recovery.",
                recommendation="1. Set up automated snapshot schedules for all EBS volumes\n2. Configure AWS Backup plans for EBS volumes\n3. Implement appropriate retention policies for snapshots\n4. Consider cross-region backup copies for critical data"
            )
        
        if instances_without_termination_protection:
            self.add_finding(
                name="[EC2] Instances without termination protection",
                severity="Medium",
                description=f"The following EC2 instances do not have termination protection enabled: {', '.join(instances_without_termination_protection[:5])}" + 
                           (", and more..." if len(instances_without_termination_protection) > 5 else ""),
                cli_command=f"# Check termination protection\naws ec2 describe-instance-attribute --instance-id INSTANCE_ID --attribute disableApiTermination --region REGION",
                impact="Without termination protection, instances can be accidentally terminated, potentially causing service disruptions and data loss.",
                recommendation="1. Enable termination protection for all production instances\n2. Implement proper change management processes for instance termination\n3. Use AWS CloudFormation stack policies to prevent accidental deletion\n4. Consider using AWS Service Catalog to standardize instance configurations"
            )
        
        if not any([volumes_without_recent_snapshots, instances_without_termination_protection]):
            print("✅ All EBS volumes have recent snapshots and EC2 instances have termination protection")

    def check_cloudwatch_metric_filters(self):
        print("Checking CloudWatch Logs metric filters for critical operations...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        missing_metric_filters = []
        
        # Critical CloudTrail events that should have metric filters
        critical_events = [
            {"name": "Root account usage", "pattern": "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"},
            {"name": "IAM policy changes", "pattern": "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"},
            {"name": "CloudTrail configuration changes", "pattern": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"},
            {"name": "Console sign-in failures", "pattern": "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"},
            {"name": "Authorization failures", "pattern": "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"},
            {"name": "Network ACL changes", "pattern": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"},
            {"name": "Security group changes", "pattern": "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"},
            {"name": "VPC changes", "pattern": "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"}
        ]
        
        for region in regions:
            # First get CloudTrail logs going to CloudWatch Logs
            trail_command = f"aws cloudtrail describe-trails --region {region}"
            trail_response = self.run_aws_command(trail_command)
            
            if not trail_response:
                continue
                
            trails = json.loads(trail_response).get("trailList", [])
            log_groups = []
            
            for trail in trails:
                if trail.get("CloudWatchLogsLogGroupArn"):
                    log_group_arn = trail.get("CloudWatchLogsLogGroupArn")
                    log_group_name = log_group_arn.split(":")[-1]
                    log_groups.append(log_group_name)
            
            # Check each log group for metric filters
            for log_group in log_groups:
                filters_command = f"aws logs describe-metric-filters --log-group-name {log_group} --region {region}"
                filters_response = self.run_aws_command(filters_command)
                
                if not filters_response:
                    for event in critical_events:
                        missing_metric_filters.append(f"{event['name']} ({region})")
                    continue
                    
                filters = json.loads(filters_response).get("metricFilters", [])
                
                # Check if each critical event has a corresponding metric filter
                for event in critical_events:
                    has_filter = False
                    for filter in filters:
                        # Basic check to see if filter patterns are similar
                        # This is a simplified comparison and might not catch all equivalences
                        if event["pattern"] in filter.get("filterPattern", ""):
                            has_filter = True
                            break
                    
                    if not has_filter:
                        missing_metric_filters.append(f"{event['name']} ({region})")
        
        # Deduplicate findings
        missing_metric_filters = list(set(missing_metric_filters))
        
        if missing_metric_filters:
            self.add_finding(
                name="[CloudWatch] Lack of metric filters for critical operations",
                severity="Medium",
                description=f"The following critical events do not have CloudWatch Logs metric filters: {', '.join(missing_metric_filters[:5])}" + 
                           (", and more..." if len(missing_metric_filters) > 5 else ""),
                cli_command=f"# List metric filters\naws logs describe-metric-filters --log-group-name LOG_GROUP_NAME --region REGION",
                impact="Without metric filters and alarms for critical operations, you cannot receive automated notifications of important security events, potentially delaying incident response.",
                recommendation="1. Create metric filters for critical CloudTrail events\n2. Set up CloudWatch alarms for these metric filters\n3. Configure notifications (e.g., SNS topics) for the alarms\n4. Ensure the notification endpoints are monitored"
            )
        else:
            print("✅ CloudWatch Logs have metric filters for critical operations")

    def check_s3_account_block_public_access(self):
        print("Checking for S3 account-level block public access...")
        command = "aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)"
        response = self.run_aws_command(command)
        
        if not response or "PublicAccessBlockConfiguration" not in response:
            self.add_finding(
                name="[S3] Account-level Block Public Access not configured",
                severity="High",
                description="S3 Block Public Access is not configured at the account level, which is the recommended security baseline.",
                cli_command=command,
                impact="Without account-level Block Public Access settings, individual buckets may be configured to allow public access, increasing the risk of data exposure.",
                recommendation="1. Enable all four Block Public Access settings at the account level\n2. Verify that this does not disrupt any legitimate public content\n3. Implement appropriate bucket-level policies and ACLs as needed\n4. Monitor for any attempts to change these settings"
            )
        else:
            try:
                config = json.loads(response).get("PublicAccessBlockConfiguration", {})
                all_enabled = (
                    config.get("BlockPublicAcls", False) and
                    config.get("IgnorePublicAcls", False) and
                    config.get("BlockPublicPolicy", False) and
                    config.get("RestrictPublicBuckets", False)
                )
                
                if not all_enabled:
                    self.add_finding(
                        name="[S3] Incomplete account-level Block Public Access configuration",
                        severity="Medium",
                        description="Not all S3 Block Public Access settings are enabled at the account level.",
                        cli_command=command,
                        impact="Incomplete Block Public Access settings may still allow public access to buckets through policies, ACLs, or other mechanisms, potentially exposing sensitive data.",
                        recommendation="1. Enable all four Block Public Access settings at the account level\n2. Verify that this does not disrupt any legitimate public content\n3. Regularly review bucket permissions to ensure compliance with your security policies"
                    )
                else:
                    print("✅ S3 account-level Block Public Access is properly configured")
            except Exception as e:
                print(f"Error checking S3 account-level Block Public Access: {str(e)}")

    def check_rds_enhanced_monitoring(self):
        print("Checking for RDS enhanced monitoring...")
        command = "aws ec2 describe-regions --output json"
        regions_response = self.run_aws_command(command)
        if not regions_response:
            self.add_issue("Unable to get AWS regions", "Unknown")
            return
        
        regions = [region["RegionName"] for region in json.loads(regions_response)["Regions"]]
        instances_without_enhanced_monitoring = []
        
        for region in regions:
            rds_command = f"aws rds describe-db-instances --region {region}"
            rds_response = self.run_aws_command(rds_command)
            
            if not rds_response:
                continue
                
            instances = json.loads(rds_response).get("DBInstances", [])
            
            for instance in instances:
                instance_id = instance["DBInstanceIdentifier"]
                enhanced_monitoring = instance.get("EnhancedMonitoring", "")
                
                if enhanced_monitoring != "default":
                    # Get instance name if available
                    instance_name = "Unnamed"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            instance_name = tag["Value"]
                            break
                    
                    instances_without_enhanced_monitoring.append(f"{instance_id} ({instance_name}, {region})")
        
        if instances_without_enhanced_monitoring:
            self.add_finding(
                name="[RDS] Enhanced monitoring not enabled",
                severity="Medium",
                description=f"The following RDS instances do not have enhanced monitoring enabled: {', '.join(instances_without_enhanced_monitoring[:5])}" + 
                           (", and more..." if len(instances_without_enhanced_monitoring) > 5 else ""),
                cli_command=f"# List RDS instances\n{rds_command}",
                impact="Enhanced monitoring allows for more granular performance metrics and alerts, which can help you proactively monitor and optimize your RDS instances. This is especially important for critical workloads.",
                recommendation="1. Enable enhanced monitoring for all RDS instances\n2. Configure appropriate CloudWatch alarms with detailed metrics\n3. Consider using AWS Organizations to enforce enhanced monitoring for critical workloads"
            )
        else:
            print("✅ All RDS instances have enhanced monitoring enabled")

if __name__ == "__main__":
    scanner = AWSSecurityScanner()
    scanner.run_all_checks() 
