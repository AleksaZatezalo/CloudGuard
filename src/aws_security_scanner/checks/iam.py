"""
IAM security checks
"""

import logging
from typing import List
from botocore.exceptions import ClientError

from ..core.framework import SecurityCheck, Finding
from ..core.provider import AWSProvider


class IAMUserWithoutMFACheck(SecurityCheck):
    """Check for IAM users without MFA enabled"""
    
    def __init__(self):
        super().__init__()
        self.check_id = "iam_user_no_mfa"
        self.check_title = "IAM users should have MFA enabled"
        self.severity = "HIGH"
        self.compliance_frameworks = ["CIS", "NIST", "FedRAMP"]
        self.service = "iam"
    
    def execute(self, aws_provider: AWSProvider) -> List[Finding]:
        findings = []
        
        try:
            iam_client = aws_provider.get_client('iam')
            
            # Get all IAM users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    # Check if user has MFA devices
                    mfa_devices = iam_client.list_mfa_devices(UserName=username)
                    has_mfa = len(mfa_devices['MFADevices']) > 0
                    
                    # Check if user has console access
                    try:
                        login_profile = iam_client.get_login_profile(UserName=username)
                        has_console_access = True
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchEntity':
                            has_console_access = False
                        else:
                            raise
                    
                    # Only flag users with console access and no MFA
                    if has_console_access and not has_mfa:
                        status = "FAIL"
                        message = "IAM user has console access but no MFA device configured"
                    elif has_console_access and has_mfa:
                        status = "PASS"
                        message = "IAM user has MFA device configured"
                    else:
                        status = "PASS"
                        message = "IAM user does not have console access"
                    
                    finding = self.create_finding(
                        resource_id=username,
                        resource_type="IAMUser",
                        region="global",
                        status=status,
                        message=message,
                        remediation="Enable MFA for IAM user in AWS Console"
                    )
                    findings.append(finding)
                    
        except Exception as e:
            logging.error(f"Error in IAM MFA check: {str(e)}")
            
        return findings


class IAMRootAccessKeyCheck(SecurityCheck):
    """Check for IAM root account access keys"""
    
    def __init__(self):
        super().__init__()
        self.check_id = "iam_root_access_keys"
        self.check_title = "Root account should not have access keys"
        self.severity = "CRITICAL"
        self.compliance_frameworks = ["CIS", "NIST", "FedRAMP"]
        self.service = "iam"
    
    def execute(self, aws_provider: AWSProvider) -> List[Finding]:
        findings = []
        
        try:
            iam_client = aws_provider.get_client('iam')
            
            # Get account summary
            account_summary = iam_client.get_account_summary()
            root_access_keys = account_summary['SummaryMap'].get('AccountAccessKeysPresent', 0)
            
            if root_access_keys > 0:
                status = "FAIL"
                message = f"Root account has {root_access_keys} access key(s)"
                remediation = ("Delete root access keys and use IAM users with "
                             "appropriate permissions instead")
            else:
                status = "PASS"
                message = "Root account does not have access keys"
                remediation = ""
            
            finding = self.create_finding(
                resource_id="root",
                resource_type="IAMRootAccount",
                region="global",
                status=status,
                message=message,
                remediation=remediation
            )
            findings.append(finding)
            
        except Exception as e:
            logging.error(f"Error in IAM root access key check: {str(e)}")
            
        return findings


class IAMPolicyTooPermissiveCheck(SecurityCheck):
    """Check for overly permissive IAM policies"""
    
    def __init__(self):
        super().__init__()
        self.check_id = "iam_policy_too_permissive"
        self.check_title = "IAM policies should follow principle of least privilege"
        self.severity = "HIGH"
        self.compliance_frameworks = ["CIS", "NIST", "FedRAMP"]
        self.service = "iam"
    
    def execute(self, aws_provider: AWSProvider) -> List[Finding]:
        findings = []
        
        try:
            iam_client = aws_provider.get_client('iam')
            
            # Check customer managed policies
            paginator = iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):  # Only customer managed
                for policy in page['Policies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['Arn']
                    
                    try:
                        # Get policy document
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        policy_doc = policy_version['PolicyVersion']['Document']
                        
                        # Check for overly permissive statements
                        is_too_permissive = False
                        permissive_reasons = []
                        
                        for statement in policy_doc.get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                resources = statement.get('Resource', [])
                                
                                # Convert to lists for easier processing
                                if isinstance(actions, str):
                                    actions = [actions]
                                if isinstance(resources, str):
                                    resources = [resources]
                                
                                # Check for wildcard actions
                                if '*' in actions:
                                    is_too_permissive = True
                                    permissive_reasons.append("Contains wildcard (*) action")
                                
                                # Check for wildcard resources
                                if '*' in resources:
                                    is_too_permissive = True
                                    permissive_reasons.append("Contains wildcard (*) resource")
                                
                                # Check for admin-like actions
                                admin_actions = [action for action in actions 
                                               if ':*' in action and action != 'iam:*']
                                if admin_actions:
                                    is_too_permissive = True
                                    permissive_reasons.append(f"Contains broad actions: {admin_actions}")
                        
                        if is_too_permissive:
                            status = "FAIL"
                            message = f"Policy is overly permissive: {'; '.join(permissive_reasons)}"
                            remediation = ("Review policy and apply principle of least privilege. "
                                         "Restrict actions and resources to minimum required.")
                        else:
                            status = "PASS"
                            message = "Policy follows principle of least privilege"
                            remediation = ""
                        
                        finding = self.create_finding(
                            resource_id=policy_name,
                            resource_type="IAMPolicy",
                            region="global",
                            status=status,
                            message=message,
                            remediation=remediation
                        )
                        findings.append(finding)
                        
                    except Exception as e:
                        logging.warning(f"Error checking policy {policy_name}: {str(e)}")
                        
        except Exception as e:
            logging.error(f"Error in IAM policy permissive check: {str(e)}")
            
        return findings