"""
S3 security checks
"""

import json
import logging
from typing import List
from botocore.exceptions import ClientError

from ..core.framework import SecurityCheck, Finding
from ..core.provider import AWSProvider


class S3BucketPublicReadCheck(SecurityCheck):
    """Check for S3 buckets with public read access"""
    
    def __init__(self):
        super().__init__()
        self.check_id = "s3_bucket_public_read"
        self.check_title = "S3 buckets should not allow public read access"
        self.severity = "HIGH"
        self.compliance_frameworks = ["CIS", "PCI-DSS", "GDPR"]
        self.service = "s3"
    
    def execute(self, aws_provider: AWSProvider) -> List[Finding]:
        findings = []
        
        try:
            s3_client = aws_provider.get_client('s3')
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket ACL
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    public_read = False
                    
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group':
                            uri = grantee.get('URI', '')
                            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                permission = grant.get('Permission')
                                if permission in ['READ', 'FULL_CONTROL']:
                                    public_read = True
                                    break
                except:
                    logging.error(f"Error in S3 bucket encryption check: {str(e)}")
                    
                    # Check bucket policy
                    try:
                        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                        policy = json.loads(policy_response['Policy'])
                        
                        for statement in policy.get('Statement', []):
                            if (statement.get('Effect') == 'Allow' and 
                                statement.get('Principal') == '*'):
                                public_read = True
                                break
                    except Exception as e:
                        logging.error(f"Error in S3 bucket encryption check: {str(e)}")
        except Exception as e:
                        logging.error(f"Error in S3 bucket encryption check: {str(e)}")
            
        return findings