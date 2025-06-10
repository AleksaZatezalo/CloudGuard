"""
EC2 security checks
"""

import logging
from typing import List
from botocore.exceptions import ClientError

from ..core.framework import SecurityCheck, Finding
from ..core.provider import AWSProvider


class EC2SecurityGroupOpenPortsCheck(SecurityCheck):
    """Check for EC2 security groups with open ports to internet"""
    
    def __init__(self):
        super().__init__()
        self.check_id = "ec2_sg_open_ports"
        self.check_title = "Security groups should not allow unrestricted access"
        self.severity = "HIGH"
        self.compliance_frameworks = ["CIS", "NIST", "PCI-DSS"]
        self.service = "ec2"
    
    def execute(self, aws_provider: AWSProvider) -> List[Finding]:
        findings = []
        
        for region in aws_provider.get_regions():
            try:
                ec2_client = aws_provider.get_client('ec2', region)
                security_groups = ec2_client.describe_security_groups()['SecurityGroups']
                
                for sg in security_groups:
                    sg_id = sg['GroupId']
                    sg_name = sg.get('GroupName', 'Unknown')
                    
                    for rule in sg.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                from_port = rule.get('FromPort', 0)
                                to_port = rule.get('ToPort', 65535)
                                protocol = rule.get('IpProtocol', 'all')
                                
                                # Check for dangerous open ports
                                dangerous_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                                is_dangerous = (from_port in dangerous_ports or 
                                              to_port in dangerous_ports or
                                              protocol == '-1')  # All protocols
                                
                                status = "FAIL" if is_dangerous else "PASS"
                                message = (f"Security group allows unrestricted access on "
                                         f"port {from_port}-{to_port} ({protocol})")
                                
                                finding = self.create_finding(
                                    resource_id=f"{sg_id} ({sg_name})",
                                    resource_type="SecurityGroup",
                                    region=region,
                                    status=status,
                                    message=message,
                                    remediation="Restrict source IP ranges to only necessary addresses"
                                )
                                findings.append(finding)
                                
            except Exception as e:
                logging.error(f"Error checking security groups in {region}: {str(e)}")
                
        return findings


class EC2InstancePublicIPCheck(SecurityCheck):
    """Check for EC2 instances with public IP addresses"""
    
    def __init__(self):
        super().__init__()
        self.check_id = "ec2_instance_public_ip"
        self.check_title = "EC2 instances should not have public IP addresses unless required"
        self.severity = "MEDIUM"
        self.compliance_frameworks = ["CIS", "NIST"]
        self.service = "ec2"
    
    def execute(self, aws_provider: AWSProvider) -> List[Finding]:
        findings = []
        
        for region in aws_provider.get_regions():
            try:
                ec2_client = aws_provider.get_client('ec2', region)
                
                # Get all instances
                paginator = ec2_client.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            instance_id = instance['InstanceId']
                            state = instance['State']['Name']
                            
                            # Only check running instances
                            if state != 'running':
                                continue
                            
                            public_ip = instance.get('PublicIpAddress')
                            has_public_ip = public_ip is not None
                            
                            # Get instance tags to check for exceptions
                            tags = {tag['Key']: tag['Value'] 
                                   for tag in instance.get('Tags', [])}
                            
                            # Skip if explicitly tagged as requiring public IP
                            if tags.get('PublicIPRequired', '').lower() == 'true':
                                continue
                            
                            if has_public_ip:
                                status = "FAIL"
                                message = f"Instance has public IP address: {public_ip}"
                                remediation = ("Move instance to private subnet or remove public IP. "
                                             "Use NAT Gateway or ALB for internet access.")
                            else:
                                status = "PASS"
                                message = "Instance does not have public IP address"
                                remediation = ""
                            
                            finding = self.create_finding(
                                resource_id=instance_id,
                                resource_type="EC2Instance",
                                region=region,
                                status=status,
                                message=message,
                                remediation=remediation
                            )
                            findings.append(finding)
                            
            except Exception as e:
                logging.error(f"Error checking EC2 instances in {region}: {str(e)}")
                
        return findings