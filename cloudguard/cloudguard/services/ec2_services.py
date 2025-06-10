"""
CloudGuard EC2 Service Scanner
Security checks for EC2 instances, security groups, and AMIs
"""

import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError

from . import BaseService
from ..models import Finding, FindingSeverity, FindingStatus


class EC2Service(BaseService):
    """EC2 security scanner"""
    
    def __init__(self, session, region):
        super().__init__(session, region)
        self.ec2_client = session.client('ec2', region_name=region)
        self.instances = []
        self.security_groups = []
        self.amis = []
    
    @property
    def service_name(self) -> str:
        return "ec2"
    
    async def scan(self) -> List[Finding]:
        """Execute EC2 security scan"""
        self.logger.info(f"Scanning EC2 in {self.region}")
        
        # Discover resources
        await self._discover_resources()
        
        # Execute checks
        findings = []
        findings.extend(await self._check_public_instances())
        findings.extend(await self._check_security_groups())
        findings.extend(await self._check_public_amis())
        findings.extend(await self._check_monitoring())
        
        self.logger.info(f"EC2 scan completed: {len(findings)} findings")
        return findings
    
    async def _discover_resources(self):
        """Discover EC2 resources"""
        try:
            # Get instances
            paginator = self.ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] not in ['terminated', 'terminating']:
                            self.instances.append(instance)
            
            # Get security groups
            paginator = self.ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                self.security_groups.extend(page['SecurityGroups'])
            
            # Get AMIs (owned by account)
            try:
                response = self.ec2_client.describe_images(Owners=['self'])
                self.amis = response['Images']
            except ClientError as e:
                self.logger.warning(f"Failed to get AMIs: {e}")
                self.amis = []
            
        except ClientError as e:
            self.logger.error(f"Failed to discover EC2 resources: {e}")
    
    async def _check_public_instances(self) -> List[Finding]:
        """Check for instances with public IP addresses"""
        findings = []
        
        for instance in self.instances:
            instance_id = instance['InstanceId']
            public_ip = instance.get('PublicIpAddress')
            
            status = FindingStatus.FAIL if public_ip else FindingStatus.PASS
            
            finding = Finding(
                check_id="ec2_instance_public_ip",
                service="ec2",
                region=self.region,
                resource_id=instance_id,
                resource_arn=f"arn:aws:ec2:{self.region}::instance/{instance_id}",
                status=status,
                severity=FindingSeverity.HIGH,
                title="EC2 instance has public IP address",
                description="EC2 instances should not be directly accessible from the internet",
                risk="Direct internet access increases attack surface and exposure to threats",
                remediation="Remove public IP address and use load balancer, NAT gateway, or bastion host for access",
                resource_tags=self._extract_tags(instance.get('Tags', [])),
                compliance_mappings={
                    "cis": ["2.1"],
                    "aws_well_architected": ["SEC03-BP01"]
                },
                raw_data={
                    "public_ip": public_ip,
                    "instance_type": instance.get('InstanceType'),
                    "vpc_id": instance.get('VpcId'),
                    "subnet_id": instance.get('SubnetId'),
                    "state": instance.get('State', {}).get('Name')
                }
            )
            findings.append(finding)
        
        return findings
    
    async def _check_security_groups(self) -> List[Finding]:
        """Check for security groups open to the world"""
        findings = []
        sensitive_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
        
        for sg in self.security_groups:
            group_id = sg['GroupId']
            
            for rule in sg.get('IpPermissions', []):
                # Check for 0.0.0.0/0 access
                open_to_world = any(
                    ip_range.get('CidrIp') == '0.0.0.0/0'
                    for ip_range in rule.get('IpRanges', [])
                )
                
                if open_to_world:
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    # Check if sensitive ports are exposed
                    exposed_ports = [
                        port for port in sensitive_ports
                        if from_port <= port <= to_port
                    ]
                    
                    if exposed_ports:
                        finding = Finding(
                            check_id="ec2_security_group_open_to_world",
                            service="ec2",
                            region=self.region,
                            resource_id=group_id,
                            resource_arn=f"arn:aws:ec2:{self.region}::security-group/{group_id}",
                            status=FindingStatus.FAIL,
                            severity=FindingSeverity.CRITICAL,
                            title="Security group allows unrestricted access to sensitive ports",
                            description="Security group allows inbound access from 0.0.0.0/0 to sensitive ports",
                            risk="Unrestricted access exposes resources to attacks from anywhere on the internet",
                            remediation="Restrict security group rules to specific IP ranges or security groups",
                            resource_tags=self._extract_tags(sg.get('Tags', [])),
                            compliance_mappings={
                                "cis": ["4.1", "4.2"],
                                "pci_dss": ["1.2.1", "1.3.1"]
                            },
                            raw_data={
                                "group_name": sg.get('GroupName'),
                                "vpc_id": sg.get('VpcId'),
                                "exposed_ports": exposed_ports,
                                "rule": rule
                            }
                        )
                        findings.append(finding)
        
        return findings
    
    async def _check_public_amis(self) -> List[Finding]:
        """Check for public AMI images"""
        findings = []
        
        for ami in self.amis:
            image_id = ami['ImageId']
            is_public = ami.get('Public', False)
            
            status = FindingStatus.FAIL if is_public else FindingStatus.PASS
            
            finding = Finding(
                check_id="ec2_ami_public",
                service="ec2",
                region=self.region,
                resource_id=image_id,
                resource_arn=f"arn:aws:ec2:{self.region}::image/{image_id}",
                status=status,
                severity=FindingSeverity.MEDIUM,
                title="AMI image is publicly accessible",
                description="AMI images should not be publicly shared to prevent data exposure",
                risk="Public AMIs may contain sensitive data, applications, or configurations",
                remediation="Make AMI private and share only with specific AWS accounts when necessary",
                resource_tags=self._extract_tags(ami.get('Tags', [])),
                compliance_mappings={
                    "cis": ["2.2"],
                    "aws_well_architected": ["SEC08-BP02"]
                },
                raw_data={
                    "name": ami.get('Name'),
                    "description": ami.get('Description'),
                    "public": is_public,
                    "creation_date": ami.get('CreationDate'),
                    "state": ami.get('State')
                }
            )
            findings.append(finding)
        
        return findings
    
    async def _check_monitoring(self) -> List[Finding]:
        """Check if instances have detailed monitoring enabled"""
        findings = []
        
        for instance in self.instances:
            instance_id = instance['InstanceId']
            monitoring_enabled = instance.get('Monitoring', {}).get('State') == 'enabled'
            
            status = FindingStatus.PASS if monitoring_enabled else FindingStatus.FAIL
            
            finding = Finding(
                check_id="ec2_instance_monitoring_enabled",
                service="ec2",
                region=self.region,
                resource_id=instance_id,
                resource_arn=f"arn:aws:ec2:{self.region}::instance/{instance_id}",
                status=status,
                severity=FindingSeverity.LOW,
                title="EC2 instance detailed monitoring not enabled",
                description="EC2 instances should have detailed CloudWatch monitoring enabled",
                risk="Limited visibility into instance performance and security events",
                remediation="Enable detailed monitoring through the EC2 console or API",
                resource_tags=self._extract_tags(instance.get('Tags', [])),
                compliance_mappings={
                    "aws_well_architected": ["OPS04-BP01"]
                },
                raw_data={
                    "monitoring_enabled": monitoring_enabled,
                    "instance_type": instance.get('InstanceType')
                }
            )
            findings.append(finding)
        
        return findings
    
    def _extract_tags(self, tags_list: List[Dict]) -> Dict[str, str]:
        """Extract tags from AWS tag format"""
        return {tag.get('Key', ''): tag.get('Value', '') for tag in tags_list}
