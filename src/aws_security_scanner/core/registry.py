"""
Registry for managing security checks
"""

from typing import Dict, List, Optional
from .framework import SecurityCheck


class CheckRegistry:
    """Registry for managing security checks"""
    
    def __init__(self):
        self.checks: Dict[str, SecurityCheck] = {}
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default security checks"""
        from ..checks.s3 import S3BucketPublicReadCheck
        from ..checks.ec2 import EC2SecurityGroupOpenPortsCheck
        from ..checks.iam import IAMUserWithoutMFACheck
        
        default_checks = [
            S3BucketPublicReadCheck(),
            EC2SecurityGroupOpenPortsCheck(),
            IAMUserWithoutMFACheck()
        ]
        
        for check in default_checks:
            self.register_check(check)
    
    def register_check(self, check: SecurityCheck):
        """Register a security check"""
        self.checks[check.check_id] = check
    
    def get_check(self, check_id: str) -> Optional[SecurityCheck]:
        """Get a specific check by ID"""
        return self.checks.get(check_id)
    
    def get_checks_by_service(self, service: str) -> List[SecurityCheck]:
        """Get all checks for a specific service"""
        return [check for check in self.checks.values() 
                if check.service == service]
    
    def get_all_checks(self) -> List[SecurityCheck]:
        """Get all registered checks"""
        return list(self.checks.values())
    
    def list_checks(self) -> Dict[str, str]:
        """List all available checks"""
        return {check_id: check.check_title 
                for check_id, check in self.checks.items()}