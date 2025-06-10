"""
Core framework classes and interfaces for security checks
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .provider import AWSProvider


@dataclass
class Finding:
    """Security finding data structure"""
    check_id: str
    check_title: str
    resource_id: str
    resource_type: str
    resource_region: str
    status: str  # PASS, FAIL, ERROR
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    compliance_frameworks: List[str]
    timestamp: str = None
    remediation: str = ""
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON output"""
        return asdict(self)


class SecurityCheck(ABC):
    """Abstract base class for security checks"""
    
    def __init__(self):
        self.check_id: str = ""
        self.check_title: str = ""
        self.severity: str = "MEDIUM"
        self.compliance_frameworks: List[str] = []
        self.service: str = ""
        
    @abstractmethod
    def execute(self, aws_provider: 'AWSProvider') -> List[Finding]:
        """Execute the security check and return findings"""
        pass
    
    def create_finding(self, resource_id: str, resource_type: str, 
                      region: str, status: str, message: str,
                      remediation: str = "") -> Finding:
        """Helper method to create a finding"""
        return Finding(
            check_id=self.check_id,
            check_title=self.check_title,
            resource_id=resource_id,
            resource_type=resource_type,
            resource_region=region,
            status=status,
            severity=self.severity,
            message=message,
            compliance_frameworks=self.compliance_frameworks,
            remediation=remediation
        )