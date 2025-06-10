"""
CloudGuard Services
Base classes and service registry for AWS security scanners
"""

from abc import ABC, abstractmethod
from typing import List
import boto3
import logging

from ..models import Finding


class BaseService(ABC):
    """Base class for all AWS service scanners"""
    
    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region = region
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def scan(self) -> List[Finding]:
        """Execute service scan and return findings"""
        pass
    
    @property
    @abstractmethod
    def service_name(self) -> str:
        """Return AWS service name"""
        pass