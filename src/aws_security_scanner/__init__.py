"""
AWS Security Scanner - A modular cloud security assessment tool

This package provides a comprehensive framework for scanning AWS environments
for security misconfigurations and compliance violations.
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__email__ = "security@example.com"

from .core.framework import SecurityCheck, Finding
from .core.provider import AWSProvider
from .core.engine import ScanEngine
from .core.registry import CheckRegistry
from .core.output import OutputEngine

__all__ = [
    "SecurityCheck",
    "Finding", 
    "AWSProvider",
    "ScanEngine",
    "CheckRegistry",
    "OutputEngine",
]