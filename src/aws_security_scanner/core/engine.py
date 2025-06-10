"""
Core scanning engine that orchestrates security checks
"""

import logging
import concurrent.futures
from typing import List, Optional
from .framework import Finding, SecurityCheck
from .provider import AWSProvider
from .registry import CheckRegistry


class ScanEngine:
    """Core scanning engine that orchestrates security checks"""
    
    def __init__(self, aws_provider: AWSProvider, registry: CheckRegistry):
        self.aws_provider = aws_provider
        self.registry = registry
    
    def run_scan(self, check_ids: List[str] = None, 
                services: List[str] = None,
                parallel: bool = True) -> List[Finding]:
        """Run security scan with specified checks or services"""
        
        # Determine which checks to run
        if check_ids:
            checks = [self.registry.get_check(check_id) for check_id in check_ids]
            checks = [check for check in checks if check is not None]
        elif services:
            checks = []
            for service in services:
                checks.extend(self.registry.get_checks_by_service(service))
        else:
            checks = self.registry.get_all_checks()
        
        if not checks:
            logging.warning("No checks selected for scanning")
            return []
        
        logging.info(f"Running {len(checks)} security checks...")
        
        all_findings = []
        
        if parallel and len(checks) > 1:
            # Run checks in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_check = {executor.submit(check.execute, self.aws_provider): check 
                                 for check in checks}
                
                for future in concurrent.futures.as_completed(future_to_check):
                    check = future_to_check[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        logging.info(f"Completed check: {check.check_title} "
                                   f"({len(findings)} findings)")
                    except Exception as e:
                        logging.error(f"Check {check.check_title} failed: {str(e)}")
        else:
            # Run checks sequentially
            for check in checks:
                try:
                    findings = check.execute(self.aws_provider)
                    all_findings.extend(findings)
                    logging.info(f"Completed check: {check.check_title} "
                               f"({len(findings)} findings)")
                except Exception as e:
                    logging.error(f"Check {check.check_title} failed: {str(e)}")
        
        logging.info(f"Scan completed. Total findings: {len(all_findings)}")
        return all_findings