"""
Output formatting and report generation
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from .framework import Finding


class OutputEngine:
    """Handle output formatting and report generation"""
    
    @staticmethod
    def format_json(findings: List[Finding], account_id: str, 
                   metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Format findings as JSON report"""
        
        if metadata is None:
            metadata = {}
        
        # Calculate summary statistics
        total_findings = len(findings)
        by_status = {}
        by_severity = {}
        by_service = {}
        
        for finding in findings:
            # Count by status
            status = finding.status
            by_status[status] = by_status.get(status, 0) + 1
            
            # Count by severity
            severity = finding.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count by service (extract from check_id)
            service = finding.check_id.split('_')[0] if '_' in finding.check_id else 'unknown'
            by_service[service] = by_service.get(service, 0) + 1
        
        report = {
            "metadata": {
                "tool": "aws-security-scanner",
                "version": "1.0.0",
                "scan_timestamp": datetime.utcnow().isoformat(),
                "account_id": account_id,
                **metadata
            },
            "summary": {
                "total_findings": total_findings,
                "by_status": by_status,
                "by_severity": by_severity,
                "by_service": by_service
            },
            "findings": [finding.to_dict() for finding in findings]
        }
        
        return report
    
    @staticmethod
    def save_report(report: Dict[str, Any], output_file: str):
        """Save JSON report to file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, sort_keys=True)
                
            logging.info(f"Report saved to: {output_path}")
            
        except Exception as e:
            logging.error(f"Error saving report: {str(e)}")
            raise