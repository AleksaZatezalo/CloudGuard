"""
CloudGuard CLI Interface
Command-line interface for the CloudGuard AWS scanner
"""

import asyncio
import json
import sys
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanner import CloudGuardScanner
from .models import ScanConfig, AWSCredentials, FindingStatus, FindingSeverity


console = Console()


@click.group()
@click.version_option(version="1.0.0")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, verbose):
    """CloudGuard AWS Security Scanner"""
    ctx.ensure_object(dict)
    
    # Configure logging
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Reduce noise from boto3
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


@cli.command()
@click.option('--profile', help='AWS profile to use')
@click.option('--access-key-id', help='AWS access key ID')
@click.option('--secret-access-key', help='AWS secret access key')
@click.option('--session-token', help='AWS session token')
@click.option('--role-arn', help='ARN of IAM role to assume')
@click.option('--external-id', help='External ID for role assumption')
@click.option('--regions', '-r', multiple=True, default=['us-east-1'], help='AWS regions to scan')
@click.option('--services', '-s', multiple=True, help='Services to scan (ec2, s3)')
@click.option('--checks', '-c', multiple=True, help='Specific checks to run')
@click.option('--excluded-services', multiple=True, help='Services to exclude')
@click.option('--excluded-checks', multiple=True, help='Checks to exclude')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--parallel/--no-parallel', default=True, help='Enable parallel execution')
@click.option('--max-workers', type=int, default=10, help='Maximum parallel workers')
@click.option('--timeout', type=int, default=300, help='Timeout in seconds')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode - JSON output only')
@click.option('--pretty', is_flag=True, help='Pretty print JSON output')
def scan(
    profile, access_key_id, secret_access_key, session_token,
    role_arn, external_id, regions, services, checks,
    excluded_services, excluded_checks, output, parallel,
    max_workers, timeout, quiet, pretty
):
    """Execute AWS security scan"""
    
    if not quiet:
        console.print("[bold blue]🛡️ CloudGuard AWS Security Scanner[/bold blue]")
        console.print(f"[dim]Scanning regions: {', '.join(regions)}[/dim]")
    
    # Create credentials
    credentials = AWSCredentials(
        profile=profile,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        role_arn=role_arn,
        external_id=external_id,
        region=regions[0]
    )
    
    # Create scan configuration
    config = ScanConfig(
        credentials=credentials,
        regions=list(regions),
        services=list(services) if services else None,
        checks=list(checks) if checks else None,
        excluded_services=list(excluded_services),
        excluded_checks=list(excluded_checks),
        parallel_execution=parallel,
        max_workers=max_workers,
        timeout=timeout
    )
    
    # Run scan
    try:
        result = asyncio.run(_execute_scan(config, quiet))
        
        # Format JSON output
        if pretty:
            json_output = json.dumps(result, indent=2, default=str)
        else:
            json_output = json.dumps(result, default=str)
        
        # Write output
        if output:
            Path(output).write_text(json_output, encoding='utf-8')
            if not quiet:
                console.print(f"[green]✅ Results written to {output}[/green]")
        else:
            print(json_output)
        
        # Exit with error code if critical/high findings
        if not quiet:
            failed_findings = [
                f for f in result['findings'] 
                if f['status'] == 'FAIL' and f['severity'] in ['critical', 'high']
            ]
            if failed_findings:
                sys.exit(1)
                
    except Exception as e:
        error_result = {
            "error": True,
            "message": str(e),
            "metadata": {
                "scanner_version": "1.0.0"
            }
        }
        
        if output:
            Path(output).write_text(json.dumps(error_result), encoding='utf-8')
        else:
            print(json.dumps(error_result))
        
        if not quiet:
            console.print(f"[red]❌ Scan failed: {e}[/red]")
        sys.exit(1)


async def _execute_scan(config: ScanConfig, quiet: bool) -> dict:
    """Execute the scan and return results"""
    scanner = CloudGuardScanner(config)
    
    if not quiet:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning AWS resources...", total=None)
            result = await scanner.scan()
            progress.update(task, description="Scan completed!")
    else:
        result = await scanner.scan()
    
    if not quiet:
        _display_summary(result.to_dict())
    
    return result.to_dict()


def _display_summary(result: dict):
    """Display scan summary in rich format"""
    summary = result['summary']
    
    # Main summary table
    table = Table(title="📊 Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", width=20)
    table.add_column("Value", style="green", width=15)
    table.add_column("Details", style="dim", width=30)
    
    table.add_row("Total Findings", str(summary['total_findings']), "All security checks executed")
    table.add_row("Failed Checks", str(summary['failed_checks']), "Security issues found")
    table.add_row("Passed Checks", str(summary['passed_checks']), "Compliant resources")
    table.add_row("Risk Score", f"{summary['risk_score']}/100", "Overall security risk level")
    table.add_row("Compliance", f"{summary['compliance_status']['percentage']:.1f}%", summary['compliance_status']['status'])
    
    console.print(table)
    
    # Severity breakdown
    if summary['failed_checks'] > 0:
        severity_table = Table(title="🎯 Issues by Severity", show_header=True, header_style="bold red")
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="magenta")
        severity_table.add_column("Priority", style="dim")
        
        severity_info = {
            "critical": ("🔴", "Immediate action required"),
            "high": ("🟠", "Address within 24 hours"),
            "medium": ("🟡", "Address within 1 week"),
            "low": ("🟢", "Address when convenient")
        }
        
        for severity, count in summary['by_severity'].items():
            if count > 0 and severity != 'info':
                emoji, priority = severity_info.get(severity, ("⚪", ""))
                severity_table.add_row(f"{emoji} {severity.upper()}", str(count), priority)
        
        console.print(severity_table)


@cli.command()
def list_checks():
    """List all available security checks"""
    checks = {
        "EC2": [
            "ec2_instance_public_ip - Check for instances with public IP addresses",
            "ec2_security_group_open_to_world - Find security groups open to 0.0.0.0/0",
            "ec2_ami_public - Identify public AMI images",
            "ec2_instance_monitoring_enabled - Check CloudWatch monitoring status"
        ],
        "S3": [
            "s3_bucket_public_access - Detect publicly accessible buckets",
            "s3_bucket_encryption_enabled - Verify bucket encryption",
            "s3_bucket_versioning_enabled - Check versioning configuration",
            "s3_bucket_logging_enabled - Validate access logging"
        ]
    }
    
    console.print("[bold blue]Available Security Checks[/bold blue]\n")
    
    for service, service_checks in checks.items():
        console.print(f"[bold green]{service}:[/bold green]")
        for check in service_checks:
            console.print(f"  • {check}")
        console.print()


@cli.command()
def list_services():
    """List all available AWS services"""
    services = {
        "ec2": "Amazon Elastic Compute Cloud - Instances, Security Groups, AMIs",
        "s3": "Amazon Simple Storage Service - Buckets and configurations"
    }
    
    console.print("[bold blue]Available AWS Services[/bold blue]\n")
    
    for service, description in services.items():
        console.print(f"[bold green]{service}[/bold green]: {description}")


def main():
    """Main CLI entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()