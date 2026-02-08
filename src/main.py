"""Main application entry point and CLI interface."""

import asyncio
import click
import json
from typing import Optional, List
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from loguru import logger

from .core.config import config
from .core.database import db_manager
from .core.logger import setup_logging
from .monitor.service import monitoring_service
from .scanner.engine import scan_engine
from .compliance.engine import compliance_engine
from .analytics.roi import roi_calculator
from .analytics.predictor import success_predictor
from .reporting.generator import report_generator
from .reporting.templates import template_manager

# Rich console for beautiful output
console = Console()

@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config_file, verbose):
    """Bug Bounty Hunting Framework - Automated ethical security research."""
    ctx.ensure_object(dict)
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(log_level)
    
    # Initialize configuration
    if config_file:
        config.config_file = config_file
        config._load_config()
    
    # Initialize database
    try:
        db_manager.init_db()
        console.print("✓ Database initialized", style="green")
    except Exception as e:
        console.print(f"✗ Database initialization failed: {e}", style="red")
        raise click.Abort()

@cli.group()
def monitor():
    """Program monitoring commands."""
    pass

@monitor.command('start')
@click.option('--interval', '-i', default=300, help='Check interval in seconds')
def monitor_start(interval):
    """Start program monitoring service."""
    async def start_monitoring():
        config.monitor.check_interval = interval
        console.print(f"Starting program monitoring (interval: {interval}s)", style="blue")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Monitoring programs...", total=None)
            
            try:
                await monitoring_service.start()
            except KeyboardInterrupt:
                progress.update(task, description="Stopping monitoring...")
                await monitoring_service.stop()
                console.print("✓ Monitoring stopped", style="yellow")
    
    asyncio.run(start_monitoring())

@monitor.command('status')
def monitor_status():
    """Get monitoring service status."""
    async def get_status():
        try:
            status = await monitoring_service.get_status()
            
            table = Table(title="Program Monitoring Status")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Running", "Yes" if status['running'] else "No")
            table.add_row("Active Monitors", ", ".join(status['monitors']))
            table.add_row("Check Interval", f"{status['check_interval']}s")
            table.add_row("Programs Today", str(status['programs_discovered_today']))
            
            for platform, count in status['program_counts'].items():
                table.add_row(f"{platform.title()} Programs", str(count))
            
            console.print(table)
            
        except Exception as e:
            console.print(f"✗ Failed to get status: {e}", style="red")
    
    asyncio.run(get_status())

@monitor.command('update')
def monitor_update():
    """Force update all programs."""
    async def force_update():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Updating programs...", total=None)
            
            try:
                await monitoring_service.force_update_all()
                progress.update(task, description="Update completed")
                console.print("✓ All programs updated", style="green")
            except Exception as e:
                console.print(f"✗ Update failed: {e}", style="red")
    
    asyncio.run(force_update())

@cli.group()
def scan():
    """Scanning commands."""
    pass

@scan.command('start')
@click.argument('program_id', type=int)
@click.argument('scan_type', type=click.Choice(['subdomain', 'port', 'vulnerability']))
@click.argument('target')
@click.option('--intensive', is_flag=True, help='Use intensive scanning')
@click.option('--depth', default=2, help='Crawl depth for vulnerability scans')
def scan_start(program_id, scan_type, target, intensive, depth):
    """Start a new scan."""
    async def start_scan():
        try:
            scan_kwargs = {}
            if scan_type == 'subdomain':
                scan_kwargs['intensive'] = intensive
            elif scan_type == 'vulnerability':
                scan_kwargs['crawl_depth'] = depth
            
            scan_id = await scan_engine.queue_scan(program_id, scan_type, target, **scan_kwargs)
            
            console.print(f"✓ Scan queued with ID: {scan_id}", style="green")
            console.print(f"Type: {scan_type}, Target: {target}")
            
            # Start scan engine if not running
            if not scan_engine.running:
                console.print("Starting scan engine...", style="blue")
                await scan_engine.start()
            
        except Exception as e:
            console.print(f"✗ Failed to start scan: {e}", style="red")
    
    asyncio.run(start_scan())

@scan.command('list')
def scan_list():
    """List active scans."""
    async def list_scans():
        try:
            scans = await scan_engine.list_active_scans()
            
            if not scans:
                console.print("No active scans", style="yellow")
                return
            
            table = Table(title="Active Scans")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="blue")
            table.add_column("Target", style="green")
            table.add_column("Started", style="yellow")
            table.add_column("Requests", style="magenta")
            table.add_column("Findings", style="red")
            
            for scan in scans:
                table.add_row(
                    str(scan['id']),
                    scan['scan_type'],
                    scan['target'][:50] + "..." if len(scan['target']) > 50 else scan['target'],
                    scan['started_at'].strftime('%H:%M:%S') if scan['started_at'] else 'N/A',
                    str(scan['requests_made']),
                    str(scan['findings_discovered'])
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"✗ Failed to list scans: {e}", style="red")
    
    asyncio.run(list_scans())

@scan.command('stop')
@click.argument('scan_id', type=int)
def scan_stop(scan_id):
    """Stop a specific scan."""
    async def stop_scan():
        try:
            success = await scan_engine.stop_scan(scan_id)
            if success:
                console.print(f"✓ Scan {scan_id} stopped", style="green")
            else:
                console.print(f"✗ Failed to stop scan {scan_id}", style="red")
                
        except Exception as e:
            console.print(f"✗ Error stopping scan: {e}", style="red")
    
    asyncio.run(stop_scan())

@cli.group()
def analytics():
    """Analytics and ROI commands."""
    pass

@analytics.command('roi')
@click.argument('program_id', type=int)
@click.argument('target')
def analytics_roi(program_id, target):
    """Calculate ROI for a target."""
    async def calculate_roi():
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Calculating ROI...", total=None)
                
                metrics = await roi_calculator.calculate_target_metrics(program_id, target)
                
                progress.update(task, description="ROI calculation completed")
            
            table = Table(title=f"ROI Analysis: {metrics.target}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Expected Bounty", f"${metrics.expected_bounty:.2f}")
            table.add_row("ROI Score", f"{metrics.roi_score:.1f}")
            table.add_row("Priority Score", f"{metrics.priority_score:.1f}")
            table.add_row("Success Rate", f"{metrics.historical_success_rate:.1%}")
            table.add_row("Competition Level", f"{metrics.competition_level:.1%}")
            table.add_row("Time to Bug", f"{metrics.time_to_first_bug:.1f} hours")
            table.add_row("Confidence", f"{metrics.confidence:.1%}")
            
            console.print(table)
            
        except Exception as e:
            console.print(f"✗ ROI calculation failed: {e}", style="red")
    
    asyncio.run(calculate_roi())

@analytics.command('predict')
@click.argument('program_id', type=int)
@click.argument('target')
def analytics_predict(program_id, target):
    """Get ML predictions for a target."""
    async def get_predictions():
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Getting predictions...", total=None)
                
                recommendations = await success_predictor.get_recommendations(program_id, target)
                
                progress.update(task, description="Predictions completed")
            
            console.print(f"\n[bold blue]ML Predictions for {target}[/bold blue]\n")
            
            console.print(f"Success Probability: [green]{recommendations['success_probability']:.1%}[/green]")
            console.print(f"Expected Bounty: [yellow]${recommendations['expected_bounty_range'][0]:.0f} - ${recommendations['expected_bounty_range'][1]:.0f}[/yellow]")
            console.print(f"Estimated Time: [cyan]{recommendations['estimated_time_hours']:.1f} hours[/cyan]")
            console.print(f"Expected Value: [magenta]${recommendations['expected_value']:.2f}[/magenta]")
            console.print(f"Confidence: [blue]{recommendations['confidence']:.1%}[/blue]")
            
            if recommendations['recommendations']:
                console.print("\n[bold]Recommendations:[/bold]")
                for i, rec in enumerate(recommendations['recommendations'], 1):
                    console.print(f"{i}. {rec}")
            
        except Exception as e:
            console.print(f"✗ Prediction failed: {e}", style="red")
    
    asyncio.run(get_predictions())

@cli.group()
def report():
    """Report generation commands."""
    pass

@report.command('generate')
@click.argument('vulnerability_id', type=int)
@click.argument('platform')
@click.option('--template', help='Specific template to use')
@click.option('--preview', is_flag=True, help='Preview only, do not save')
def report_generate(vulnerability_id, platform, template, preview):
    """Generate a report for a vulnerability."""
    async def generate_report():
        try:
            if preview:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Generating preview...", total=None)
                    
                    preview_data = await report_generator.preview_report(
                        vulnerability_id, platform, template
                    )
                    
                    progress.update(task, description="Preview completed")
                
                console.print(f"\n[bold blue]Report Preview[/bold blue]\n")
                console.print(f"Template: {preview_data['template_name']}")
                console.print(f"Title: {preview_data['title']}")
                console.print(f"Validation: {'✓ Valid' if preview_data['validation']['valid'] else '✗ Invalid'}")
                
                if not preview_data['validation']['valid']:
                    console.print(f"Missing required fields: {', '.join(preview_data['validation']['missing_required'])}", style="red")
                
                if preview_data['preview_content']:
                    console.print("\n[bold]Content Preview:[/bold]")
                    console.print(preview_data['preview_content'][:500] + "..." if len(preview_data['preview_content']) > 500 else preview_data['preview_content'])
            
            else:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Generating report...", total=None)
                    
                    generated_report = await report_generator.generate_report(
                        vulnerability_id, platform, template
                    )
                    
                    progress.update(task, description="Report generated")
                
                console.print(f"✓ Report generated successfully", style="green")
                console.print(f"Title: {generated_report.title}")
                console.print(f"Platform: {generated_report.platform}")
                console.print(f"Evidence files: {len(generated_report.evidence_files)}")
                console.print(f"Generated at: {generated_report.generated_at}")
            
        except Exception as e:
            console.print(f"✗ Report generation failed: {e}", style="red")
    
    asyncio.run(generate_report())

@report.command('templates')
def report_templates():
    """List available report templates."""
    templates = template_manager.list_templates()
    
    table = Table(title="Available Report Templates")
    table.add_column("Name", style="cyan")
    table.add_column("Platform", style="blue")
    table.add_column("Vulnerability Type", style="green")
    table.add_column("Required Fields", style="yellow")
    
    for template in templates:
        table.add_row(
            template['name'],
            template['platform'],
            template['vulnerability_type'],
            str(len(template['required_fields']))
        )
    
    console.print(table)

@cli.group()
def compliance():
    """Compliance and safety commands."""
    pass

@compliance.command('status')
@click.argument('program_id', type=int)
def compliance_status(program_id):
    """Get compliance status for a program."""
    async def get_compliance_status():
        try:
            status = await compliance_engine.get_compliance_status(program_id)
            
            if 'error' in status:
                console.print(f"✗ {status['error']}", style="red")
                return
            
            table = Table(title=f"Compliance Status - Program {program_id}")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Kill Switch", "Active" if status['kill_switch_active'] else "Inactive")
            table.add_row("Scope Rules", str(status['scope_rules_count']))
            table.add_row("Out-of-Scope Rules", str(status['out_of_scope_rules_count']))
            table.add_row("Requests/Second", str(status['rate_limits']['requests_per_second']))
            table.add_row("Requests/Minute", str(status['rate_limits']['requests_per_minute']))
            table.add_row("Concurrent Requests", str(status['rate_limits']['concurrent_requests']))
            
            console.print(table)
            
            # Show current usage
            usage = status['current_usage']
            console.print(f"\n[bold]Current Usage:[/bold]")
            console.print(f"Active requests: {usage['active_concurrent_requests']}")
            console.print(f"Requests last minute: {usage['requests_last_minute']}")
            
        except Exception as e:
            console.print(f"✗ Failed to get compliance status: {e}", style="red")
    
    asyncio.run(get_compliance_status())

@compliance.command('check')
@click.argument('program_id', type=int)
@click.argument('target')
@click.option('--action', default='scan', help='Action to check')
def compliance_check(program_id, target, action):
    """Check compliance for a specific action."""
    async def check_compliance():
        try:
            result = await compliance_engine.check_compliance(program_id, action, target)
            
            console.print(f"\n[bold blue]Compliance Check: {target}[/bold blue]\n")
            console.print(f"Compliant: {'✓ Yes' if result['compliant'] else '✗ No'}")
            console.print(f"Allowed: {'✓ Yes' if result['allowed'] else '✗ No'}")
            
            if result['violations']:
                console.print(f"\n[bold red]Violations:[/bold red]")
                for violation in result['violations']:
                    console.print(f"• {violation}")
            
            if result['warnings']:
                console.print(f"\n[bold yellow]Warnings:[/bold yellow]")
                for warning in result['warnings']:
                    console.print(f"• {warning}")
            
        except Exception as e:
            console.print(f"✗ Compliance check failed: {e}", style="red")
    
    asyncio.run(check_compliance())

@cli.command('init')
@click.option('--sample-data', is_flag=True, help='Load sample data')
def init_framework(sample_data):
    """Initialize the bug bounty framework."""
    console.print("[bold blue]Initializing Bug Bounty Hunting Framework[/bold blue]\n")
    
    try:
        # Initialize database
        db_manager.init_db()
        console.print("✓ Database initialized", style="green")
        
        # Train ML models
        if sample_data:
            async def train_models():
                await success_predictor.train_models()
                console.print("✓ ML models trained", style="green")
            
            asyncio.run(train_models())
        
        # Save default configuration
        config.save_config()
        console.print("✓ Configuration saved", style="green")
        
        console.print("\n[bold green]Framework initialized successfully![/bold green]")
        console.print("\nNext steps:")
        console.print("1. Start monitoring: bbhk monitor start")
        console.print("2. Check program status: bbhk monitor status")
        console.print("3. Start scanning: bbhk scan start <program_id> <scan_type> <target>")
        
    except Exception as e:
        console.print(f"✗ Initialization failed: {e}", style="red")
        raise click.Abort()

@cli.command('version')
def version():
    """Show version information."""
    from . import __version__
    console.print(f"Bug Bounty Hunting Framework v{__version__}")

if __name__ == "__main__":
    cli()