"""Report generation engine with automated evidence collection."""

import os
import json
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlparse
from loguru import logger

from .templates import template_manager, ReportTemplate
from ..core.database import Vulnerability, Report, Program, get_async_db
from ..core.config import config
from ..core.utils import calculate_cvss_score

@dataclass
class EvidenceFile:
    """Represents an evidence file."""
    filename: str
    filepath: str
    file_type: str  # 'screenshot', 'video', 'request', 'response', 'log'
    description: str
    size_bytes: int = 0

@dataclass
class GeneratedReport:
    """Represents a generated report."""
    vulnerability_id: int
    platform: str
    title: str
    content: str
    evidence_files: List[EvidenceFile] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class ReportGenerator:
    """Advanced report generator with evidence collection."""
    
    def __init__(self):
        """Initialize report generator."""
        self.output_dir = Path(config.reporting.output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Evidence collection settings
        self.screenshot_enabled = config.reporting.auto_screenshot
        self.video_enabled = config.reporting.video_poc_enabled
        self.max_file_size = config.reporting.max_report_size_mb * 1024 * 1024
    
    async def generate_report(self, vulnerability_id: int, platform: str, 
                            template_name: Optional[str] = None) -> GeneratedReport:
        """Generate a complete report for a vulnerability."""
        try:
            # Get vulnerability data
            vulnerability_data = await self._get_vulnerability_data(vulnerability_id)
            if not vulnerability_data:
                raise ValueError(f"Vulnerability {vulnerability_id} not found")
            
            # Determine template
            if not template_name:
                template_name = self._determine_template(platform, vulnerability_data['vulnerability_type'])
            
            # Collect evidence
            evidence_files = await self._collect_evidence(vulnerability_data)
            
            # Prepare template data
            template_data = await self._prepare_template_data(vulnerability_data, evidence_files)
            
            # Generate report content
            report_content = template_manager.render_template(template_name, template_data)
            
            # Create report object
            report = GeneratedReport(
                vulnerability_id=vulnerability_id,
                platform=platform,
                title=self._generate_report_title(vulnerability_data),
                content=report_content,
                evidence_files=evidence_files,
                metadata={
                    'template_used': template_name,
                    'generation_timestamp': datetime.now(timezone.utc).isoformat(),
                    'evidence_count': len(evidence_files),
                    'total_file_size': sum(f.size_bytes for f in evidence_files)
                }
            )
            
            # Save report to disk
            await self._save_report(report)
            
            # Update database
            await self._create_report_record(report, vulnerability_data)
            
            logger.info(f"Generated report for vulnerability {vulnerability_id}")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report for vulnerability {vulnerability_id}: {e}")
            raise
    
    async def generate_batch_reports(self, vulnerability_ids: List[int], platform: str) -> List[GeneratedReport]:
        """Generate reports for multiple vulnerabilities."""
        reports = []
        
        for vuln_id in vulnerability_ids:
            try:
                report = await self.generate_report(vuln_id, platform)
                reports.append(report)
            except Exception as e:
                logger.error(f"Failed to generate report for vulnerability {vuln_id}: {e}")
        
        return reports
    
    async def preview_report(self, vulnerability_id: int, platform: str, 
                           template_name: Optional[str] = None) -> Dict[str, Any]:
        """Generate a preview of the report without saving."""
        try:
            vulnerability_data = await self._get_vulnerability_data(vulnerability_id)
            if not vulnerability_data:
                raise ValueError(f"Vulnerability {vulnerability_id} not found")
            
            if not template_name:
                template_name = self._determine_template(platform, vulnerability_data['vulnerability_type'])
            
            # Prepare template data (without evidence collection for preview)
            template_data = await self._prepare_template_data(vulnerability_data, [])
            
            # Validate template data
            validation = template_manager.validate_template_data(template_name, template_data)
            
            preview_content = ""
            if validation['valid']:
                preview_content = template_manager.render_template(template_name, template_data)
            
            return {
                'template_name': template_name,
                'validation': validation,
                'preview_content': preview_content,
                'title': self._generate_report_title(vulnerability_data),
                'estimated_evidence_files': await self._estimate_evidence_files(vulnerability_data)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate report preview: {e}")
            raise
    
    async def _get_vulnerability_data(self, vulnerability_id: int) -> Optional[Dict[str, Any]]:
        """Get vulnerability data from database."""
        try:
            async with get_async_db() as db:
                vulnerability = await db.get(Vulnerability, vulnerability_id)
                if not vulnerability:
                    return None
                
                # Get related scan and program data
                scan = await db.get('Scan', vulnerability.scan_id)
                program = await db.get(Program, scan.program_id) if scan else None
                
                return {
                    'id': vulnerability.id,
                    'title': vulnerability.title,
                    'description': vulnerability.description,
                    'vulnerability_type': vulnerability.vulnerability_type,
                    'severity': vulnerability.severity,
                    'url': vulnerability.url,
                    'parameter': vulnerability.parameter,
                    'payload': vulnerability.payload,
                    'cvss_score': vulnerability.cvss_score,
                    'confidence': vulnerability.confidence,
                    'proof_of_concept': vulnerability.proof_of_concept,
                    'screenshot_path': vulnerability.screenshot_path,
                    'video_path': vulnerability.video_path,
                    'discovered_at': vulnerability.discovered_at,
                    'scan_data': {
                        'target': scan.target if scan else '',
                        'scan_type': scan.scan_type if scan else '',
                        'parameters': scan.parameters if scan else {}
                    },
                    'program_data': {
                        'name': program.name if program else '',
                        'platform': program.platform if program else '',
                        'url': program.url if program else ''
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to get vulnerability data: {e}")
            return None
    
    def _determine_template(self, platform: str, vulnerability_type: str) -> str:
        """Determine the best template for the vulnerability."""
        template = template_manager.get_template(platform, vulnerability_type)
        if template:
            return template.name
        else:
            return 'generic'
    
    async def _collect_evidence(self, vulnerability_data: Dict[str, Any]) -> List[EvidenceFile]:
        """Collect evidence files for the vulnerability."""
        evidence_files = []
        
        try:
            # Create evidence directory
            evidence_dir = self.output_dir / f"evidence_{vulnerability_data['id']}"
            evidence_dir.mkdir(exist_ok=True)
            
            # Collect existing evidence files
            if vulnerability_data.get('screenshot_path'):
                screenshot_file = await self._copy_evidence_file(
                    vulnerability_data['screenshot_path'],
                    evidence_dir,
                    'screenshot',
                    'Vulnerability screenshot'
                )
                if screenshot_file:
                    evidence_files.append(screenshot_file)
            
            if vulnerability_data.get('video_path'):
                video_file = await self._copy_evidence_file(
                    vulnerability_data['video_path'],
                    evidence_dir,
                    'video', 
                    'Proof of concept video'
                )
                if video_file:
                    evidence_files.append(video_file)
            
            # Generate new evidence if needed
            if self.screenshot_enabled and not vulnerability_data.get('screenshot_path'):
                screenshot_file = await self._generate_screenshot(vulnerability_data, evidence_dir)
                if screenshot_file:
                    evidence_files.append(screenshot_file)
            
            # Generate HTTP request/response files
            request_file = await self._generate_request_file(vulnerability_data, evidence_dir)
            if request_file:
                evidence_files.append(request_file)
            
            # Generate payload file for reference
            payload_file = await self._generate_payload_file(vulnerability_data, evidence_dir)
            if payload_file:
                evidence_files.append(payload_file)
            
        except Exception as e:
            logger.error(f"Failed to collect evidence: {e}")
        
        return evidence_files
    
    async def _copy_evidence_file(self, source_path: str, evidence_dir: Path, 
                                file_type: str, description: str) -> Optional[EvidenceFile]:
        """Copy existing evidence file to report directory."""
        try:
            if not os.path.exists(source_path):
                return None
            
            source = Path(source_path)
            destination = evidence_dir / source.name
            
            # Copy file
            import shutil
            shutil.copy2(source, destination)
            
            return EvidenceFile(
                filename=destination.name,
                filepath=str(destination),
                file_type=file_type,
                description=description,
                size_bytes=destination.stat().st_size
            )
            
        except Exception as e:
            logger.error(f"Failed to copy evidence file {source_path}: {e}")
            return None
    
    async def _generate_screenshot(self, vulnerability_data: Dict[str, Any], 
                                 evidence_dir: Path) -> Optional[EvidenceFile]:
        """Generate screenshot of the vulnerability."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            # Setup headless browser
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            
            driver = webdriver.Chrome(options=options)
            
            try:
                # Navigate to vulnerable URL
                url = vulnerability_data.get('url', '')
                if not url:
                    return None
                
                # Add payload if present
                payload = vulnerability_data.get('payload', '')
                if payload and '?' in url:
                    url += f"&{vulnerability_data.get('parameter', 'test')}={payload}"
                elif payload:
                    url += f"?{vulnerability_data.get('parameter', 'test')}={payload}"
                
                driver.get(url)
                await asyncio.sleep(2)  # Wait for page load
                
                # Take screenshot
                screenshot_path = evidence_dir / f"screenshot_{vulnerability_data['id']}.png"
                driver.save_screenshot(str(screenshot_path))
                
                return EvidenceFile(
                    filename=screenshot_path.name,
                    filepath=str(screenshot_path),
                    file_type='screenshot',
                    description='Automated screenshot of vulnerability',
                    size_bytes=screenshot_path.stat().st_size
                )
                
            finally:
                driver.quit()
                
        except Exception as e:
            logger.error(f"Failed to generate screenshot: {e}")
            return None
    
    async def _generate_request_file(self, vulnerability_data: Dict[str, Any], 
                                   evidence_dir: Path) -> Optional[EvidenceFile]:
        """Generate HTTP request file."""
        try:
            url = vulnerability_data.get('url', '')
            parameter = vulnerability_data.get('parameter', '')
            payload = vulnerability_data.get('payload', '')
            
            if not url:
                return None
            
            # Generate HTTP request
            parsed_url = urlparse(url)
            
            request_content = f"""GET {parsed_url.path}"""
            if parsed_url.query:
                request_content += f"?{parsed_url.query}"
            if parameter and payload:
                separator = '&' if parsed_url.query else '?'
                request_content += f"{separator}{parameter}={payload}"
            
            request_content += f""" HTTP/1.1
Host: {parsed_url.netloc}
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1

"""
            
            request_file = evidence_dir / f"request_{vulnerability_data['id']}.txt"
            request_file.write_text(request_content)
            
            return EvidenceFile(
                filename=request_file.name,
                filepath=str(request_file),
                file_type='request',
                description='HTTP request demonstrating vulnerability',
                size_bytes=request_file.stat().st_size
            )
            
        except Exception as e:
            logger.error(f"Failed to generate request file: {e}")
            return None
    
    async def _generate_payload_file(self, vulnerability_data: Dict[str, Any], 
                                   evidence_dir: Path) -> Optional[EvidenceFile]:
        """Generate payload reference file."""
        try:
            payload = vulnerability_data.get('payload', '')
            if not payload:
                return None
            
            payload_content = f"""Vulnerability: {vulnerability_data.get('title', 'Unknown')}
Type: {vulnerability_data.get('vulnerability_type', 'Unknown')}
Parameter: {vulnerability_data.get('parameter', 'Unknown')}
URL: {vulnerability_data.get('url', 'Unknown')}

Payload:
{payload}

CVSS Score: {vulnerability_data.get('cvss_score', 'N/A')}
Severity: {vulnerability_data.get('severity', 'Unknown')}
Confidence: {vulnerability_data.get('confidence', 'N/A')}

Discovery Date: {vulnerability_data.get('discovered_at', 'Unknown')}
"""
            
            payload_file = evidence_dir / f"payload_{vulnerability_data['id']}.txt"
            payload_file.write_text(payload_content)
            
            return EvidenceFile(
                filename=payload_file.name,
                filepath=str(payload_file),
                file_type='payload',
                description='Vulnerability payload and details',
                size_bytes=payload_file.stat().st_size
            )
            
        except Exception as e:
            logger.error(f"Failed to generate payload file: {e}")
            return None
    
    async def _prepare_template_data(self, vulnerability_data: Dict[str, Any], 
                                   evidence_files: List[EvidenceFile]) -> Dict[str, Any]:
        """Prepare data for template rendering."""
        # Basic vulnerability data
        template_data = {
            'vulnerability_type': vulnerability_data.get('vulnerability_type', 'Unknown'),
            'severity': vulnerability_data.get('severity', 'medium'),
            'title': vulnerability_data.get('title', 'Vulnerability'),
            'description': vulnerability_data.get('description', ''),
            'url': vulnerability_data.get('url', ''),
            'parameter': vulnerability_data.get('parameter', ''),
            'payload': vulnerability_data.get('payload', ''),
            'target': vulnerability_data.get('url', ''),
            'discovery_date': vulnerability_data.get('discovered_at', datetime.now()).strftime('%Y-%m-%d'),
            'cvss_score': vulnerability_data.get('cvss_score', 0.0),
            'confidence': vulnerability_data.get('confidence', 0.0)
        }
        
        # Generate proof of concept URL
        if template_data['url'] and template_data['parameter'] and template_data['payload']:
            parsed_url = urlparse(template_data['url'])
            separator = '&' if parsed_url.query else '?'
            template_data['poc_url'] = f"{template_data['url']}{separator}{template_data['parameter']}={template_data['payload']}"
        else:
            template_data['poc_url'] = template_data['url']
        
        # Add evidence files
        template_data['screenshots'] = [
            {'filename': f.filename, 'description': f.description, 'url': f.filepath}
            for f in evidence_files if f.file_type == 'screenshot'
        ]
        
        # Generate reproduction steps
        template_data['reproduction_steps'] = self._generate_reproduction_steps(vulnerability_data)
        
        # Add technical details based on vulnerability type
        template_data.update(self._generate_technical_details(vulnerability_data))
        
        # Add impact assessment
        template_data['impact'] = self._generate_impact_assessment(vulnerability_data)
        
        # Add remediation suggestions
        template_data['remediation'] = self._generate_remediation(vulnerability_data)
        
        return template_data
    
    def _generate_reproduction_steps(self, vulnerability_data: Dict[str, Any]) -> List[str]:
        """Generate reproduction steps for the vulnerability."""
        steps = []
        
        vuln_type = vulnerability_data.get('vulnerability_type', '').lower()
        url = vulnerability_data.get('url', '')
        parameter = vulnerability_data.get('parameter', '')
        payload = vulnerability_data.get('payload', '')
        
        if vuln_type == 'xss':
            steps = [
                f"Navigate to {url}",
                f"Identify the vulnerable parameter: {parameter}",
                f"Insert the XSS payload: {payload}",
                "Submit the form or trigger the request",
                "Observe that the payload executes in the browser"
            ]
        elif vuln_type == 'sqli':
            steps = [
                f"Navigate to {url}",
                f"Identify the vulnerable parameter: {parameter}",
                f"Insert the SQL injection payload: {payload}",
                "Submit the request",
                "Observe the SQL error or unexpected behavior"
            ]
        elif vuln_type == 'lfi':
            steps = [
                f"Navigate to {url}",
                f"Identify the file inclusion parameter: {parameter}",
                f"Insert the path traversal payload: {payload}",
                "Submit the request",
                "Observe that system files are exposed"
            ]
        else:
            steps = [
                f"Navigate to {url}",
                f"Identify the vulnerable parameter: {parameter}",
                f"Insert the payload: {payload}",
                "Submit the request",
                "Observe the vulnerability behavior"
            ]
        
        return steps
    
    def _generate_technical_details(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical details based on vulnerability type."""
        details = {}
        vuln_type = vulnerability_data.get('vulnerability_type', '').lower()
        
        if vuln_type == 'xss':
            details.update({
                'method': 'GET',
                'reflection_context': 'HTML content',
                'encoding_bypasses': 'None required',
                'browser_tested': 'Chrome 120.0'
            })
        elif vuln_type == 'sqli':
            details.update({
                'method': 'GET',
                'database_type': 'Unknown',
                'injection_point': vulnerability_data.get('parameter', 'Unknown'),
                'query_context': 'WHERE clause',
                'error_based': True,
                'time_based': False,
                'union_based': False
            })
        
        return details
    
    def _generate_impact_assessment(self, vulnerability_data: Dict[str, Any]) -> str:
        """Generate impact assessment for the vulnerability."""
        vuln_type = vulnerability_data.get('vulnerability_type', '').lower()
        severity = vulnerability_data.get('severity', 'medium').lower()
        
        impact_templates = {
            'xss': {
                'critical': 'Critical impact: Full account takeover possible through session hijacking, potential for widespread user compromise.',
                'high': 'High impact: Session hijacking, unauthorized actions, and potential data theft.',
                'medium': 'Medium impact: Limited cross-site scripting attacks, potential for user session compromise.',
                'low': 'Low impact: Limited XSS with minimal user interaction required.'
            },
            'sqli': {
                'critical': 'Critical impact: Complete database compromise, potential for data extraction, modification, and system access.',
                'high': 'High impact: Significant database access, potential for sensitive data extraction.',
                'medium': 'Medium impact: Limited database access, possible information disclosure.',
                'low': 'Low impact: Minor database information disclosure.'
            },
            'lfi': {
                'critical': 'Critical impact: Full system file access, potential for remote code execution.',
                'high': 'High impact: Sensitive file access, potential for configuration exposure.',
                'medium': 'Medium impact: Limited file access, information disclosure.',
                'low': 'Low impact: Minor file disclosure with limited sensitive content.'
            }
        }
        
        return impact_templates.get(vuln_type, {}).get(severity, 
            'Impact varies based on implementation and exploitability.')
    
    def _generate_remediation(self, vulnerability_data: Dict[str, Any]) -> str:
        """Generate remediation suggestions."""
        vuln_type = vulnerability_data.get('vulnerability_type', '').lower()
        
        remediation_templates = {
            'xss': '''1. Implement proper output encoding for all user-controlled data
2. Use Content Security Policy (CSP) headers to prevent XSS attacks
3. Validate and sanitize all input parameters
4. Use context-aware encoding (HTML, JavaScript, CSS, URL)
5. Consider using security-focused templating engines''',
            
            'sqli': '''1. Use parameterized queries (prepared statements) for all database interactions
2. Implement proper input validation and sanitization
3. Apply the principle of least privilege for database accounts
4. Use stored procedures where appropriate
5. Enable database query logging and monitoring''',
            
            'lfi': '''1. Implement proper input validation and sanitization
2. Use whitelist-based file access controls
3. Avoid dynamic file inclusion based on user input
4. Use absolute paths and validate file extensions
5. Implement proper access controls and chroot environments'''
        }
        
        return remediation_templates.get(vuln_type, 
            'Implement proper input validation, output encoding, and security controls.')
    
    def _generate_report_title(self, vulnerability_data: Dict[str, Any]) -> str:
        """Generate a concise report title."""
        vuln_type = vulnerability_data.get('vulnerability_type', 'Vulnerability').title()
        severity = vulnerability_data.get('severity', 'Medium').title()
        url = vulnerability_data.get('url', '')
        
        if url:
            domain = urlparse(url).netloc
            return f"{severity} {vuln_type} in {domain}"
        else:
            return f"{severity} {vuln_type} Vulnerability"
    
    async def _estimate_evidence_files(self, vulnerability_data: Dict[str, Any]) -> List[str]:
        """Estimate what evidence files would be generated."""
        estimated_files = ['HTTP Request Example', 'Payload Details']
        
        if self.screenshot_enabled:
            estimated_files.append('Automated Screenshot')
        
        if vulnerability_data.get('screenshot_path'):
            estimated_files.append('Existing Screenshot')
        
        if vulnerability_data.get('video_path'):
            estimated_files.append('Existing Video')
        
        return estimated_files
    
    async def _save_report(self, report: GeneratedReport):
        """Save generated report to disk."""
        try:
            # Create report directory
            report_dir = self.output_dir / f"report_{report.vulnerability_id}"
            report_dir.mkdir(exist_ok=True)
            
            # Save main report content
            report_file = report_dir / f"report_{report.vulnerability_id}.md"
            report_file.write_text(report.content, encoding='utf-8')
            
            # Save metadata
            metadata_file = report_dir / f"metadata_{report.vulnerability_id}.json"
            metadata_file.write_text(json.dumps(report.metadata, indent=2, default=str))
            
            logger.info(f"Report saved to {report_dir}")
            
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            raise
    
    async def _create_report_record(self, report: GeneratedReport, vulnerability_data: Dict[str, Any]):
        """Create report record in database."""
        try:
            async with get_async_db() as db:
                report_record = Report(
                    program_id=vulnerability_data['scan_data'].get('program_id'),
                    vulnerability_id=report.vulnerability_id,
                    title=report.title,
                    description=vulnerability_data.get('description', ''),
                    platform_report_id=None,  # Will be set when submitted
                    status='draft',
                    attachments=[f.filepath for f in report.evidence_files],
                    created_at=report.generated_at
                )
                
                db.add(report_record)
                await db.commit()
                
        except Exception as e:
            logger.error(f"Failed to create report record: {e}")

# Global report generator
report_generator = ReportGenerator()