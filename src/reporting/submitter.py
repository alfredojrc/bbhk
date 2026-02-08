"""Automated report submission to bug bounty platforms."""

import asyncio
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from loguru import logger

from .generator import GeneratedReport
from ..core.database import Report, get_async_db
from ..core.config import config

@dataclass
class SubmissionResult:
    """Result of report submission."""
    success: bool
    platform_id: Optional[str] = None
    submission_url: Optional[str] = None
    error_message: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None

class ReportSubmitter:
    """Handles automated report submission to various platforms."""
    
    def __init__(self):
        """Initialize report submitter."""
        self.platforms = {
            'hackerone': HackerOneSubmitter(),
            'bugcrowd': BugcrowdSubmitter(),
            'intigriti': IntigritiSubmitter()
        }
    
    async def submit_report(self, report_id: int, platform: str, 
                          credentials: Dict[str, str]) -> SubmissionResult:
        """Submit a report to the specified platform."""
        try:
            # Get report from database
            async with get_async_db() as db:
                report = await db.get(Report, report_id)
                if not report:
                    return SubmissionResult(
                        success=False,
                        error_message=f"Report {report_id} not found"
                    )
            
            # Get platform submitter
            submitter = self.platforms.get(platform.lower())
            if not submitter:
                return SubmissionResult(
                    success=False,
                    error_message=f"Platform {platform} not supported"
                )
            
            # Submit report
            result = await submitter.submit(report, credentials)
            
            # Update database with submission result
            await self._update_report_status(report, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to submit report {report_id}: {e}")
            return SubmissionResult(
                success=False,
                error_message=str(e)
            )
    
    async def check_submission_status(self, report_id: int) -> Dict[str, Any]:
        """Check the status of a submitted report."""
        try:
            async with get_async_db() as db:
                report = await db.get(Report, report_id)
                if not report:
                    return {'error': 'Report not found'}
                
                if not report.platform_report_id:
                    return {
                        'status': 'not_submitted',
                        'message': 'Report has not been submitted yet'
                    }
                
                # Get program to determine platform
                program = await db.get('Program', report.program_id)
                if not program:
                    return {'error': 'Associated program not found'}
                
                submitter = self.platforms.get(program.platform.lower())
                if not submitter:
                    return {'error': f'Platform {program.platform} not supported'}
                
                # Check status on platform
                status_info = await submitter.check_status(report.platform_report_id)
                
                return {
                    'report_id': report_id,
                    'platform_id': report.platform_report_id,
                    'status': report.status,
                    'platform_status': status_info,
                    'submitted_at': report.submitted_at,
                    'last_updated': report.updated_at
                }
                
        except Exception as e:
            logger.error(f"Failed to check submission status for report {report_id}: {e}")
            return {'error': str(e)}
    
    async def _update_report_status(self, report: Report, result: SubmissionResult):
        """Update report status in database."""
        try:
            async with get_async_db() as db:
                if result.success:
                    report.platform_report_id = result.platform_id
                    report.status = 'submitted'
                    report.submitted_at = datetime.now(timezone.utc)
                else:
                    report.status = 'submission_failed'
                
                report.updated_at = datetime.now(timezone.utc)
                await db.commit()
                
        except Exception as e:
            logger.error(f"Failed to update report status: {e}")

class BasePlatformSubmitter:
    """Base class for platform-specific submitters."""
    
    def __init__(self, platform_name: str):
        """Initialize base submitter."""
        self.platform_name = platform_name
        self.session = None
    
    async def submit(self, report: Report, credentials: Dict[str, str]) -> SubmissionResult:
        """Submit report to platform - to be implemented by subclasses."""
        raise NotImplementedError
    
    async def check_status(self, platform_id: str) -> Dict[str, Any]:
        """Check report status on platform - to be implemented by subclasses."""
        raise NotImplementedError
    
    async def _make_authenticated_request(self, url: str, method: str = 'GET', 
                                        credentials: Dict[str, str] = None, **kwargs):
        """Make authenticated request to platform API."""
        import aiohttp
        
        if not self.session:
            self.session = aiohttp.ClientSession()
        
        # Add authentication headers based on platform
        headers = kwargs.get('headers', {})
        headers.update(self._get_auth_headers(credentials))
        kwargs['headers'] = headers
        
        async with self.session.request(method, url, **kwargs) as response:
            return {
                'status': response.status,
                'headers': dict(response.headers),
                'data': await response.json() if 'json' in response.headers.get('content-type', '') else await response.text()
            }
    
    def _get_auth_headers(self, credentials: Dict[str, str]) -> Dict[str, str]:
        """Get authentication headers - to be implemented by subclasses."""
        return {}
    
    async def cleanup(self):
        """Clean up session."""
        if self.session:
            await self.session.close()

class HackerOneSubmitter(BasePlatformSubmitter):
    """HackerOne report submitter."""
    
    def __init__(self):
        """Initialize HackerOne submitter."""
        super().__init__('hackerone')
        self.api_base = 'https://api.hackerone.com/v1'
    
    async def submit(self, report: Report, credentials: Dict[str, str]) -> SubmissionResult:
        """Submit report to HackerOne."""
        try:
            # Get vulnerability and program data
            async with get_async_db() as db:
                vulnerability = await db.get('Vulnerability', report.vulnerability_id)
                program = await db.get('Program', report.program_id)
                
                if not vulnerability or not program:
                    return SubmissionResult(
                        success=False,
                        error_message="Missing vulnerability or program data"
                    )
            
            # Extract program handle from URL
            program_handle = program.url.split('/')[-1]
            
            # Prepare submission data
            submission_data = {
                'data': {
                    'type': 'report',
                    'attributes': {
                        'title': report.title,
                        'vulnerability_information': report.description,
                        'impact': self._generate_impact_description(vulnerability),
                        'severity_rating': vulnerability.severity,
                        'weakness_id': self._map_weakness_id(vulnerability.vulnerability_type)
                    }
                }
            }
            
            # Submit report
            response = await self._make_authenticated_request(
                f'{self.api_base}/reports',
                method='POST',
                credentials=credentials,
                json=submission_data
            )
            
            if response['status'] == 201:
                report_data = response['data']['data']
                return SubmissionResult(
                    success=True,
                    platform_id=report_data['id'],
                    submission_url=f"https://hackerone.com/reports/{report_data['id']}",
                    response_data=response['data']
                )
            else:
                return SubmissionResult(
                    success=False,
                    error_message=f"API returned status {response['status']}",
                    response_data=response['data']
                )
                
        except Exception as e:
            logger.error(f"HackerOne submission failed: {e}")
            return SubmissionResult(
                success=False,
                error_message=str(e)
            )
    
    async def check_status(self, platform_id: str) -> Dict[str, Any]:
        """Check report status on HackerOne."""
        try:
            response = await self._make_authenticated_request(
                f'{self.api_base}/reports/{platform_id}'
            )
            
            if response['status'] == 200:
                report_data = response['data']['data']
                return {
                    'state': report_data['attributes']['state'],
                    'substate': report_data['attributes']['substate'],
                    'title': report_data['attributes']['title'],
                    'created_at': report_data['attributes']['created_at'],
                    'triaged_at': report_data['attributes']['triaged_at'],
                    'bounty_awarded_at': report_data['attributes']['bounty_awarded_at']
                }
            else:
                return {'error': f'API returned status {response["status"]}'}
                
        except Exception as e:
            logger.error(f"Failed to check HackerOne status: {e}")
            return {'error': str(e)}
    
    def _get_auth_headers(self, credentials: Dict[str, str]) -> Dict[str, str]:
        """Get HackerOne authentication headers."""
        import base64
        
        username = credentials.get('username', '')
        api_token = credentials.get('api_token', '')
        
        if username and api_token:
            credentials_str = f"{username}:{api_token}"
            encoded_credentials = base64.b64encode(credentials_str.encode()).decode()
            
            return {
                'Authorization': f'Basic {encoded_credentials}',
                'Content-Type': 'application/json'
            }
        
        return {}
    
    def _generate_impact_description(self, vulnerability) -> str:
        """Generate impact description for HackerOne."""
        vuln_type = vulnerability.vulnerability_type.lower()
        
        impact_templates = {
            'xss': 'This cross-site scripting vulnerability allows attackers to execute arbitrary JavaScript code in victim browsers, potentially leading to session hijacking, data theft, and unauthorized actions.',
            'sqli': 'This SQL injection vulnerability allows attackers to manipulate database queries, potentially leading to data extraction, modification, or deletion.',
            'lfi': 'This local file inclusion vulnerability allows attackers to access sensitive system files, potentially leading to information disclosure and system compromise.'
        }
        
        return impact_templates.get(vuln_type, 'This vulnerability poses security risks to the application and its users.')
    
    def _map_weakness_id(self, vulnerability_type: str) -> int:
        """Map vulnerability type to HackerOne weakness ID."""
        weakness_mapping = {
            'xss': 60,  # Cross-site Scripting (XSS) - Generic
            'sqli': 67,  # SQL Injection
            'lfi': 73,  # External Control of File Name or Path
            'csrf': 62,  # Cross-Site Request Forgery (CSRF)
            'ssrf': 68,  # Server-Side Request Forgery (SSRF)
            'rce': 58   # Remote Code Execution
        }
        
        return weakness_mapping.get(vulnerability_type.lower(), 58)  # Default to RCE

class BugcrowdSubmitter(BasePlatformSubmitter):
    """Bugcrowd report submitter (placeholder implementation)."""
    
    def __init__(self):
        """Initialize Bugcrowd submitter."""
        super().__init__('bugcrowd')
        self.api_base = 'https://api.bugcrowd.com'
    
    async def submit(self, report: Report, credentials: Dict[str, str]) -> SubmissionResult:
        """Submit report to Bugcrowd."""
        # Placeholder implementation
        logger.info("Bugcrowd submission not yet implemented")
        return SubmissionResult(
            success=False,
            error_message="Bugcrowd submission not yet implemented"
        )
    
    async def check_status(self, platform_id: str) -> Dict[str, Any]:
        """Check report status on Bugcrowd."""
        return {'error': 'Bugcrowd status checking not yet implemented'}

class IntigritiSubmitter(BasePlatformSubmitter):
    """Intigriti report submitter (placeholder implementation)."""
    
    def __init__(self):
        """Initialize Intigriti submitter."""
        super().__init__('intigriti')
        self.api_base = 'https://api.intigriti.com'
    
    async def submit(self, report: Report, credentials: Dict[str, str]) -> SubmissionResult:
        """Submit report to Intigriti."""
        # Placeholder implementation
        logger.info("Intigriti submission not yet implemented")
        return SubmissionResult(
            success=False,
            error_message="Intigriti submission not yet implemented"
        )
    
    async def check_status(self, platform_id: str) -> Dict[str, Any]:
        """Check report status on Intigriti."""
        return {'error': 'Intigriti status checking not yet implemented'}

# Global report submitter
report_submitter = ReportSubmitter()