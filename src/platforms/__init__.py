"""
BBHK Platform Integrations
Authentication tested and validated on 2025-08-16
"""

from .hackerone_client import HackerOneClient, HACKERONE_CREDENTIALS

__all__ = ['HackerOneClient', 'HACKERONE_CREDENTIALS']

# Integration status
PLATFORM_STATUS = {
    'hackerone': {
        'status': 'OPERATIONAL',
        'tested': '2025-08-16',
        'endpoints_working': ['/hackers/me/reports', '/hackers/payments/earnings'],
        'authentication': 'HTTP Basic Auth - Validated',
        'rate_limits': {
            'read': '600 requests/minute',
            'write': '25 requests/20 seconds'
        }
    },
    'bugcrowd': {
        'status': 'PENDING',
        'integration': 'MCP server available'
    },
    'intigriti': {
        'status': 'PLANNED',
        'priority': 'Phase 2'
    }
}