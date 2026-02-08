#!/usr/bin/env python3
"""
API Data Validator - Prevents fake data injection
Validates all data before database insertion

Author: Data Integrity Team
Date: August 17, 2025
"""

import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

# Patterns that indicate fake/synthetic data
FAKE_PATTERNS = [
    r'microblog',
    r'Microblog',
    r'Latest updates',
    r'December 2024',
    r'January 2025',
    r'February 2025',
    r'March 2025',
    r'April 2025',
    r'May 2025',
    r'June 2025',
    r'July 2025',
    r'September 2025',  # Future months
    r'October 2025',
    r'November 2025',
    r'December 2025',
    r'2026',  # Any future year
    r'2027',
    r'we will keep you updated',
    r'In this microblog',
    r'•\t\*\*\d+\w+ of \w+ 202\d\*\*',  # Bullet point dates
]

# Maximum reasonable sizes based on real API data
MAX_POLICY_SIZE = 40000  # Largest legitimate policy seen
MIN_POLICY_SIZE = 10  # Minimum viable policy
TYPICAL_POLICY_SIZE = 2558  # Most common size

class APIDataValidator:
    """Validates API data before database insertion"""
    
    def __init__(self):
        self.violations = []
        self.warnings = []
        
    def validate_policy(self, policy: str, program_handle: str) -> Tuple[bool, str, List[str]]:
        """
        Validate policy content for fake data patterns
        
        Returns:
            (is_valid, cleaned_policy, issues)
        """
        if not policy:
            return True, policy, []
        
        issues = []
        
        # Check size
        policy_len = len(policy)
        if policy_len > MAX_POLICY_SIZE:
            issues.append(f"Policy too large: {policy_len} chars (max: {MAX_POLICY_SIZE})")
            return False, policy, issues
        
        if policy_len < MIN_POLICY_SIZE:
            issues.append(f"Policy too small: {policy_len} chars (min: {MIN_POLICY_SIZE})")
            
        # Check for fake patterns
        for pattern in FAKE_PATTERNS:
            if re.search(pattern, policy, re.IGNORECASE):
                issues.append(f"Fake pattern detected: '{pattern}'")
                return False, policy, issues
        
        # Check for future dates
        if self._contains_future_dates(policy):
            issues.append("Contains future dates")
            return False, policy, issues
        
        # Check for suspicious content structure
        if self._is_suspicious_structure(policy):
            issues.append("Suspicious content structure")
            self.warnings.append(f"{program_handle}: Suspicious structure detected")
        
        return len(issues) == 0, policy, issues
    
    def _contains_future_dates(self, text: str) -> bool:
        """Check if text contains dates in the future"""
        current_date = datetime.now()
        future_threshold = current_date + timedelta(days=30)  # Allow 30 days future
        
        # Common date patterns
        date_patterns = [
            r'\b(\d{1,2})\w*\s+of\s+(\w+)\s+(\d{4})\b',  # "12th of December 2024"
            r'\b(\w+)\s+(\d{1,2}),?\s+(\d{4})\b',  # "December 12, 2024"
            r'\b(\d{4})-(\d{2})-(\d{2})\b',  # "2024-12-12"
        ]
        
        for pattern in date_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                try:
                    # Parse and check if date is in future
                    if self._is_future_date(match, future_threshold):
                        return True
                except:
                    continue
        
        return False
    
    def _is_future_date(self, date_parts: tuple, threshold: datetime) -> bool:
        """Check if parsed date is in the future"""
        months = {
            'january': 1, 'february': 2, 'march': 3, 'april': 4,
            'may': 5, 'june': 6, 'july': 7, 'august': 8,
            'september': 9, 'october': 10, 'november': 11, 'december': 12
        }
        
        try:
            if len(date_parts) == 3:
                # Try different formats
                if date_parts[0].isdigit() and not date_parts[1].isdigit():
                    # "12th of December 2024"
                    day = int(date_parts[0])
                    month = months.get(date_parts[1].lower(), 0)
                    year = int(date_parts[2])
                elif not date_parts[0].isdigit() and date_parts[1].isdigit():
                    # "December 12, 2024"
                    month = months.get(date_parts[0].lower(), 0)
                    day = int(date_parts[1])
                    year = int(date_parts[2])
                else:
                    # "2024-12-12"
                    year = int(date_parts[0])
                    month = int(date_parts[1])
                    day = int(date_parts[2])
                
                if month > 0:
                    date_obj = datetime(year, month, day)
                    return date_obj > threshold
        except:
            pass
        
        return False
    
    def _is_suspicious_structure(self, policy: str) -> bool:
        """Check for suspicious content structure"""
        
        # Check for excessive bullet points (sign of fake timeline)
        bullet_count = policy.count('•')
        if bullet_count > 20:
            return True
        
        # Check for repeated patterns
        if policy.count('has been added to') > 5:
            return True
        
        if policy.count('moved from Tier') > 5:
            return True
        
        return False
    
    def validate_program_data(self, program_data: Dict) -> Tuple[bool, Dict, List[str]]:
        """
        Validate complete program data before insertion
        
        Returns:
            (is_valid, cleaned_data, issues)
        """
        issues = []
        cleaned_data = program_data.copy()
        
        # Validate policy if present
        if 'policy' in program_data:
            is_valid, cleaned_policy, policy_issues = self.validate_policy(
                program_data['policy'],
                program_data.get('handle', 'unknown')
            )
            
            if not is_valid:
                issues.extend(policy_issues)
                # Don't insert fake data - set to None or empty
                cleaned_data['policy'] = ''
            else:
                cleaned_data['policy'] = cleaned_policy
        
        # Validate other fields
        if 'name' in program_data:
            if len(program_data['name']) > 200:
                issues.append(f"Program name too long: {len(program_data['name'])} chars")
        
        # Ensure required fields
        required_fields = ['program_id', 'handle']
        for field in required_fields:
            if field not in program_data or not program_data[field]:
                issues.append(f"Missing required field: {field}")
        
        return len(issues) == 0, cleaned_data, issues
    
    def generate_validation_report(self) -> Dict:
        """Generate validation report"""
        return {
            'timestamp': datetime.now().isoformat(),
            'violations': self.violations,
            'warnings': self.warnings,
            'total_violations': len(self.violations),
            'total_warnings': len(self.warnings),
            'status': 'clean' if len(self.violations) == 0 else 'violations_found'
        }


def validate_before_insert(program_data: Dict) -> Tuple[bool, Dict]:
    """
    Main validation function to call before ANY database insertion
    
    Usage:
        is_valid, cleaned_data = validate_before_insert(api_data)
        if is_valid:
            # Insert cleaned_data into database
        else:
            # Log rejection and skip
    """
    validator = APIDataValidator()
    is_valid, cleaned_data, issues = validator.validate_program_data(program_data)
    
    if not is_valid:
        print(f"❌ VALIDATION FAILED for {program_data.get('handle', 'unknown')}")
        for issue in issues:
            print(f"   - {issue}")
        return False, None
    
    return True, cleaned_data


# Validation rules for different data types
VALIDATION_RULES = {
    'policy': {
        'max_size': 40000,
        'min_size': 10,
        'forbidden_patterns': FAKE_PATTERNS,
        'check_future_dates': True
    },
    'scope': {
        'max_identifier_length': 500,
        'valid_asset_types': ['URL', 'WILDCARD', 'IP_ADDRESS', 'APPLE_STORE_APP_ID', 
                              'GOOGLE_PLAY_APP_ID', 'OTHER_APK', 'OTHER_IPA', 'SOURCE_CODE']
    },
    'program': {
        'max_name_length': 200,
        'max_handle_length': 100,
        'required_fields': ['program_id', 'handle']
    }
}


if __name__ == "__main__":
    # Test validation
    test_cases = [
        {
            'program_id': '123',
            'handle': 'test_program',
            'policy': 'This is a legitimate policy with no fake content.'
        },
        {
            'program_id': '456',
            'handle': 'fake_program',
            'policy': '# Latest updates – Microblog 2024\n12th of December 2024 - Added fake content'
        }
    ]
    
    for test in test_cases:
        is_valid, cleaned = validate_before_insert(test)
        if is_valid:
            print(f"✅ {test['handle']}: Valid")
        else:
            print(f"❌ {test['handle']}: Invalid (rejected)")