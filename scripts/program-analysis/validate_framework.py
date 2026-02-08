#!/usr/bin/env python3
"""
Framework Validation Script
Tests the automated program analysis framework with multiple programs

Author: BBHK Team + Claude-Flow Hive Mind
Date: August 17, 2025
"""

import subprocess
import sys
import os
from datetime import datetime

class FrameworkValidator:
    def __init__(self):
        self.test_programs = [
            'watson_group',  # Top ROI program
            '8x8-bounty',    # Second ROI program  
            'nordsecurity',  # Third ROI program
            'metamask',      # Popular crypto program
            'grammarly'      # Well-known brand
        ]
        self.results = {}
        
    def validate_program(self, program_handle):
        """Validate framework with a specific program"""
        print(f"\n🧪 Testing: {program_handle}")
        print("-" * 40)
        
        try:
            # Run the framework
            result = subprocess.run([
                'python3', 
                '/home/kali/bbhk/scripts/program-analysis/generate_program_analysis.py',
                program_handle
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Check if files were created
                program_dir = f"/home/kali/bbhk/docs/bb-sites/hackerone/programs/{program_handle}"
                
                files_created = []
                if os.path.exists(program_dir):
                    files_created = os.listdir(program_dir)
                
                expected_files = [
                    f'COMPLETE-',  # Should have complete data file
                    f'{program_handle}_program_',  # Program JSON
                    f'{program_handle}_structured_scopes_',  # Scopes JSON
                    f'{program_handle}_deep_dive_'  # Analysis JSON
                ]
                
                files_found = 0
                for expected in expected_files:
                    for created in files_created:
                        if expected in created:
                            files_found += 1
                            break
                
                success = files_found >= 3  # At least 3 of 4 expected files
                
                self.results[program_handle] = {
                    'status': 'SUCCESS' if success else 'PARTIAL',
                    'files_created': len(files_created),
                    'expected_files_found': files_found,
                    'directory': program_dir,
                    'output': result.stdout,
                    'error': result.stderr
                }
                
                print(f"✅ Status: {'SUCCESS' if success else 'PARTIAL'}")
                print(f"📁 Files created: {len(files_created)}")
                print(f"📋 Expected files found: {files_found}/4")
                
            else:
                self.results[program_handle] = {
                    'status': 'FAILED',
                    'error': result.stderr,
                    'output': result.stdout,
                    'return_code': result.returncode
                }
                print(f"❌ Status: FAILED")
                print(f"Error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.results[program_handle] = {
                'status': 'TIMEOUT',
                'error': 'Process timed out after 60 seconds'
            }
            print(f"⏰ Status: TIMEOUT")
            
        except Exception as e:
            self.results[program_handle] = {
                'status': 'ERROR',
                'error': str(e)
            }
            print(f"🔥 Status: ERROR - {e}")
    
    def run_validation(self):
        """Run validation on all test programs"""
        print("🚀 Starting Framework Validation")
        print("=" * 60)
        print(f"Testing {len(self.test_programs)} programs...")
        
        for program in self.test_programs:
            self.validate_program(program)
        
        self.print_summary()
        
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("📊 VALIDATION SUMMARY")
        print("=" * 60)
        
        total = len(self.test_programs)
        successful = len([r for r in self.results.values() if r['status'] == 'SUCCESS'])
        partial = len([r for r in self.results.values() if r['status'] == 'PARTIAL'])
        failed = len([r for r in self.results.values() if r['status'] in ['FAILED', 'TIMEOUT', 'ERROR']])
        
        print(f"🎯 Total Programs Tested: {total}")
        print(f"✅ Successful: {successful}")
        print(f"🟡 Partial: {partial}")
        print(f"❌ Failed: {failed}")
        print(f"📈 Success Rate: {(successful/total)*100:.1f}%")
        
        print(f"\n📋 Detailed Results:")
        for program, result in self.results.items():
            status_emoji = {
                'SUCCESS': '✅',
                'PARTIAL': '🟡', 
                'FAILED': '❌',
                'TIMEOUT': '⏰',
                'ERROR': '🔥'
            }.get(result['status'], '❓')
            
            files_info = f"({result.get('files_created', 0)} files)" if 'files_created' in result else ""
            print(f"  {status_emoji} {program:15} | {result['status']:8} {files_info}")
        
        if successful >= total * 0.8:  # 80% success rate
            print(f"\n🎉 FRAMEWORK VALIDATION: PASSED")
            print(f"Framework is ready for production use!")
        else:
            print(f"\n⚠️  FRAMEWORK VALIDATION: NEEDS ATTENTION")
            print(f"Some programs failed validation - review errors above")
        
        print(f"\n🗂️  Generated Analysis Directories:")
        for program, result in self.results.items():
            if result['status'] in ['SUCCESS', 'PARTIAL']:
                directory = result.get('directory', f'Unknown')
                print(f"  📁 {program}: {directory}")

if __name__ == "__main__":
    validator = FrameworkValidator()
    validator.run_validation()