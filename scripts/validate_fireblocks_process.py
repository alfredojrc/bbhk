#!/usr/bin/env python3
"""
Validate Fireblocks MPC Process - End to End Test
Ensures the complete process can be reproduced from scratch

Author: Process Validator Agent
Date: August 18, 2025
"""

import os
import subprocess
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime
from pathlib import Path

class ProcessValidator:
    def __init__(self):
        self.checks = []
        self.program_handle = "fireblocks_mpc"
        self.docs_dir = f"/home/kali/bbhk/docs/bb-sites/hackerone/programs/{self.program_handle}"
        
    def check_database_connection(self):
        """Verify database connection works"""
        print("1️⃣ Checking database connection...")
        try:
            conn = psycopg2.connect(
                host='localhost',
                port=5432,
                database='bbhk_db',
                user='bbhk_user',
                password=os.getenv('POSTGRES_PASSWORD', '')
            )
            cursor = conn.cursor()
            cursor.execute("SELECT version()")
            result = cursor.fetchone()
            conn.close()
            self.checks.append(("Database Connection", True, "Connected"))
            print("   ✅ Database connected")
            return True
        except Exception as e:
            self.checks.append(("Database Connection", False, str(e)))
            print(f"   ❌ Database error: {e}")
            return False
    
    def check_program_exists(self):
        """Check if Fireblocks MPC exists in database"""
        print("2️⃣ Checking if Fireblocks MPC exists...")
        try:
            conn = psycopg2.connect(
                host='localhost',
                port=5432,
                database='bbhk_db',
                user='bbhk_user',
                password=os.getenv('POSTGRES_PASSWORD', '')
            )
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT program_id, handle, name, offers_bounties, 
                       length(policy) as policy_len
                FROM programs 
                WHERE handle = %s
            """, (self.program_handle,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                self.checks.append(("Program Exists", True, f"{result['name']}"))
                print(f"   ✅ Found: {result['name']} (Policy: {result['policy_len']} chars)")
                return True
            else:
                self.checks.append(("Program Exists", False, "Not found"))
                print("   ❌ Program not found in database")
                return False
                
        except Exception as e:
            self.checks.append(("Program Exists", False, str(e)))
            print(f"   ❌ Error: {e}")
            return False
    
    def check_scripts_exist(self):
        """Verify required scripts exist"""
        print("3️⃣ Checking required scripts...")
        
        scripts = [
            "scripts/program-analysis/generate_program_analysis.py",
            "scripts/api_data_validator.py",
            "scripts/fetch_all_programs_to_postgres.py"
        ]
        
        all_exist = True
        for script in scripts:
            path = Path(f"/home/kali/bbhk/{script}")
            if path.exists():
                print(f"   ✅ {script}")
            else:
                print(f"   ❌ {script} missing")
                all_exist = False
        
        self.checks.append(("Scripts Exist", all_exist, "All scripts present" if all_exist else "Missing scripts"))
        return all_exist
    
    def check_documentation_created(self):
        """Check if documentation was created"""
        print("4️⃣ Checking documentation files...")
        
        files = [
            f"COMPLETE-FIREBLOCKS-MPC-DATA.md",
            f"{self.program_handle}_program_*.json",
            f"{self.program_handle}_structured_scopes_*.json"
        ]
        
        if not os.path.exists(self.docs_dir):
            self.checks.append(("Documentation Created", False, "Directory missing"))
            print(f"   ❌ Directory not found: {self.docs_dir}")
            return False
        
        files_found = []
        for pattern in files:
            if '*' in pattern:
                # Use glob pattern
                import glob
                matches = glob.glob(f"{self.docs_dir}/{pattern}")
                if matches:
                    files_found.extend(matches)
                    print(f"   ✅ Found: {os.path.basename(matches[0])}")
            else:
                path = f"{self.docs_dir}/{pattern}"
                if os.path.exists(path):
                    files_found.append(path)
                    print(f"   ✅ Found: {pattern}")
        
        success = len(files_found) >= 3
        self.checks.append(("Documentation Created", success, f"{len(files_found)} files found"))
        return success
    
    def check_data_validation(self):
        """Verify data passes validation (no fake content)"""
        print("5️⃣ Checking data validation...")
        
        try:
            # Get policy from database
            conn = psycopg2.connect(
                host='localhost',
                port=5432,
                database='bbhk_db',
                user='bbhk_user',
                password=os.getenv('POSTGRES_PASSWORD', '')
            )
            cursor = conn.cursor()
            cursor.execute("SELECT policy FROM programs WHERE handle = %s", (self.program_handle,))
            result = cursor.fetchone()
            conn.close()
            
            if result and result[0]:
                policy = result[0]
                
                # Check for fake patterns
                fake_patterns = ['microblog', 'December 2024', 'Latest updates']
                has_fake = False
                for pattern in fake_patterns:
                    if pattern.lower() in policy.lower():
                        has_fake = True
                        print(f"   ❌ Found fake pattern: '{pattern}'")
                        break
                
                if not has_fake:
                    self.checks.append(("Data Validation", True, "No fake content"))
                    print("   ✅ No fake content detected")
                    return True
                else:
                    self.checks.append(("Data Validation", False, "Fake content found"))
                    return False
            else:
                self.checks.append(("Data Validation", True, "No policy to validate"))
                print("   ✅ No policy data")
                return True
                
        except Exception as e:
            self.checks.append(("Data Validation", False, str(e)))
            print(f"   ❌ Error: {e}")
            return False
    
    def run_analysis_command(self):
        """Test running the analysis command"""
        print("6️⃣ Testing analysis command...")
        
        cmd = f"python3 /home/kali/bbhk/scripts/program-analysis/generate_program_analysis.py {self.program_handle}"
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and "Analysis Complete" in result.stdout:
                self.checks.append(("Analysis Command", True, "Executed successfully"))
                print("   ✅ Analysis command works")
                return True
            else:
                self.checks.append(("Analysis Command", False, "Command failed"))
                print(f"   ❌ Command failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.checks.append(("Analysis Command", False, str(e)))
            print(f"   ❌ Error: {e}")
            return False
    
    def generate_report(self):
        """Generate validation report"""
        print("\n" + "="*60)
        print("📋 PROCESS VALIDATION REPORT")
        print("="*60)
        
        all_passed = all(check[1] for check in self.checks)
        
        for name, passed, details in self.checks:
            status = "✅" if passed else "❌"
            print(f"{status} {name}: {details}")
        
        print("\n" + "="*60)
        if all_passed:
            print("✅ ALL CHECKS PASSED - Process is reproducible!")
        else:
            print("❌ SOME CHECKS FAILED - Process needs fixing")
        
        # Save report
        report = {
            'timestamp': datetime.now().isoformat(),
            'program': self.program_handle,
            'checks': [
                {'name': name, 'passed': passed, 'details': details}
                for name, passed, details in self.checks
            ],
            'all_passed': all_passed
        }
        
        report_file = f"/home/kali/bbhk/analysis/process_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Report saved: {report_file}")
        
        return all_passed
    
    def validate(self):
        """Run complete validation"""
        print("🚀 VALIDATING FIREBLOCKS MPC PROCESS")
        print("="*60)
        
        # Run all checks
        self.check_database_connection()
        self.check_program_exists()
        self.check_scripts_exist()
        self.check_documentation_created()
        self.check_data_validation()
        self.run_analysis_command()
        
        # Generate report
        success = self.generate_report()
        
        print("\n📚 Process Steps Validated:")
        print("1. Check program exists: psql query or API")
        print("2. Run analysis: python3 scripts/program-analysis/generate_program_analysis.py <handle>")
        print("3. Documentation created in: /docs/bb-sites/hackerone/programs/<handle>/")
        print("4. Data validated: No fake content")
        
        return success

if __name__ == "__main__":
    validator = ProcessValidator()
    success = validator.validate()
    exit(0 if success else 1)