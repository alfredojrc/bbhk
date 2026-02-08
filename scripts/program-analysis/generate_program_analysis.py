#!/usr/bin/env python3
"""
Automated HackerOne Program Analysis Generator
Creates comprehensive program analysis for any HackerOne program

Author: BBHK Team + Claude-Flow Hive Mind
Date: August 17, 2025
"""

import psycopg2
from psycopg2.extras import RealDictCursor
import json
import os
from datetime import datetime
import argparse
from pathlib import Path

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'bbhk_db',
    'user': 'bbhk_user',
    'password': os.getenv('POSTGRES_PASSWORD', '')
}

class ProgramAnalysisGenerator:
    def __init__(self, program_handle):
        self.program_handle = program_handle
        self.conn = None
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = "/home/kali/bbhk/docs/bb-sites/hackerone/programs"
        self.program_dir = f"{self.base_dir}/{program_handle}"
        self.templates_dir = "/home/kali/bbhk/scripts/program-analysis/templates"
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            return True
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def create_program_directory(self):
        """Create program directory structure"""
        os.makedirs(self.program_dir, exist_ok=True)
        print(f"✅ Created directory: {self.program_dir}")
    
    def extract_program_data(self):
        """Extract complete program data"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        # Get program basic data
        program_query = """
        SELECT * FROM programs WHERE handle = %s
        """
        cursor.execute(program_query, (self.program_handle,))
        program_data = cursor.fetchone()
        
        if not program_data:
            print(f"❌ Program '{self.program_handle}' not found!")
            return None
        
        # Convert to dict and add metadata
        program_dict = dict(program_data)
        program_dict['extraction_timestamp'] = datetime.now().isoformat()
        program_dict['data_source'] = 'PostgreSQL BBHK Database'
        
        print(f"✅ Extracted program data for: {program_dict['name']}")
        return program_dict
    
    def extract_structured_scopes(self):
        """Extract structured scopes for the program"""
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        scopes_query = """
        SELECT s.*, p.name as program_name, p.handle as program_handle
        FROM structured_scopes s
        JOIN programs p ON s.program_id = p.program_id
        WHERE p.handle = %s
        ORDER BY 
            CASE s.max_severity 
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            s.asset_type,
            s.asset_identifier
        """
        
        cursor.execute(scopes_query, (self.program_handle,))
        scopes_data = cursor.fetchall()
        
        scopes_list = [dict(scope) for scope in scopes_data]
        
        scopes_metadata = {
            'extraction_timestamp': datetime.now().isoformat(),
            'total_scopes': len(scopes_list),
            'data_source': 'PostgreSQL BBHK Database',
            'scopes': scopes_list
        }
        
        print(f"✅ Extracted {len(scopes_list)} structured scopes")
        return scopes_metadata
    
    def analyze_scopes(self, scopes_data, program_data):
        """Perform comprehensive scope analysis"""
        scopes = scopes_data['scopes']
        
        if not scopes:
            return {
                'extraction_timestamp': datetime.now().isoformat(),
                'program_handle': self.program_handle,
                'total_scopes': 0,
                'error': 'No scopes found for this program'
            }
        
        # Asset type distribution
        asset_types = {}
        for scope in scopes:
            asset_type = scope['asset_type'] or 'UNKNOWN'
            asset_types[asset_type] = asset_types.get(asset_type, 0) + 1
        
        # Severity distribution
        severities = {}
        for scope in scopes:
            severity = scope['max_severity'] or 'none'
            severities[severity] = severities.get(severity, 0) + 1
        
        # Bounty eligible count
        bounty_eligible = len([s for s in scopes if s['eligible_for_bounty']])
        
        # CIA analysis
        cia_analysis = {
            'high_confidentiality': len([s for s in scopes if s['confidentiality_requirement'] == 'high']),
            'high_integrity': len([s for s in scopes if s['integrity_requirement'] == 'high']),
            'high_availability': len([s for s in scopes if s['availability_requirement'] == 'high'])
        }
        
        # Calculate ROI score (simplified version)
        roi_score = self.calculate_roi_score(program_data, len(scopes), severities)
        
        analysis = {
            'extraction_timestamp': datetime.now().isoformat(),
            'program_handle': self.program_handle,
            'total_scopes': len(scopes),
            'bounty_eligible_scopes': bounty_eligible,
            'bounty_eligible_percentage': f"{(bounty_eligible/len(scopes)*100):.1f}%" if scopes else "0%",
            'asset_type_distribution': asset_types,
            'severity_distribution': severities,
            'cia_requirements_analysis': cia_analysis,
            'critical_ratio': f"{(severities.get('critical', 0)/len(scopes)*100):.1f}%" if scopes else "0%",
            'high_value_assets': len([s for s in scopes if s['max_severity'] in ['critical', 'high']]),
            'roi_score': roi_score,
            'success_probability': f"{min(100, roi_score)}%"
        }
        
        return analysis
    
    def calculate_roi_score(self, program_data, scope_count, severities):
        """Calculate ROI score for the program"""
        score = 0
        
        # Scope volume (0-25 points)
        if scope_count >= 1000:
            score += 25
        elif scope_count >= 500:
            score += 20
        elif scope_count >= 100:
            score += 15
        elif scope_count >= 50:
            score += 10
        elif scope_count >= 10:
            score += 5
        else:
            score += 1
        
        # Critical assets (0-30 points)
        critical_ratio = severities.get('critical', 0) / max(scope_count, 1)
        score += min(30, int(critical_ratio * 100))
        
        # Bounty program (0-20 points)
        if program_data.get('offers_bounties'):
            score += 20
        
        # Gold standard (0-15 points)
        if program_data.get('gold_standard_safe_harbor'):
            score += 15
        
        # Fast payments (0-10 points)
        if program_data.get('fast_payments'):
            score += 10
        
        return score
    
    def save_data_files(self, program_data, scopes_data, analysis_data):
        """Save JSON data files"""
        files_saved = {}
        
        # Program data
        program_file = f"{self.program_dir}/{self.program_handle}_program_{self.timestamp}.json"
        with open(program_file, 'w') as f:
            json.dump(program_data, f, indent=2, default=str)
        files_saved['program_file'] = program_file
        
        # Scopes data
        scopes_file = f"{self.program_dir}/{self.program_handle}_structured_scopes_{self.timestamp}.json"
        with open(scopes_file, 'w') as f:
            json.dump(scopes_data, f, indent=2, default=str)
        files_saved['scopes_file'] = scopes_file
        
        # Analysis data
        analysis_file = f"{self.program_dir}/{self.program_handle}_deep_dive_{self.timestamp}.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis_data, f, indent=2, default=str)
        files_saved['analysis_file'] = analysis_file
        
        print(f"💾 Saved {len(files_saved)} JSON data files")
        return files_saved
    
    def generate_complete_data_markdown(self, program_data, scopes_data, analysis_data):
        """Generate COMPLETE-[PROGRAM]-DATA.md file"""
        
        # Format program name for filename
        safe_name = program_data['name'].upper().replace(' ', '-').replace('.', '')
        filename = f"{self.program_dir}/COMPLETE-{safe_name}-DATA.md"
        
        # Get asset type breakdown for display
        asset_types = analysis_data.get('asset_type_distribution', {})
        severity_dist = analysis_data.get('severity_distribution', {})
        
        # Sample high-priority assets
        scopes = scopes_data.get('scopes', [])
        critical_assets = [s for s in scopes if s['max_severity'] == 'critical'][:10]
        
        content = f"""# 🎯 Complete {program_data['name']} Data from PostgreSQL

**Date**: {datetime.now().strftime('%B %d, %Y')}  
**Status**: FULLY ANALYZED  
**Data Source**: PostgreSQL BBHK Database (100% Real Data)  
**ROI Score**: {analysis_data.get('roi_score', 'N/A')}/115

## ✅ {program_data['name']} - Program Overview

### 1. Program Attributes

| Attribute | Value |
|-----------|-------|
| **Handle** | @{program_data['handle']} |
| **Name** | {program_data['name']} |
| **Status** | {program_data['submission_state']} |
| **Bounties** | {'✅ Active' if program_data.get('offers_bounties') else '❌ No bounties'} |
| **Gold Standard** | {'✅ Safe Harbor' if program_data.get('gold_standard_safe_harbor') else '❌ No safe harbor'} |
| **Fast Payments** | {'✅ Available' if program_data.get('fast_payments') else '❌ Not available'} |

### 2. Attack Surface Analysis

#### Total Scope: {analysis_data.get('total_scopes', 0)} Assets
- **Bounty Eligible**: {analysis_data.get('bounty_eligible_scopes', 0)} assets ({analysis_data.get('bounty_eligible_percentage', '0%')})
- **Critical Severity**: {severity_dist.get('critical', 0)} assets ({analysis_data.get('critical_ratio', '0%')})
- **High-Value Assets**: {analysis_data.get('high_value_assets', 0)}
- **Success Probability**: {analysis_data.get('success_probability', '0%')}

#### Asset Type Distribution

| Asset Type | Count |
|------------|-------|"""

        for asset_type, count in asset_types.items():
            content += f"\n| **{asset_type}** | {count} |"

        content += f"""

#### Severity Distribution

| Severity | Count |
|----------|-------|"""

        for severity, count in severity_dist.items():
            content += f"\n| **{severity.title()}** | {count} |"

        content += f"""

### 3. High-Priority Targets

#### Critical Assets (Top 10):
"""
        for i, asset in enumerate(critical_assets, 1):
            content += f"{i}. `{asset['asset_identifier']}` - {asset['asset_type']}\n"

        content += f"""

### 4. CIA Security Requirements

| Requirement | High Rating Count |
|-------------|------------------|
| **Confidentiality** | {analysis_data.get('cia_requirements_analysis', {}).get('high_confidentiality', 0)} |
| **Integrity** | {analysis_data.get('cia_requirements_analysis', {}).get('high_integrity', 0)} |
| **Availability** | {analysis_data.get('cia_requirements_analysis', {}).get('high_availability', 0)} |

### 5. ROI Analysis

- **ROI Score**: {analysis_data.get('roi_score', 'N/A')}/115
- **Success Probability**: {analysis_data.get('success_probability', '0%')}
- **Attack Surface Size**: {analysis_data.get('total_scopes', 0)} assets
- **Critical Asset Ratio**: {analysis_data.get('critical_ratio', '0%')}

### 6. Data Files Generated

1. `{self.program_handle}_program_{self.timestamp}.json` - Complete program data
2. `{self.program_handle}_structured_scopes_{self.timestamp}.json` - All scope items
3. `{self.program_handle}_deep_dive_{self.timestamp}.json` - Analysis and metrics

## 🎯 Strategic Assessment

**Program Summary**: {program_data['name']} offers {analysis_data.get('total_scopes', 0)} assets with {analysis_data.get('critical_ratio', '0%')} critical severity rating.

**Recommended Action**: {'High priority due to excellent ROI metrics' if analysis_data.get('roi_score', 0) >= 80 else 'Medium priority for specialized research' if analysis_data.get('roi_score', 0) >= 50 else 'Lower priority unless specific expertise matches'}

---

**Analysis Generated**: {datetime.now().isoformat()}  
**Framework Version**: 1.0  
**Data Extraction**: Real PostgreSQL Database
"""

        with open(filename, 'w') as f:
            f.write(content)
        
        print(f"📄 Generated: {filename}")
        return filename

    def generate_analysis(self):
        """Generate complete program analysis"""
        print(f"🚀 Starting Program Analysis for: {self.program_handle}")
        print("=" * 60)
        
        # Connect to database
        if not self.connect_db():
            return None
        
        # Create directory
        self.create_program_directory()
        
        # Extract data
        program_data = self.extract_program_data()
        if not program_data:
            return None
            
        scopes_data = self.extract_structured_scopes()
        analysis_data = self.analyze_scopes(scopes_data, program_data)
        
        # Save files
        files_saved = self.save_data_files(program_data, scopes_data, analysis_data)
        
        # Generate markdown documentation
        complete_data_file = self.generate_complete_data_markdown(program_data, scopes_data, analysis_data)
        
        # Close connection
        self.conn.close()
        
        print(f"\n✅ Program Analysis Complete for {program_data['name']}")
        print(f"📊 Assets: {analysis_data.get('total_scopes', 0)}")
        print(f"🔥 Critical: {analysis_data['severity_distribution'].get('critical', 0)}")
        print(f"🏆 ROI Score: {analysis_data.get('roi_score', 'N/A')}/115")
        print(f"📁 Directory: {self.program_dir}")
        
        return {
            'program_data': program_data,
            'scopes_data': scopes_data,
            'analysis_data': analysis_data,
            'files_saved': files_saved,
            'complete_data_file': complete_data_file
        }

def main():
    parser = argparse.ArgumentParser(description='Generate HackerOne Program Analysis')
    parser.add_argument('program_handle', help='HackerOne program handle (e.g., watson_group)')
    parser.add_argument('--list-programs', action='store_true', help='List available programs')
    
    args = parser.parse_args()
    
    if args.list_programs:
        # List available programs
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("SELECT handle, name FROM programs ORDER BY name")
            programs = cursor.fetchall()
            
            print("Available Programs:")
            print("-" * 50)
            for handle, name in programs:
                print(f"{handle:20} | {name}")
            conn.close()
        except Exception as e:
            print(f"Error listing programs: {e}")
        return
    
    # Generate analysis for specified program
    generator = ProgramAnalysisGenerator(args.program_handle)
    results = generator.generate_analysis()
    
    if results:
        print(f"\n🎯 Analysis files created in: {generator.program_dir}")

if __name__ == "__main__":
    main()