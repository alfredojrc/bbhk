#!/usr/bin/env python3
"""
Fetch detailed program metrics from HackerOne API
Including response times, payout stats, and resolution rates
"""

import os
import requests
import json
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import base64

# HackerOne API credentials
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')

# Create auth header
credentials = f"{USERNAME}:{API_TOKEN}"
encoded_credentials = base64.b64encode(credentials.encode()).decode()
headers = {
    "Accept": "application/json",
    "Authorization": f"Basic {encoded_credentials}"
}

def fetch_program_details(handle):
    """Fetch detailed metrics for a specific program"""
    # Try multiple endpoints to get comprehensive data
    endpoints = [
        f"https://api.hackerone.com/v1/hackers/programs?filter[handles][]={handle}",
        f"https://api.hackerone.com/v1/hackers/programs/{handle}",
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching from {endpoint}: {e}")
    
    return None

def analyze_programs_for_bootstrap():
    """Analyze multiple programs to find best bootstrap targets"""
    
    # Our potential targets
    targets = [
        "spotify", "vimeo", "8x8-bounty", "stripe", "paypal",
        "shopify", "adobe", "grab", "gitlab", "dropbox",
        "airbnb", "uber", "lyft", "coinbase", "robinhood"
    ]
    
    print("=" * 80)
    print("FETCHING REAL PROGRAM METRICS FROM HACKERONE")
    print("=" * 80)
    
    # Fetch all programs data
    url = "https://api.hackerone.com/v1/hackers/programs?page[size]=100"
    all_programs = []
    
    while url:
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                all_programs.extend(data.get('data', []))
                
                # Check for next page
                url = data.get('links', {}).get('next')
            else:
                print(f"Error: Status {response.status_code}")
                break
        except Exception as e:
            print(f"Error fetching programs: {e}")
            break
    
    print(f"\nTotal programs fetched: {len(all_programs)}")
    
    # Analyze our targets
    results = []
    for program in all_programs:
        attrs = program.get('attributes', {})
        handle = attrs.get('handle')
        
        if handle in targets:
            metrics = {
                'handle': handle,
                'name': attrs.get('name'),
                'offers_bounties': attrs.get('offers_bounties'),
                'response_efficiency_percentage': attrs.get('response_efficiency_percentage'),
                'response_efficiency_in_days': attrs.get('response_efficiency_in_days'),
                'average_time_to_first_program_response': attrs.get('average_time_to_first_program_response'),
                'average_time_to_report_resolved': attrs.get('average_time_to_report_resolved'),
                'average_time_to_bounty_awarded': attrs.get('average_time_to_bounty_awarded'),
                'top_bounty_lower_amount': attrs.get('top_bounty_lower_amount'),
                'top_bounty_upper_amount': attrs.get('top_bounty_upper_amount'),
            }
            results.append(metrics)
            
            print(f"\n{'='*40}")
            print(f"Program: {metrics['name']} ({handle})")
            print(f"Offers Bounties: {metrics['offers_bounties']}")
            print(f"Response Efficiency: {metrics['response_efficiency_percentage']}%")
            print(f"Response Time: {metrics['response_efficiency_in_days']} days")
            print(f"Time to First Response: {metrics['average_time_to_first_program_response']} days")
            print(f"Time to Resolution: {metrics['average_time_to_report_resolved']} days")
            print(f"Time to Bounty: {metrics['average_time_to_bounty_awarded']} days")
            print(f"Top Bounty Range: ${metrics['top_bounty_lower_amount']}-${metrics['top_bounty_upper_amount']}")
    
    # Save to JSON for analysis
    with open('/home/kali/bbhk/PROGRAM_METRICS_ANALYSIS.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n\nResults saved to PROGRAM_METRICS_ANALYSIS.json")
    
    # Rank programs by bootstrap potential
    print("\n" + "="*80)
    print("BOOTSTRAP RANKING (Best to Worst)")
    print("="*80)
    
    # Score based on response time and efficiency
    for program in results:
        score = 0
        if program['response_efficiency_percentage']:
            score += program['response_efficiency_percentage']
        if program['average_time_to_bounty_awarded']:
            # Lower time is better, so invert
            score += (30 - min(program['average_time_to_bounty_awarded'], 30)) * 3
        if program['top_bounty_lower_amount']:
            # Higher min bounty is better
            score += min(program['top_bounty_lower_amount'] / 100, 50)
        
        program['bootstrap_score'] = score
    
    # Sort by score
    ranked = sorted(results, key=lambda x: x.get('bootstrap_score', 0), reverse=True)
    
    for i, program in enumerate(ranked[:10], 1):
        print(f"\n{i}. {program['name']} (Score: {program.get('bootstrap_score', 0):.1f})")
        print(f"   Response: {program['response_efficiency_percentage']}% in {program['response_efficiency_in_days']} days")
        print(f"   Bounty Time: {program['average_time_to_bounty_awarded']} days")
        print(f"   Payout Range: ${program['top_bounty_lower_amount']}-${program['top_bounty_upper_amount']}")

def create_metrics_tables():
    """Create tables to store program metrics"""
    
    create_tables_sql = """
    -- Table for program-wide metrics (how the program performs overall)
    CREATE TABLE IF NOT EXISTS program_metrics (
        id SERIAL PRIMARY KEY,
        handle VARCHAR(100) UNIQUE NOT NULL,
        name VARCHAR(200),
        response_efficiency_percentage FLOAT,
        response_efficiency_in_days FLOAT,
        average_time_to_first_response FLOAT,
        average_time_to_resolution FLOAT,
        average_time_to_bounty FLOAT,
        top_bounty_lower_amount INTEGER,
        top_bounty_upper_amount INTEGER,
        total_reports_resolved INTEGER,
        total_bounties_paid_usd INTEGER,
        bootstrap_score FLOAT,
        last_updated TIMESTAMP DEFAULT NOW()
    );
    
    -- Table for our personal metrics with each program
    CREATE TABLE IF NOT EXISTS hunter_program_stats (
        id SERIAL PRIMARY KEY,
        program_handle VARCHAR(100),
        reports_submitted INTEGER DEFAULT 0,
        reports_triaged INTEGER DEFAULT 0,
        reports_resolved INTEGER DEFAULT 0,
        reports_bounty_awarded INTEGER DEFAULT 0,
        total_earned_usd DECIMAL(10,2) DEFAULT 0,
        average_bounty_usd DECIMAL(10,2) DEFAULT 0,
        highest_bounty_usd DECIMAL(10,2) DEFAULT 0,
        last_submission_date TIMESTAMP,
        last_bounty_date TIMESTAMP,
        personal_success_rate FLOAT,
        notes TEXT,
        FOREIGN KEY (program_handle) REFERENCES program_metrics(handle)
    );
    
    -- Table for tracking bootstrap attempts
    CREATE TABLE IF NOT EXISTS bootstrap_tracking (
        id SERIAL PRIMARY KEY,
        program_handle VARCHAR(100),
        attempt_date DATE,
        hours_invested FLOAT,
        bugs_found INTEGER DEFAULT 0,
        bugs_submitted INTEGER DEFAULT 0,
        bugs_accepted INTEGER DEFAULT 0,
        bounty_earned DECIMAL(10,2) DEFAULT 0,
        tools_used TEXT,
        vulnerability_types TEXT,
        lessons_learned TEXT,
        created_at TIMESTAMP DEFAULT NOW()
    );
    
    COMMENT ON TABLE program_metrics IS 'Overall program performance metrics from HackerOne';
    COMMENT ON TABLE hunter_program_stats IS 'Our personal statistics with each program';
    COMMENT ON TABLE bootstrap_tracking IS 'Track our bootstrap attempts and learnings';
    """
    
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            host="localhost",
            database="bbhk_db",
            user="bbhk_user",
            password=os.getenv('POSTGRES_PASSWORD', '')
        )
        
        with conn.cursor() as cur:
            cur.execute(create_tables_sql)
            conn.commit()
            print("\n✅ Metrics tables created successfully!")
            
    except Exception as e:
        print(f"Error creating tables: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Creating metrics tables...")
    create_metrics_tables()
    
    print("\nFetching program metrics...")
    analyze_programs_for_bootstrap()