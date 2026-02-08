#!/usr/bin/env python3
"""
WORKING HackerOne Data Fetcher - Simple and Direct
NO MORE PLANNING - JUST GET IT WORKING!
"""

import os
import requests
import psycopg2
import json
from dotenv import load_dotenv

load_dotenv('/home/kali/bbhk/.env')

def main():
    # Database connection
    conn = psycopg2.connect(
        host='localhost',
        port=5432,
        database='bbhk_db',
        user='bbhk_user',
        password=os.getenv('POSTGRES_PASSWORD', '')
    )
    
    cursor = conn.cursor()
    
    # HackerOne API
    username = os.getenv('HACKERONE_API_USERNAME')
    token = os.getenv('HACKERONE_API_TOKEN')
    
    print("🚀 Fetching REAL HackerOne programs...")
    
    # Fetch programs
    response = requests.get(
        'https://api.hackerone.com/v1/hackers/programs',
        auth=(username, token),
        params={'page[size]': 25}
    )
    
    if response.status_code != 200:
        print(f"❌ API Error: {response.status_code}")
        return
    
    programs = response.json()['data']
    
    # Store programs
    stored_count = 0
    for program in programs:
        attrs = program['attributes']
        handle = attrs.get('handle', '')
        
        # Skip obvious test programs
        if 'test' in handle.lower() and 'security' not in handle:
            continue
            
        try:
            cursor.execute("""
                INSERT INTO programs (id, handle, name, currency, submission_state, offers_bounties, state)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                program['id'],
                handle,
                attrs.get('name', ''),
                attrs.get('currency', 'usd'),
                attrs.get('submission_state', ''),
                attrs.get('offers_bounties', False),
                attrs.get('state', '')
            ))
            
            stored_count += 1
            print(f"✅ Stored: {attrs.get('name')} ({handle})")
            
            # Get scopes
            scope_response = requests.get(
                f'https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes',
                auth=(username, token)
            )
            
            if scope_response.status_code == 200:
                scopes = scope_response.json()['data']
                for scope in scopes:
                    scope_attrs = scope['attributes']
                    try:
                        cursor.execute("""
                            INSERT INTO structured_scopes (id, program_id, asset_type, asset_identifier, eligible_for_bounty, max_severity)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO NOTHING
                        """, (
                            scope['id'],
                            program['id'],
                            scope_attrs.get('asset_type'),
                            scope_attrs.get('asset_identifier'),
                            scope_attrs.get('eligible_for_bounty', False),
                            scope_attrs.get('max_severity')
                        ))
                    except:
                        pass  # Skip if error
            
        except Exception as e:
            print(f"⚠️ Error with {handle}: {e}")
            continue
    
    conn.commit()
    
    # Show results
    cursor.execute("SELECT COUNT(*) FROM programs")
    program_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM structured_scopes")
    scope_count = cursor.fetchone()[0]
    
    print(f"\n📊 SUCCESS!")
    print(f"Programs: {program_count}")
    print(f"Scopes: {scope_count}")
    print("✅ REAL DATA POPULATED!")
    
    conn.close()

if __name__ == "__main__":
    main()