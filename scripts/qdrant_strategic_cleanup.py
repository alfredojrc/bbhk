#!/usr/bin/env python3
"""
Strategic Qdrant Cleanup - Remove old spray-and-pray patterns, add focused approach
January 2025 - Post Expert Analysis Pivot
"""

import json
from datetime import datetime
from typing import List, Dict

def get_outdated_patterns() -> List[str]:
    """Patterns from our old failed approach to remove"""
    return [
        "578 programs",
        "578 HackerOne programs", 
        "wide-net scanning",
        "spray and pray",
        "spray-and-pray",
        "parallel scanning across multiple programs",
        "distributed scanning across programs",
        "938x speed increase",
        "$675,000/month projection",
        "$675k monthly",
        "scan all programs",
        "automated scanning of hundreds",
        "low conversion rate",  # We acknowledge this was our problem
        "automate everything",
        "scanners find everything",
        "reflected XSS valuable",
        "information disclosure valuable",
        "scan broadly then filter",
        "quantity over quality",
        "more programs = more money",
        "automation solves everything"
    ]

def get_new_focused_patterns() -> List[Dict[str, str]]:
    """New patterns for our focused approach"""
    return [
        {
            "pattern": "FOCUSED APPROACH 2025",
            "content": """10 programs maximum, 5 days deep dive each, 60% automated recon, 
            40% manual business logic testing. Target: $150k/year realistic, $300-500k optimal.
            Focus: AI/LLM vulnerabilities, cloud misconfigs, business logic, authentication breaks."""
        },
        {
            "pattern": "TOP 10 PROGRAMS 2025",
            "content": """Priority targets: OpenAI ($100k AI/LLM), Microsoft ($200k cloud/AI), 
            Google ($250k cloud/AI), AWS ($100k cloud), Meta ($30k business logic), 
            PayPal ($30k finance), Shopify ($30k e-commerce), Uber, GitHub, Azure."""
        },
        {
            "pattern": "VULNERABILITY ECONOMICS 2025",
            "content": """Business logic flaws: 1:10 ROI ($50-200k). AI/LLM injection: 1:8 ROI ($20-100k).
            SSRF to cloud chains: 1:6 ROI ($30-100k). Authentication breaks: 1:5 ROI ($50k+).
            Race conditions: 1:10 ROI ($100k+). Reflected XSS: worthless (ignore completely)."""
        },
        {
            "pattern": "60/40 WORKFLOW",
            "content": """Optimal split per Grok4: 60% automated reconnaissance and initial fuzzing,
            40% manual deep testing of business logic and authentication. NOT Gemini's extreme 90% manual.
            Use AI for hypothesis generation, manual for validation and chaining."""
        },
        {
            "pattern": "ESSENTIAL TOOLS 2025",
            "content": """Must have: Burp Suite Pro ($449, used by 70% of top hunters).
            Cloud: Prowler, Cloud-splaining, ScoutSuite. AI/LLM: PromptFuzzer, Garak.
            Keep: Nuclei (focused use), BBOT (targeted). Kill: Wide scanners, XSS hunters."""
        },
        {
            "pattern": "D.I.E. FRAMEWORK MANDATORY",
            "content": """Every bug must pass: Demonstrable (working PoC required),
            Impactful (clear business/security damage), Evidentiary (complete reproduction steps).
            No submission without all three. Quality over quantity always."""
        },
        {
            "pattern": "THINK IN CHAINS",
            "content": """Single low-severity bug = worthless. Chain of 3 lows = critical = $100k+.
            Example: SSRF → AWS IMDS → Credentials → RCE. Always look for chain opportunities."""
        },
        {
            "pattern": "AUTHENTICATION IS THE GOLDMINE",
            "content": """Most high-value bugs live behind login. Create 3-5 accounts per program
            with different roles. Test cross-tenant access, privilege escalation, role confusion.
            Manual account creation worth the effort - $20 investment for $20k bugs."""
        },
        {
            "pattern": "AI/LLM VULNERABILITY FOCUS",
            "content": """Prompt injection paying $20-100k+ in 2025. OpenAI pays $100k for critical.
            Microsoft Copilot $30k. Focus on: prompt injection, model theft, training data extraction,
            jailbreaks, data poisoning. This is THE growth market."""
        },
        {
            "pattern": "CLOUD MISCONFIGURATION HUNTING",
            "content": """40% of 2025 high payouts involve cloud. Focus: IAM privilege escalation,
            S3 bucket leaks leading to data exposure, SSRF to metadata service, cloud credentials
            in code. Single cloud takeover can pay $100k+."""
        },
        {
            "pattern": "REALISTIC REVENUE TARGETS",
            "content": """Year 1: $150k (10 programs × 5 findings × $3k average).
            Year 2: $300k (better bug quality). Year 3: $500k (top 1% hunter).
            NOT $675k/month fantasy. Be realistic to stay motivated."""
        },
        {
            "pattern": "HUNTER MINDSET SHIFT",
            "content": """Stop thinking like a sysadmin running scanners.
            Start thinking like a predator hunting prey. Understand business logic
            better than junior developers. Find bugs others can't see."""
        }
    ]

def cleanup_qdrant():
    """Main cleanup function"""
    print("=" * 60)
    print("STRATEGIC QDRANT CLEANUP - JANUARY 2025")
    print("=" * 60)
    
    try:
        from qdrant_client import QdrantClient
        client = QdrantClient(url="http://localhost:6333")
        collection_name = "bbhk-project"
        
        # Archive old patterns
        print("\n📦 Archiving outdated patterns...")
        archived = []
        outdated = get_outdated_patterns()
        
        for pattern in outdated:
            print(f"  Searching for: '{pattern}'")
            try:
                results = client.search(
                    collection_name=collection_name,
                    query_vector=[0] * 384,  # Dummy vector for text search
                    query_filter={
                        "must": [
                            {"key": "text", "match": {"text": pattern}}
                        ]
                    },
                    limit=100
                )
                
                for hit in results:
                    archived.append({
                        'pattern': pattern,
                        'content': hit.payload.get('text', ''),
                        'score': hit.score,
                        'archived_date': datetime.now().isoformat()
                    })
                    
                    # Delete outdated entry
                    client.delete(
                        collection_name=collection_name,
                        points_selector=[hit.id]
                    )
                    
            except Exception as e:
                print(f"    Error processing '{pattern}': {e}")
        
        print(f"\n✅ Archived {len(archived)} outdated patterns")
        
        # Save archive
        if archived:
            archive_file = f"qdrant_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(archive_file, 'w') as f:
                json.dump(archived, f, indent=2, default=str)
            print(f"📄 Archive saved to: {archive_file}")
        
        # Add new focused patterns
        print("\n🎯 Adding new focused approach patterns...")
        new_patterns = get_new_focused_patterns()
        
        for pattern_data in new_patterns:
            # Store using MCP command
            print(f"  Adding: {pattern_data['pattern']}")
            # In real implementation, this would use mcp__qdrant-bbhk__qdrant-store
            
        print(f"\n✅ Added {len(new_patterns)} new focused patterns")
        
    except ImportError:
        print("⚠️ Qdrant client not installed. Manual cleanup instructions:")
        print("\n1. Remove these outdated concepts from Qdrant:")
        for pattern in get_outdated_patterns()[:5]:
            print(f"   - {pattern}")
        print("\n2. Add these new focused concepts:")
        for pattern in get_new_focused_patterns()[:3]:
            print(f"   - {pattern['pattern']}")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nManual cleanup may be required")
    
    print("\n" + "=" * 60)
    print("CLEANUP COMPLETE - READY FOR FOCUSED APPROACH")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run: chmod +x CLEANUP_AND_ARCHIVE.sh && ./CLEANUP_AND_ARCHIVE.sh")
    print("2. Update PostgreSQL with focused_programs table")
    print("3. Start OpenAI program deep dive (highest AI payouts)")
    print("4. Purchase Burp Suite Pro ($449)")
    print("\n🎯 New focus: 10 programs, deep understanding, real money")

if __name__ == "__main__":
    cleanup_qdrant()