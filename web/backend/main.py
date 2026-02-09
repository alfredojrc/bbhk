#!/usr/bin/env python3
"""
BBHK Web Dashboard Backend
FastAPI application for serving bug bounty data
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sqlite3
from typing import List, Dict, Any, Optional
from pathlib import Path
from pydantic import BaseModel
from datetime import datetime
import os

app = FastAPI(
    title="BBHK Dashboard API",
    description="Bug Bounty Hunter Kit Dashboard Backend",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database path - resolve relative to project root
_DEFAULT_DB = str(Path(__file__).resolve().parent.parent.parent / "core" / "database" / "bbhk.db")
DB_PATH = os.getenv("DATABASE_PATH", _DEFAULT_DB)


class Program(BaseModel):
    """Program model"""
    id: int
    platform: str
    name: str
    handle: str
    url: Optional[str]
    max_bounty: Optional[float]
    offers_bounties: bool
    submission_state: str
    managed: bool
    target_count: Optional[int] = 0
    response_efficiency: Optional[float] = 0


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "BBHK Dashboard API",
        "status": "operational",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/stats")
async def get_stats():
    """Get overall statistics"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Get statistics
        stats = {}
        
        # Total programs
        cursor.execute("SELECT COUNT(*) as count FROM programs")
        stats['total_programs'] = cursor.fetchone()['count']
        
        # Programs with bounties
        cursor.execute("SELECT COUNT(*) as count FROM programs WHERE max_bounty > 0")
        stats['programs_with_bounties'] = cursor.fetchone()['count']
        
        # Total targets
        cursor.execute("SELECT COUNT(*) as count FROM targets")
        stats['total_targets'] = cursor.fetchone()['count']
        
        # Programs by platform
        cursor.execute("""
            SELECT p.name, COUNT(pr.id) as count
            FROM platforms p
            LEFT JOIN programs pr ON p.id = pr.platform_id
            GROUP BY p.id
        """)
        stats['programs_by_platform'] = {row['name']: row['count'] for row in cursor.fetchall()}
        
        # Top bounties
        cursor.execute("""
            SELECT program_name, max_bounty
            FROM programs
            WHERE max_bounty > 0
            ORDER BY max_bounty DESC
            LIMIT 10
        """)
        stats['top_bounty_programs'] = [
            {'name': row['program_name'], 'max_bounty': row['max_bounty']}
            for row in cursor.fetchall()
        ]
        
        return stats
        
    finally:
        conn.close()


@app.get("/api/programs", response_model=List[Dict[str, Any]])
async def get_programs(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    platform: Optional[str] = None,
    has_bounty: Optional[bool] = None,
    search: Optional[str] = Query(default=None, max_length=200),
):
    """Get programs with filtering"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Build query
        query = """
            SELECT 
                pr.id,
                pl.name as platform,
                pr.program_name as name,
                pr.program_name as handle,
                pr.program_url as url,
                pr.max_bounty,
                pr.max_bounty > 0 as offers_bounties,
                pr.active as submission_state,
                pr.vdp_only = 0 as managed,
                COUNT(DISTINCT t.id) as target_count
            FROM programs pr
            JOIN platforms pl ON pr.platform_id = pl.id
            LEFT JOIN targets t ON pr.id = t.program_id
            WHERE 1=1
        """
        
        params = []
        
        if platform:
            query += " AND pl.name = ?"
            params.append(platform)
        
        if has_bounty is not None:
            if has_bounty:
                query += " AND pr.max_bounty > 0"
            else:
                query += " AND (pr.max_bounty = 0 OR pr.max_bounty IS NULL)"
        
        if search:
            query += " AND pr.program_name LIKE ?"
            params.append(f"%{search}%")
        
        query += " GROUP BY pr.id ORDER BY pr.max_bounty DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        
        programs = []
        for row in cursor.fetchall():
            programs.append(dict(row))
        
        return programs
        
    finally:
        conn.close()


@app.get("/api/programs/{program_id}")
async def get_program(program_id: int):
    """Get single program details"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT 
                pr.*,
                pl.name as platform_name,
                COUNT(DISTINCT t.id) as target_count
            FROM programs pr
            JOIN platforms pl ON pr.platform_id = pl.id
            LEFT JOIN targets t ON pr.id = t.program_id
            WHERE pr.id = ?
            GROUP BY pr.id
        """, (program_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Program not found")
        
        program = dict(row)
        
        # Get targets
        cursor.execute("""
            SELECT * FROM targets WHERE program_id = ? AND in_scope = 1
        """, (program_id,))
        
        program['targets'] = [dict(row) for row in cursor.fetchall()]
        
        return program
        
    finally:
        conn.close()


@app.get("/api/customers")
async def get_customers():
    """Get customer correlations"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT rule_name, rule_value
            FROM rules
            WHERE scope_type = 'customer'
        """)
        
        customers = []
        for row in cursor.fetchall():
            import json
            data = json.loads(row['rule_value'])
            customers.append({
                'id': row['rule_name'].replace('customer_', ''),
                **data
            })
        
        return customers
        
    finally:
        conn.close()


@app.get("/api/targets")
async def get_targets(program_id: Optional[int] = None):
    """Get targets"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        if program_id:
            cursor.execute("""
                SELECT t.*, p.program_name
                FROM targets t
                JOIN programs p ON t.program_id = p.id
                WHERE t.program_id = ? AND t.in_scope = 1
            """, (program_id,))
        else:
            cursor.execute("""
                SELECT t.*, p.program_name
                FROM targets t
                JOIN programs p ON t.program_id = p.id
                WHERE t.in_scope = 1
                LIMIT 1000
            """)
        
        targets = [dict(row) for row in cursor.fetchall()]
        return targets
        
    finally:
        conn.close()


@app.get("/api/search")
async def search_programs(q: str):
    """Search programs and targets"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Search programs
        cursor.execute("""
            SELECT 
                pr.id,
                pl.name as platform,
                pr.program_name as name,
                pr.max_bounty
            FROM programs pr
            JOIN platforms pl ON pr.platform_id = pl.id
            WHERE pr.program_name LIKE ?
            LIMIT 20
        """, (f"%{q}%",))
        
        programs = [dict(row) for row in cursor.fetchall()]
        
        # Search targets
        cursor.execute("""
            SELECT 
                t.asset_identifier,
                p.program_name
            FROM targets t
            JOIN programs p ON t.program_id = p.id
            WHERE t.asset_identifier LIKE ? AND t.in_scope = 1
            LIMIT 20
        """, (f"%{q}%",))
        
        targets = [dict(row) for row in cursor.fetchall()]
        
        return {
            "programs": programs,
            "targets": targets
        }
        
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)