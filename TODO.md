# BBHK TODO - Project Improvement Plan

**Generated**: 2026-02-08
**Project**: Bug Bounty Hunter Kit v3.0
**Tracked Files**: 572 | **Python LoC**: ~10,800 (src/)

---

## P0 - Critical Bugs (Fix Immediately)

### Code Crashes

- [x] **Fix undefined `template_manager` in `src/main.py:361`**
  - Added import: `from .reporting.templates import template_manager`

- [x] **Fix 3 bare `except:` clauses** (swallow KeyboardInterrupt, SystemExit)
  - `src/analytics/predictor.py` -> `except (ValueError, KeyError)`
  - `src/monitor/bugcrowd.py` -> `except (ValueError, IndexError, TypeError)`
  - `src/compliance/engine.py` -> `except (OSError, UnicodeDecodeError)`

- [ ] **Fix `src/main.py` CLI startup crash**
  - `from .core.database import db_manager` fails on import
  - Module can't be run as `python -m src.main` without proper packaging

### Configuration

- [x] **Fix `docker-compose.yml` external volume**
  - Changed `qdrant-data` from `external: true` to `driver: local`

- [x] **Pin `cryptography` version in `requirements.txt`**
  - Pinned to `cryptography==44.0.1`

---

## P1 - High Priority (This Week)

### Code Cleanup

- [x] **Consolidate 9 duplicate web backends into 1**
  - Removed 8 duplicate files (~3,100 lines dead code)
  - Kept only `web/backend/main.py` (used by Docker)

- [x] **Consolidate duplicate frontends**
  - Removed `web/frontend/`, `web/portal_enhanced/`, `web/dashboard/`, `web/portal/`
  - Kept `docker/frontend/` (active Docker frontend)

- [x] **Remove duplicate fetch/populate scripts**
  - Removed 9 duplicate scripts from `scripts/data/`
  - Kept `get_all_programs.py`, `save_all_programs_to_db.py`, `import-all-570-programs.py`

### Dependency Updates

- [x] **Update Qdrant `v1.12.5` -> `v1.16.3`** in docker-compose.yml
  - Gains: ACORN filtered HNSW, MMR search diversity, full-text filtering,
    tiered multitenancy, disk-efficient vector search

- [x] **Update `requirements.txt` - all packages updated**

  | Package | Old | New | Delta |
  |---------|-----|-----|-------|
  | aiohttp | 3.9.1 | 3.11.14 | Major |
  | fastapi | 0.104.1 | 0.115.8 | Major |
  | sqlalchemy | 2.0.23 | 2.0.38 | Patch |
  | pydantic | 2.5.2 | 2.10.6 | Minor |
  | requests | 2.31.0 | 2.32.3 | Minor |
  | rich | 13.7.0 | 13.9.4 | Minor |
  | cryptography | (unpinned) | 44.0.1 | Pinned |
  | numpy | 1.24.3 | 2.2.3 | Major |
  | pandas | 2.0.3 | 2.2.3 | Minor |
  | scikit-learn | 1.3.0 | 1.6.1 | Major |
  | pytest | 7.4.3 | 8.3.4 | Major |
  | + dnspython | (missing) | 2.7.0 | Added |

- [ ] **Update ProjectDiscovery tools** (all have Jan 2026 releases)
  - nuclei v3.7.0, httpx v1.8.1, katana v1.4.0, subfinder v2.6.6

### Docker Hardening

- [x] **Upgrade base images from `python:3.11-slim` to `python:3.13-slim`**
  - Updated `Dockerfile` and `docker/backend/Dockerfile`
  - Updated `docker/frontend/Dockerfile` from `node:18-alpine` to `node:22-alpine`
  - Updated `setup.py` `python_requires` from `>=3.8` to `>=3.11`

- [x] **Pin all Docker image versions** (removed all `latest` tags)
  - `qdrant/qdrant:v1.16.3`
  - `prom/prometheus:v3.2.1`
  - `grafana/grafana:11.5.1`

---

## P2 - Medium Priority (This Month)

### Project Modernization

- [x] **Migrate `setup.py` to `pyproject.toml`**
  - Created PEP 621 compliant `pyproject.toml` with setuptools backend
  - Includes ruff, mypy, pytest, coverage tool configs
  - Optional deps: `[dev]`, `[ml]`, `[browser]`, `[all]`
  - `setup.py` kept for backwards compatibility

- [ ] **Install and adopt `uv` as package manager**
  - 10-100x faster than pip (Rust-based, by Astral)
  - `curl -LsSf https://astral.sh/uv/install.sh | sh`
  - Replace `pip install -r requirements.txt` with `uv sync`
  - Add `uv.lock` for reproducible builds

- [x] **Make heavy dependencies optional** (partially done)
  - Removed `tensorflow` from core requirements.txt (still in pyproject.toml `[ml]` extras)
  - `scikit-learn` kept in core (used by analytics predictor)

- [x] **Add missing dependency: `dnspython==2.7.0`**
  - Added to requirements.txt

### Code Quality

- [x] **Add database session context managers**
  - Added `session_scope()` and `async_session_scope()` to `DatabaseManager`
  - Updated `get_db()` and `get_async_db()` to use context managers (FastAPI-compatible)
  - Prevents connection leaks with automatic commit/rollback/close

- [x] **Add request validation to API endpoints**
  - `web/backend/main.py`: Added `Query(ge=1, le=1000)` bounds on `limit`
  - Added `Query(ge=0)` on `offset`, `Query(max_length=200)` on `search`
  - Imported `Query` from FastAPI

- [x] **Fix hardcoded collection name in vector store**
  - `src/storage/vector_store.py`: Now reads from `QDRANT_HOST`, `QDRANT_PORT`, `QDRANT_COLLECTION` env vars
  - Falls back to sensible defaults (`localhost:6333`, `bbhk-programs`)

- [x] **Fix fragile DB path construction**
  - `web/backend/main.py`: Replaced `"sqlite:///../../core/database/bbhk.db"` path traversal
  - Now uses `Path(__file__).resolve().parent` for proper resolution
  - Reads from `DATABASE_PATH` env var with proper fallback

### New MCP Integrations

- [x] **Add ProjectDiscovery MCP server** to `.mcp.json`
  - Added `@anthropic-ai/claude-mcp-projectdiscovery@latest` via npx
  - Integrates subfinder, httpx, nuclei, katana, dnsx, naabu
  - Requires `PDCP_API_KEY` env var (added to `.env.example`)

- [ ] **Evaluate FuzzingLabs mcp-security-hub**
  - Docker-based MCP server with Nmap, Ghidra, Nuclei, SQLMap, Hashcat
  - GitHub: `FuzzingLabs/mcp-security-hub`

### Testing

- [ ] **Add unit tests for core modules** (currently 0% coverage)
  - Priority modules: `src/core/config.py`, `src/core/database.py`,
    `src/platforms/hackerone_client.py`
  - Target: 60% coverage on `src/` directory

- [ ] **Add API endpoint tests**
  - `web/backend/main.py` has 0 tests
  - Use `TestClient` from FastAPI

- [ ] **Fix existing tests**
  - `tests/test_discovery.py` (16KB) - check if it runs
  - `tests/test-campaign-lifecycle-system.py` (29KB) - check if it runs
  - `tests/test_scope_frontend.html` - not a real test, move to docs/

### Docker Security

- [x] **Add `security_opt: no-new-privileges`** to all services
  - Applied to: backend, frontend, redis, qdrant, postgres, prometheus, grafana

- [x] **Add `cap_drop: ALL`** and only add required capabilities
  - Redis: `cap_drop ALL` + `read_only: true` + tmpfs
  - Qdrant: `cap_drop ALL`
  - Postgres: `cap_drop ALL` + `cap_add` CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID
  - Prometheus: `cap_drop ALL` + `read_only: true` + tmpfs

- [x] **Add Trivy scanning** via GitHub Actions CI/CD
  - Filesystem scan + Docker image scan in `.github/workflows/ci.yml`
  - SARIF output uploaded to GitHub Security tab

---

## P3 - Low Priority (This Quarter)

### Documentation

- [ ] **Consolidate 30+ doc files into organized structure**
  - Create `docs/INDEX.md` as table of contents (exists but may be stale)
  - Group: setup, architecture, API reference, methodology, troubleshooting
  - Remove/archive outdated docs from Aug 2025

- [ ] **Add OpenAPI/Swagger documentation**
  - FastAPI auto-generates this at `/docs` endpoint
  - Ensure all endpoints have proper type hints and descriptions

- [ ] **Create `scripts/README.md`**
  - Document purpose of each script in `scripts/`
  - Mark which are one-off vs reusable

### New Tools & Platforms

- [ ] **Evaluate Caido** (Rust-based Burp Suite alternative, v0.47.0+)
  - Lower memory, cleaner UI, more affordable
  - Good for manual HTTP traffic analysis
  - Not a full Burp replacement yet (no extensions)

- [ ] **Register on huntr.com** (AI/ML bug bounty platform)
  - World's first AI/ML-specific bug bounty platform (by Protect AI)
  - Up to $50k for critical AI/ML vulnerabilities
  - Growing attack surface as AI adoption increases

- [ ] **Add Semgrep AI-powered IDOR detection** (when out of private beta)
  - 20,000+ rules, AI-powered detection for business logic flaws
  - Directly relevant to BBHK's focus on broken access control

- [ ] **Monitor Microsoft Zero Day Quest** (Spring 2026)
  - Largest-ever hacking event: Azure, Copilot, Identity, M365
  - Copilot bounties up to $30,000

### Architecture

- [ ] **Test Python 3.14 free-threaded build** for concurrent agents
  - PEP 779: GIL removal now supported (not experimental)
  - Could significantly improve multi-agent scanning performance

- [ ] **Evaluate pgvector as Qdrant alternative/complement**
  - If already running PostgreSQL, avoids extra infrastructure
  - Could replace Qdrant for simpler use cases

- [x] **Add CI/CD pipeline** (GitHub Actions)
  - Created `.github/workflows/ci.yml` with 5 jobs:
    - **Lint**: ruff check + format check
    - **Type Check**: mypy on `src/`
    - **Test**: pytest with coverage (Python 3.11, 3.12, 3.13 matrix)
    - **Security**: Trivy filesystem scan with SARIF upload
    - **Docker**: Build backend + frontend images, Trivy image scan

### Cleanup

- [x] **Remove `web/portal_enhanced/`** (done - entire directory removed)

- [x] **Archive one-off data cleanup scripts**
  - Moved to `scripts/archive/`:
    - `CLEAN_FAKE_DATA_AND_REFETCH.py`
    - `COMPLETE_DATA_CLEANUP.py`
    - `URGENT_data_integrity_investigation.py`

- [ ] **Clean up `hacks/` directory**
  - Remove abandoned targets with no findings
  - Archive completed/submitted work
  - Standardize structure per CLAUDE.md rules

- [x] **Update `.env.example`** with all required variables
  - Added: `QDRANT_COLLECTION`, `PDCP_API_KEY`
  - Already had: `QDRANT_API_KEY`, `REACT_APP_API_URL`, `LOG_LEVEL`

---

## Reference: Versions Applied

| Component | Old | New | Notes |
|-----------|-----|-----|-------|
| Python (Docker) | 3.11-slim | 3.13-slim | Ecosystem-compatible |
| Node.js (Docker) | 18-alpine | 22-alpine | Active LTS until Oct 2027 |
| Qdrant | v1.12.5 | v1.16.3 | ACORN, MMR, full-text filtering |
| FastAPI | 0.104.1 | 0.115.8 | Performance, new features |
| Prometheus | latest | v3.2.1 | Pinned |
| Grafana | latest | 11.5.1 | Pinned |
| setup.py python_requires | >=3.8 | >=3.11 | Dropped EOL versions |
| pyproject.toml | (none) | PEP 621 | New declarative config |
| CI/CD | (none) | GitHub Actions | 5-job pipeline |
| Docker security | (none) | Hardened | no-new-privileges, cap-drop, read-only |

## Reference: New MCP Servers

| MCP Server | Status | Purpose |
|------------|--------|---------|
| projectdiscovery | Added | Recon pipeline (subfinder, httpx, nuclei) |
| mcp-security-hub | Evaluate | Nmap, SQLMap, Hashcat integration |
| fuzzforge-ai | Evaluate | AI-powered fuzzing |
| semgrep-mcp | Evaluate | Static analysis rules |

---

*Last updated: 2026-02-08 by Claude Opus 4.6*
