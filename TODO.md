# BBHK TODO - Project Improvement Plan

**Generated**: 2026-02-08 | **Updated**: 2026-02-09
**Project**: Bug Bounty Hunter Kit v3.0
**Tracked Files**: 523 | **Python LoC**: ~10,800 (src/)

---

## P0 - Critical Bugs (Fix Immediately)

### Code Crashes

- [x] **Fix undefined `template_manager` in `src/main.py:361`**
  - Added import: `from .reporting.templates import template_manager`

- [x] **Fix 3 bare `except:` clauses** (swallow KeyboardInterrupt, SystemExit)
  - `src/analytics/predictor.py` -> `except (ValueError, KeyError)`
  - `src/monitor/bugcrowd.py` -> `except (ValueError, IndexError, TypeError)`
  - `src/compliance/engine.py` -> `except (OSError, UnicodeDecodeError)`

- [x] **Fix `src/main.py` CLI startup crash**
  - Added `src/__main__.py` entry point (`python -m src` now works)
  - Fixed Click `--config` param name mismatch (was `config_file`)
  - Fixed `config` import shadowing (renamed to `app_config`)
  - Fixed loguru compression format (`"gzip"` -> `"gz"`)
  - Fixed module-level `setup_logging()` call (deferred to CLI invocation)
  - Fixed SQLAlchemy `metadata` reserved column name in AuditLog
  - Fixed `pool_size`/`max_overflow` not supported by SQLite
  - Added `aiosqlite` dependency for async SQLite support
  - Updated `__version__` from 1.0.0 to 3.0.0

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
  | + aiosqlite | (missing) | 0.22.1 | Added |

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
  - Created PEP 621 compliant `pyproject.toml` with `setuptools.build_meta` backend
  - Includes ruff, mypy, pytest, coverage tool configs
  - Optional deps: `[dev]`, `[ml]`, `[browser]`, `[all]`
  - Console script: `bbhk = "src.main:cli"`
  - `setup.py` kept for backwards compatibility

- [x] **Install and adopt `uv` as package manager**
  - Updated uv from v0.8.11 to v0.10.0
  - `uv.lock` tracked for reproducible builds (4338 lines, 177 packages)
  - `uv sync` replaces `pip install -r requirements.txt`
  - `uv run bbhk --help` works out of the box
  - CI/CD updated to use `astral-sh/setup-uv@v6`

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

- [x] **Fix SQLAlchemy deprecation warnings**
  - `declarative_base()` -> `sqlalchemy.orm.declarative_base()`
  - `datetime.utcnow()` -> `datetime.now()` in API

### New MCP Integrations

- [x] **Add ProjectDiscovery MCP server** to `.mcp.json`
  - Added `@anthropic-ai/claude-mcp-projectdiscovery@latest` via npx
  - Integrates subfinder, httpx, nuclei, katana, dnsx, naabu
  - Requires `PDCP_API_KEY` env var (added to `.env.example`)

- [ ] **Evaluate FuzzingLabs mcp-security-hub**
  - Docker-based MCP server with Nmap, Ghidra, Nuclei, SQLMap, Hashcat
  - GitHub: `FuzzingLabs/mcp-security-hub`

### Testing

- [x] **Add unit tests for core modules**
  - `tests/test_config.py`: 9 tests (Config defaults, JSON loading, env overrides, save)
  - `tests/test_database.py`: 8 tests (table creation, session scope, CRUD, rollback)
  - Coverage: **97% on config.py**, **88% on database.py**

- [x] **Add API endpoint tests**
  - `tests/test_api.py`: 18 tests using FastAPI TestClient
  - Tests: root, stats, programs (filtering, validation, pagination), search, targets
  - Validation tests: limit bounds, offset bounds, search length

- [ ] **Fix existing tests**
  - `tests/test_discovery.py` (16KB) - check if it runs
  - `tests/test-campaign-lifecycle-system.py` (29KB) - check if it runs
  - `tests/test_scope_frontend.html` - not a real test, move to docs/

- [ ] **Increase test coverage above 50%**
  - Current: 6% overall (core modules well covered, scanner/monitor untested)
  - Add tests for `src/platforms/hackerone_client.py`
  - Add tests for `src/scanner/` modules

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

- [ ] **Evaluate Caido** (Rust-based Burp Suite alternative, production-ready)
  - Plugin ecosystem now available
  - Lower memory, cleaner UI, more affordable than Burp
  - Good for manual HTTP traffic analysis

- [ ] **Register on huntr.com** (AI/ML bug bounty platform)
  - World's first AI/ML-specific bug bounty platform (by Protect AI)
  - Up to $50k for critical AI/ML vulnerabilities
  - Growing attack surface as AI adoption increases - blue ocean opportunity

- [ ] **Add Semgrep AI-powered IDOR detection** (request private beta access)
  - 1.9x better IDOR detection vs traditional rules
  - 20,000+ rules, AI-powered detection for business logic flaws
  - Directly relevant to BBHK's focus on broken access control

- [ ] **Monitor Microsoft Zero Day Quest** (Fall 2026)
  - Spring 2026 event closed - prepare for Fall 2026
  - Azure, Copilot, Identity, M365 targets
  - Copilot bounties up to $30,000

### Architecture

- [ ] **Test Python 3.14 free-threaded build** for concurrent agents
  - PEP 779: GIL removal now supported (not experimental)
  - Wait for ecosystem maturity before adopting

- [ ] **Evaluate pgvector as Qdrant alternative/complement**
  - If already running PostgreSQL, avoids extra infrastructure
  - Could replace Qdrant for simpler use cases

- [x] **Add CI/CD pipeline** (GitHub Actions)
  - Created `.github/workflows/ci.yml` with 5 jobs using `uv`:
    - **Lint**: ruff check + format check (via `uv run`)
    - **Type Check**: mypy on `src/` (via `uv run`)
    - **Test**: pytest with coverage (Python 3.11, 3.12, 3.13 matrix)
    - **Security**: Trivy filesystem scan with SARIF upload
    - **Docker**: Build backend + frontend images, Trivy image scan
  - **Note**: CI file exists locally but NOT pushed to GitHub (needs `workflow` OAuth scope)
  - To push: `gh auth refresh -h github.com -s workflow` (requires browser)

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
| pyproject.toml | (none) | PEP 621 | Declarative config with setuptools.build_meta |
| uv | 0.8.11 | 0.10.0 | Rust-based package manager, 10-100x faster |
| CI/CD | (none) | GitHub Actions | 5-job pipeline with uv |
| Docker security | (none) | Hardened | no-new-privileges, cap-drop, read-only |

## Reference: Test Suite

| Test File | Tests | Covers |
|-----------|-------|--------|
| `tests/test_config.py` | 9 | Config defaults, JSON loading, env overrides, save |
| `tests/test_database.py` | 8 | Table creation, CRUD, session scope, rollback |
| `tests/test_api.py` | 18 | All API endpoints, validation, filtering, 404s |
| **Total** | **35** | **97% config, 88% database, 6% overall** |

## Reference: New MCP Servers

| MCP Server | Status | Purpose |
|------------|--------|---------|
| projectdiscovery | Added | Recon pipeline (subfinder, httpx, nuclei) |
| mcp-security-hub | Evaluate | Nmap, SQLMap, Hashcat integration |
| fuzzforge-ai | Evaluate | AI-powered fuzzing |
| semgrep-mcp | Evaluate | Static analysis rules |

---

*Last updated: 2026-02-09 by Claude Opus 4.6*
