# RansomShield AI — Production-Grade Ransomware Detection & SOC Platform

RansomShield AI is an enterprise-defensible, AI-powered Windows ransomware detection and Security Operations Center (SOC) monitoring platform. It combines real-time Windows kernel and endpoint telemetry, an XGBoost Model V2 machine learning classification engine trained on authentic Windows Sysmon ransomware datasets, a resilient FastAPI backend with MongoDB persistence, authenticated WebSockets, reversible defensive endpoint containment, and a dark-themed React SOC dashboard.

---

## 1. System Architecture Overview

```
+-------------------------------------------------------------------------------------------------------------+
|                                           WINDOWS ENDPOINT AGENT                                            |
|                                                                                                             |
|   +-----------------------+     +-----------------------+     +-----------------------------------------+   |
|   | Live Telemetry Engine | --> |  Model V2 Inference   | --> | Decision Engine & Alert/Incident Manager|   |
|   +-----------------------+     +-----------------------+     +-----------------------------------------+   |
|                                                                                    |                        |
|                                         +------------------------------------------+                        |
|                                         | Non-blocking enqueue (< 0.2ms)                                    |
|                                         v                                                                   |
|                     +---------------------------------------+                                               |
|                     |     AgentTransportManager (Queue)     |                                               |
|                     |      Bounded in-memory (500 items)    |                                               |
|                     +---------------------------------------+                                               |
|                              |                     |                                                        |
|            Queue not full    |                     | Outage / Queue full                                    |
|                              v                     v                                                        |
|                     +------------------+  +------------------+                                              |
|                     | Background Worker|  |   SQLite Spool   |                                              |
|                     |    Thread        |  | (ransomshield_   |                                              |
|                     +------------------+  |  spool.db)       |                                              |
|                              |            +------------------+                                              |
|                              | Send over HTTP      ^                                                        |
|                              v                     | Drain on reconnect                                     |
|                     +----------------------------------+                                                    |
|                     |        AgentNetworkClient        |                                                    |
|                     |  X-Agent-Key + Exponential Retry |                                                    |
|                     +----------------------------------+                                                    |
+---------------------------------------|---------------------------------------------------------------------+
                                        | HTTP REST (POST JSON with X-Agent-Key)
                                        v
+-------------------------------------------------------------------------------------------------------------+
|                                              FASTAPI BACKEND                                                |
|                                                                                                             |
|   1. Security & Protection Middleware:                                                                      |
|      - RateLimiterMiddleware (Sliding window throttling: Auth 10/min, Response 30/min, General 120/min)      |
|      - RequestSizeLimitMiddleware (Strict 10MB payload size limit; returns HTTP 413)                         |
|      - Agent Auth (X-Agent-Key validation via constant-time hmac.compare_digest)                             |
|      - JWT Authentication (HS256 signature verification, expiration, role claims)                           |
|      - Server-Side RBAC (ADMIN, ANALYST, VIEWER enforcement)                                                |
|                                                                                                             |
|   2. Persistence Layer:                                                                                     |
|      - MongoDB collections: agents, detections, alerts, incidents, users, response_actions, response_audit  |
|      - Automatic graceful fallback to In-Memory Repositories when MongoDB is offline                        |
|                                                                                                             |
|   3. Event Streaming:                                                                                       |
|      - WebSocketManager (/api/v1/ws?token=<jwt>) broadcasting live detection, alert, and incident updates   |
+----------------------------------------|--------------------------------------------------------------------+
                                         | WebSocket ws://.../api/v1/ws?token=<jwt>
                                         v
+-------------------------------------------------------------------------------------------------------------+
|                                            REACT SOC DASHBOARD                                              |
|                                                                                                             |
|   - Real API Client (src/services/api.ts) with JWT Bearer authentication                                    |
|   - Live WebSocket Stream with exponential backoff auto-reconnect                                           |
|   - Response Center: Process termination, reversible file quarantine, network isolation, two-person rule    |
+-------------------------------------------------------------------------------------------------------------+
```

---

## 2. Quick Start & Development Setup

### 2.1. Prerequisites
- **Python**: 3.11+ (Tested on Python 3.11 – 3.14)
- **Node.js**: 18+ and npm (or bun)
- **MongoDB**: 6.0+ (Optional; local instance on `localhost:27017` or standalone Docker container. Backend automatically falls back to in-memory mode if MongoDB is absent)
- **Operating System**: Windows 10/11 or Windows Server (for native Windows Agent ETW/Sysmon telemetry); Backend & Dashboard run cross-platform on Windows or Linux.

### 2.2. Configuration
Copy the environment template:
```bash
cp .env.example .env
```

Review and adjust settings in `.env`:
```ini
# Environment Mode: development, testing, or production
ENVIRONMENT="development"

# Server Host & Port
HOST="0.0.0.0"
PORT=8000
DEBUG=false

# Authentication & Cryptography
JWT_SECRET_KEY="dev-jwt-secret-key-change-in-production-min-32-chars"
JWT_ALGORITHM="HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=480

# Agent Secret Header Key
RANSHIELD_AGENT_KEY="rs-agent-secret-key-dev"

# Database Configuration
MONGODB_URI="mongodb://localhost:27017"
MONGODB_DATABASE="ransomshield_db"

# Containment Safety
RESPONSE_DRY_RUN=true
```

### 2.3. Starting the Backend
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

### 2.4. Starting the React SOC Dashboard
```bash
cd ransomshield-complete-main
npm install
npm run dev
```
Open `http://localhost:5173` to access the SOC command center.

### 2.5. Default Credentials
| Username | Password | Role | Description |
|---|---|---|---|
| `admin` | `admin123` | `ADMIN` | Full administrative access, user management, policy & containment approval |
| `analyst` | `analyst123` | `ANALYST` | Threat triage, alert & incident acknowledgment and resolution |
| `viewer` | `viewer123` | `VIEWER` | Read-only observation of telemetry, metrics, and incident history |

---

## 3. Production Deployment & Security Requirements

### 3.1. Production Security Guardrails
When `ENVIRONMENT="production"`, the backend strictly validates configuration upon startup and will **refuse to boot** if insecure settings are detected:
- **`JWT_SECRET_KEY`**: Must be at least 32 characters in length and cannot match default development placeholders. Generate using:
  ```bash
  openssl rand -hex 32
  ```
- **`RANSHIELD_AGENT_KEY`**: Must be at least 16 characters in length and cannot match default placeholders. Generate using:
  ```bash
  openssl rand -hex 16
  ```
- **`CORS_ORIGINS`**: Wildcards (`*`) are prohibited. Must specify explicit production domain origins (e.g. `["https://soc.corp.local"]`).
- **`RESPONSE_DRY_RUN`**: Explicitly set to `false` only after full containment staging and policy review.

### 3.2. Docker Deployment (Backend & Database Stack)
A multi-stage `Dockerfile` and `docker-compose.yml` are provided for containerized backend and database deployment:
```bash
# Start backend and MongoDB services
docker-compose up -d --build

# View backend logs
docker-compose logs -f backend

# Verify health status
curl http://localhost:8000/api/v1/health/ready
```
> **Note**: The **Windows Endpoint Agent** (`agent/`) remains a native Windows application / service to interface directly with Windows kernel ETW and Sysmon event tracing. It is never containerized.

### 3.3. Rate Limiting Policy
Built-in sliding-window in-memory throttling per client IP address:
- **Auth Endpoints (`/api/v1/auth/login`, `/register`)**: 10 requests / minute
- **Response Actions (`/api/v1/response/actions`)**: 30 requests / minute
- **General Endpoints**: 120 requests / minute
- Exceeding clients receive **HTTP 429 Too Many Requests** with `Retry-After: 60`.

### 3.4. Input Validation & Containment Guards
- **File Quarantine Path Traversal Protection**: Rejects null bytes (`\x00`), UNC network paths (`\\\\`), and directory traversals (`..`). Re-computes SHA-256 pre- and post-quarantine.
- **Process Termination Guards**: Re-verifies PID existence and executable name match immediately prior to kill. Rejects PID 0, PID 4, critical OS system binaries, and the agent itself.
- **Network Isolation**: Dedicated reversible Windows Firewall rules preserving management connectivity to the backend host. Zero arbitrary shell command execution.

---

## 4. Backup, Recovery & Maintenance Procedures

### 4.1. MongoDB Backup & Restoration
```bash
# Export full database dump
mongodump --uri="mongodb://localhost:27017" --db="ransomshield_db" --out="/var/backups/ransomshield_$(date +%F)"

# Restore database from archive
mongorestore --uri="mongodb://localhost:27017" --db="ransomshield_db" "/var/backups/ransomshield_2026-09-17/ransomshield_db"
```

### 4.2. Local Agent Spool Maintenance
During prolonged network outages, the agent spools unsent telemetry to `ransomshield_spool.db` in SQLite format:
- Spool capacity: Up to 50,000 events before circular pruning.
- Automatic recovery: Telemetry automatically drains and replays in FIFO order when connectivity to the backend is re-established.
- Corruption recovery: If SQLite detects database file corruption, the agent archives the damaged spool with a timestamp suffix (`ransomshield_spool.db.corrupt.<timestamp>`) and initializes a clean spool without interrupting detection.

### 4.3. Quarantined File Restoration
Quarantined files are held in an isolated directory with metadata manifests:
- To restore a quarantined file, use the SOC Dashboard Response Center or trigger `POST /api/v1/response/actions` with `action_type: RESTORE_FILE`.
- The system verifies the original SHA-256 hash before restoring the file to its original normalized path.

---

## 5. Automated Testing & Verification

Run the entire regression test suite across all subsystems:
```bash
# Full regression suite (224 tests)
python -m pytest ml/tests backend/tests agent/tests -q

# Domain specific suites
python -m pytest ml/tests -v
python -m pytest backend/tests -v
python -m pytest agent/tests -v

# Dedicated security hardening suite
python -m pytest backend/tests/test_security_hardening.py -v

# Frontend production build & dependency audit
cd ransomshield-complete-main
npm run build
npm audit --omit=dev
```

---

## 6. Implementation Phase Status

- [x] **Phase 1**: Machine Learning Pipeline & Model V2 (19-feature Sysmon contract, TreeSHAP)
- [x] **Phase 2A**: Windows Agent Foundation & Telemetry Buffers
- [x] **Phase 2B**: Live Windows Collectors (psutil, watchdog, Sysmon XML parser)
- [x] **Phase 2C**: Sliding Window Feature Aggregator & Model V2 Inference
- [x] **Phase 2D**: Decision Engine, Alerts & Incident Management
- [x] **Phase 3A**: FastAPI Backend Foundation & Health/Readiness Probes
- [x] **Phase 3B**: MongoDB Persistence Layer (Graceful fallback to in-memory storage)
- [x] **Phase 3C**: Full Backend Integration (Transport Queue, SQLite Spool, WebSockets, JWT/RBAC, React Real API)
- [x] **Phase 4**: Automated Containment & Defensive Response (Process termination, reversible file quarantine, network isolation, two-person approval)
- [x] **Phase 5**: Production Hardening & Security (Secret audit, rate limiting, request size limits, Docker readiness, 13 security tests, 224/224 regression tests)
- [x] **Phase 6**: Final End-to-End Validation, Release Verification & Project Completion (Full system integration, 224/224 passing twice, 757ms clean build, RC1 release readiness)

