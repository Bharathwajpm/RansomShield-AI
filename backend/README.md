# RansomShield AI — FastAPI Backend Service

**Component:** SOC Backend API  
**Current Phase:** Phase 3B (MongoDB Persistence Layer)  
**Status:** Completed & Verified (160/160 Full Suite Tests Passing)  

---

> [!NOTE]
> **Phase 3B Scope & Architecture:**  
> Phase 3B introduces production-grade MongoDB persistence while preserving the repository abstraction layer (`BaseRepository[T]`). The backend dynamically routes persistence between MongoDB and in-memory fallback based on environment configuration (`DATABASE_BACKEND="auto"|"mongodb"|"memory"`) and live connection health. The REST API contracts, service layer, and router definitions remain 100% backward-compatible.

---

## 1. System Architecture

```
                       WINDOWS ENDPOINT (Agent)
                                  │
                                  ▼
                InMemoryTelemetryBuffer (5s/10s/30s)
                                  │
                                  ▼
                     Model V2 XGBoost + TreeSHAP
                                  │
                                  ▼
                      DetectionDecisionEngine
                                  │
                     ┌────────────┴────────────┐
                     ▼                         ▼
               AlertManager              IncidentManager
                     │                         │
                     └────────────┬────────────┘
                                  ▼
                         AgentModelAdapter
                                  │ (REST API / Transport)
                                  ▼
                       FastAPI Backend (/api/v1)
                                  │
            ┌─────────────────────┼─────────────────────┐
            ▼                     ▼                     ▼
     /agents (Router)      /alerts (Router)     /incidents (Router)
            │                     │                     │
            ▼                     ▼                     ▼
       AgentService          AlertService        IncidentService
            │                     │                     │
            ▼                     ▼                     ▼
     AgentRepository       AlertRepository       IncidentRepository
            │                     │                     │
            └─────────────────────┼─────────────────────┘
                                  ▼
                         Repository Selection
                         ├── MongoDB Repositories (Phase 3B Primary)
                         │   ├── MongoAgentRepository
                         │   ├── MongoAlertRepository
                         │   ├── MongoIncidentRepository
                         │   └── MongoDetectionRepository
                         │        │
                         │        ▼
                         │   MongoDB Database (Collections & Indexes)
                         │   ├── agents
                         │   ├── alerts
                         │   ├── incidents
                         │   └── detections
                         │
                         └── In-Memory Repositories (Fallback / Unit Tests)
```

---

## 2. Directory Layout

```
backend/
├── __init__.py                # Package metadata and version info
├── main.py                    # FastAPI application entrypoint & lifespan
├── config/
│   ├── __init__.py
│   └── settings.py            # Pydantic Settings v2 configuration
├── database/
│   ├── __init__.py
│   └── mongodb.py             # Asynchronous MongoDB connection manager & index init
├── schemas/
│   ├── __init__.py
│   ├── common.py              # ResponseEnvelope, ErrorDetail, HealthResponse, Readiness
│   ├── agent.py               # AgentRegisterRequest, AgentResponse, AgentStatusResponse
│   ├── alert.py               # AlertResponse, AlertAcknowledgeRequest, AlertResolveRequest
│   ├── incident.py            # IncidentResponse, IncidentAcknowledgeRequest, Resolve, FalsePositive
│   └── detection.py           # DetectionIngestRequest, DetectionResponse
├── repositories/
│   ├── __init__.py
│   ├── base.py                # Generic BaseRepository interface
│   ├── factory.py             # Dynamic repository selection factory
│   ├── agent_repository.py    # Thread-safe in-memory Agent repository
│   ├── alert_repository.py    # Thread-safe in-memory Alert repository
│   ├── incident_repository.py # Thread-safe in-memory Incident repository
│   ├── detection_repository.py# Thread-safe in-memory Detection repository
│   ├── mongo_agent_repository.py    # Persistent MongoDB Agent repository
│   ├── mongo_alert_repository.py    # Persistent MongoDB Alert repository
│   ├── mongo_incident_repository.py # Persistent MongoDB Incident repository
│   └── mongo_detection_repository.py# Persistent MongoDB Detection repository
├── services/
│   ├── __init__.py
│   ├── agent_service.py       # Agent registration & discovery business logic
│   ├── alert_service.py       # Alert listing & lifecycle transitions
│   ├── incident_service.py    # Incident listing & validated state machine transitions
│   └── detection_service.py   # Raw detection result streaming & storage
├── middleware/
│   ├── __init__.py
│   ├── request_logging.py     # Request ID (X-Request-ID) tracking & execution timing
│   └── error_handler.py       # Standardized error envelopes & sanitization
├── logging/
│   ├── __init__.py
│   └── structured_logger.py   # Standardized structured backend logger
├── adapters/
│   ├── __init__.py
│   └── agent_adapter.py       # Agent DetectionResult/Alert/Incident to Pydantic adapters
├── tests/
│   ├── __init__.py
│   ├── test_health.py         # Health, liveness, and readiness tests
│   ├── test_schemas.py        # Pydantic schema validation tests
│   ├── test_api_contracts.py  # REST API endpoint CRUD and state transition tests
│   ├── test_agent_integration.py # Agent model to backend schema conversion tests
│   ├── test_backend_startup.py# Lifespan, CORS, middleware, error formatting tests
│   ├── test_mongo_connection.py # MongoDB connection, URI sanitization & probes
│   ├── test_mongo_repositories.py # MongoDB repository CRUD, filters & index verification
│   ├── test_persistence_verification.py # Cross-session data persistence proof
│   └── test_mongo_failure_handling.py # Database outage, invalid URI & timeout resilience
└── README.md
```

---

## 3. Environment Variables Configuration

Configure environment variables in `.env` (derived from `.env.example`):

```bash
# Application Identity
APP_NAME="RansomShield AI Backend"
APP_VERSION="0.1.0"
ENVIRONMENT="development"
DEBUG=false
HOST="0.0.0.0"
PORT=8000
API_V1_PREFIX="/api/v1"
LOG_LEVEL="INFO"

# Database Configuration (Phase 3B: MongoDB Persistence)
DATABASE_BACKEND="auto"        # Options: "auto" (default), "mongodb", "memory"
MONGODB_URI="mongodb://localhost:27017"
MONGODB_DATABASE="ransomshield_db"
MONGODB_SERVER_SELECTION_TIMEOUT_MS=2000
MONGODB_CONNECT_TIMEOUT_MS=2000

# CORS Configuration (Comma-separated list of allowed origins)
CORS_ORIGINS="http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"

# Agent Communication Settings
AGENT_HEARTBEAT_TIMEOUT_SECONDS=60
MAX_IN_MEMORY_RECORDS=1000
```

---

## 4. Running the Backend Server

Start the FastAPI application using Uvicorn:

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive Documentation:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

---

## 5. MongoDB Collections & Indexes

| Collection | Unique Index | Query & Sorting Indexes | Purpose |
|---|---|---|---|
| `agents` | `idx_agents_agent_id` (`agent_id: 1`) | `idx_agents_last_seen` (`last_seen: -1`)<br>`idx_agents_status` (`status: 1`) | Endpoint discovery, heartbeat timeout monitoring |
| `alerts` | `idx_alerts_alert_id` (`alert_id: 1`) | `idx_alerts_endpoint_id`<br>`idx_alerts_severity`<br>`idx_alerts_status`<br>`idx_alerts_created_at` (`created_at: -1`)<br>`idx_alerts_endpoint_created` (`endpoint_id: 1, created_at: -1`) | Real-time threat alert tracking, triage filtering |
| `incidents` | `idx_incidents_incident_id` (`incident_id: 1`) | `idx_incidents_endpoint_id`<br>`idx_incidents_severity`<br>`idx_incidents_status`<br>`idx_incidents_created_at` (`created_at: -1`)<br>`idx_incidents_endpoint_created` (`endpoint_id: 1, created_at: -1`) | SOC incident lifecycle, alert correlation, state transitions |
| `detections` | `idx_detections_detection_id` (`detection_id: 1`) | `idx_detections_endpoint_id`<br>`idx_detections_timestamp` (`timestamp: -1`)<br>`idx_detections_prediction`<br>`idx_detections_endpoint_timestamp` (`endpoint_id: 1, timestamp: -1`) | Raw live Model V2 sliding window telemetry history |

---

## 6. Running Tests

### Run Complete Regression Suite (Phases 1, 2A–2D, 3A, 3B)
```bash
python -m pytest agent/tests ml/tests backend/tests -v
```

### Verification Results:
- `ml/tests/test_ml_pipeline.py`: **9/9 PASSED**
- `agent/tests/test_agent_foundation.py`: **16/16 PASSED**
- `agent/tests/test_live_collectors.py`: **25/25 PASSED**
- `agent/tests/test_phase2c.py`: **30/30 PASSED**
- `agent/tests/test_phase2d.py`: **40/40 PASSED**
- `backend/tests/`: **40/40 PASSED**
- **TOTAL:** **160/160 PASSED (100% Pass Rate in 12.28s)**
