# RansomShield AI — Windows Endpoint Monitoring Agent

**Component:** Endpoint Monitoring Agent  
**Current Phase:** Phase 2D (Detection Decision, Alerting & Incident Pipeline)  
**Status:** Completed & Verified (120/120 Tests Passing)  
**Mode:** Non-Destructive, Read-Only Defensive Telemetry Collection, Real-Time ML Scoring & Incident Lifecycle  

---

> [!NOTE]
> **Phase 2D Implementation Summary:**  
> Phase 2D implements the end-to-end detection decision engine, alert lifecycle management, deduplication across overlapping sliding windows, and local incident correlation. Live `DetectionResult` objects from Phase 2C are evaluated against configurable risk thresholds, translated into human-readable TreeSHAP-derived reasons, deduplicated, and correlated into unified `Incident` records with validated state machine transitions.

---

## 1. Subsystem Architecture

```
                    WINDOWS ENDPOINT
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
     Process            File              Network
    Collector          Collector          Collector
  (psutil/Win32)      (watchdog)      (psutil.net_conns)
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                InMemoryTelemetryBuffer
                           │
                 5s / 10s / 30s Windows
                           ▼
                  LiveFeatureExtractor
              (Exact 19 Model V2 Features)
                           ▼
                  LiveInferenceEngine
               (XGBoost Model V2 + TreeSHAP)
                           ▼
                    DetectionResult
                           │ (Event Callback)
                           ▼
               DetectionDecisionEngine
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
           AlertManager       IncidentManager
                 │                   │
                 ▼                   ▼
          AlertDeduplicator   IncidentStateMachine
                 │                   │
                 └─────────┬─────────┘
                           ▼
                  LocalIncidentStore
               (Bounded In-Memory FIFO)
```

---

## 2. Directory Structure

```
agent/
├── __init__.py                # Package metadata and version info
├── config.py                  # Agent configuration dataclass and loaders
├── smoke_test.py              # Phase 2C live Windows smoke test
├── phase2d_smoke_test.py      # Phase 2D live Windows endpoint smoke test
├── models/
│   ├── __init__.py
│   └── telemetry.py           # Strongly typed telemetry data contracts & event types
├── collectors/
│   ├── __init__.py            # Collector package exports
│   ├── base.py                # Collector interfaces (BaseCollector, Process/File/Sysmon/Net)
│   ├── process_collector.py   # Live psutil process hierarchy and path metrics collector
│   ├── file_collector.py      # Live watchdog filesystem observer & entropy calculator
│   ├── network_collector.py   # Live psutil socket and connection collector
│   ├── sysmon_collector.py    # Live Sysmon channel subscriber with graceful fallback
│   └── event_log_collector.py # Live Windows Event Log collector
├── buffers/
│   ├── __init__.py
│   └── memory_buffer.py       # Thread-safe rolling in-memory buffer (5s, 10s, 30s)
├── features/
│   ├── __init__.py
│   ├── feature_window.py      # FeatureWindow dataclass with 19-feature vector representation
│   └── feature_extractor.py   # LiveFeatureExtractor computing 19 features across sliding windows
├── inference/
│   ├── __init__.py
│   ├── detection_result.py    # DetectionResult schema (prediction, confidence, risk, SHAP)
│   └── live_inference.py      # LiveInferenceEngine coordinating Model V2 scoring & TreeSHAP
├── detection/
│   ├── __init__.py            # Detection package exports
│   ├── severity.py            # AlertSeverity, IncidentSeverity, AlertStatus, IncidentStatus enums
│   ├── deduplication.py       # AlertDeduplicator with deterministic fingerprinting
│   ├── incident_store.py      # LocalIncidentStore thread-safe in-memory bounded storage
│   ├── alert_manager.py       # DetectionAlert dataclass and AlertManager service
│   ├── incident_manager.py    # Incident dataclass, IncidentStateMachine, IncidentManager
│   └── decision_engine.py     # DetectionDecisionEngine evaluating thresholds and reasons
├── service/
│   ├── __init__.py
│   └── agent.py               # Core Agent service lifecycle, logger, and subsystem coordination
├── tests/
│   ├── __init__.py
│   ├── test_agent_foundation.py # Phase 2A foundation tests (16 tests)
│   ├── test_live_collectors.py  # Phase 2B live collector tests (25 tests)
│   ├── test_phase2c.py          # Phase 2C feature extraction & live inference tests (30 tests)
│   └── test_phase2d.py          # Phase 2D detection decision, alerts & incidents (40 tests)
├── PHASE2B_VALIDATION.md      # Phase 2B validation document
├── PHASE2C_VALIDATION.md      # Phase 2C validation document
├── PHASE2D_VALIDATION.md      # Phase 2D validation document
└── README.md
```

---

## 3. Severity & Threshold Architecture

| Severity | Default Threshold | Action |
|---|---|---|
| **INFO** | Risk 0 – 29 | Normal activity, ignored from alert creation |
| **LOW** | Risk 30 – 49 | Minor deviation, stored as monitored alert |
| **MEDIUM** | Risk 50 – 69 | Suspicious behavior, correlated into incident |
| **HIGH** | Risk 70 – 84 (or Ransomware) | High-risk pattern, elevated incident |
| **CRITICAL** | Risk 85 – 100 (or Ransomware & Risk>=80) | Active high-confidence ransomware pattern |

---

## 4. Running the Tests & Live Smoke Test

### Run Complete Project Test Suite (Phases 1, 2A, 2B, 2C, 2D)
```bash
python -m pytest agent/tests ml/tests/test_ml_pipeline.py -v
```

### Run Live Windows Phase 2D Smoke Test (Safe & Non-Destructive)
```bash
python agent/phase2d_smoke_test.py
```

### Verification Results:
- `agent/tests/test_agent_foundation.py`: **16/16 PASSED**
- `agent/tests/test_live_collectors.py`: **25/25 PASSED**
- `agent/tests/test_phase2c.py`: **30/30 PASSED**
- `agent/tests/test_phase2d.py`: **40/40 PASSED**
- `ml/tests/test_ml_pipeline.py`: **9/9 PASSED**
- **Total:** **120/120 PASSED (100% Pass Rate)**
