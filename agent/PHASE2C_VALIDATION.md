# RansomShield AI — Phase 2C Validation Report

**Phase:** Phase 2C (Sliding Window Feature Extractor & Live ML Inference Engine)  
**Status:** Completed & Verified  
**Operating Mode:** Read-Only Defensive Telemetry Collection & Live Model Scoring  

---

> [!IMPORTANT]
> **DETECTION ONLY — ZERO REMEDIATION IN PHASE 2C:**  
> Phase 2C strictly performs real-time feature extraction, Model V2 XGBoost inference, risk score calculation, and TreeSHAP attribution. It does NOT terminate processes, isolate network interfaces, modify firewall rules, or perform file quarantine. Automated containment is reserved for later phases.

---

## 1. Files Created
1. [`agent/features/__init__.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/features/__init__.py) — Exports `FeatureWindow` and `LiveFeatureExtractor`.
2. [`agent/features/feature_window.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/features/feature_window.py) — Encapsulates window metadata, event counts, feature dictionaries, and 19-element feature vector numpy arrays.
3. [`agent/features/feature_extractor.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/features/feature_extractor.py) — Real-time feature extractor mapping live telemetry in `InMemoryTelemetryBuffer` to the exact 19 Model V2 features across 5s, 10s, and 30s sliding windows.
4. [`agent/inference/__init__.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/inference/__init__.py) — Exports `DetectionResult` and `LiveInferenceEngine`.
5. [`agent/inference/detection_result.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/inference/detection_result.py) — Strongly typed dataclass schema for detection output, probabilities, confidence, risk score, stage, and TreeSHAP indicators.
6. [`agent/inference/live_inference.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/inference/live_inference.py) — Background worker executing Model V2 inference and TreeSHAP explanations on configured sliding windows with thread-safe history and callbacks.
7. [`agent/smoke_test.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/smoke_test.py) — Safe live Windows endpoint smoke test script.
8. [`agent/tests/test_phase2c.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/tests/test_phase2c.py) — 30 comprehensive unit & integration tests covering the complete Phase 2C feature extraction and inference pipeline.
9. [`agent/PHASE2C_VALIDATION.md`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/PHASE2C_VALIDATION.md) — Comprehensive technical validation document.

---

## 2. Files Modified
1. [`agent/config.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/config.py) — Added `inference_enabled`, `inference_interval_seconds`, and `model_version` configuration options.
2. [`agent/service/agent.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/service/agent.py) — Integrated `LiveInferenceEngine` into agent lifecycle (`start()`, `stop()`, `status()`, `evaluate_now()`).
3. [`agent/collectors/file_collector.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/collectors/file_collector.py) — Fixed truthiness check on empty buffer.
4. [`agent/collectors/process_collector.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/collectors/process_collector.py) — Fixed truthiness check on empty buffer.
5. [`agent/collectors/network_collector.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/collectors/network_collector.py) — Fixed truthiness check on empty buffer.
6. [`agent/collectors/sysmon_collector.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/collectors/sysmon_collector.py) — Fixed truthiness check on empty buffer.
7. [`agent/collectors/event_log_collector.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/collectors/event_log_collector.py) — Fixed truthiness check on empty buffer.
8. [`agent/README.md`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/README.md) — Updated with Phase 2C architecture and validation status.

---

## 3. 19-Feature Extraction Implementation

The `LiveFeatureExtractor` computes the exact 19 Model V2 features in strict sequence from events retrieved via `InMemoryTelemetryBuffer.get_events(window_seconds)`:

| # | Feature Name | Telemetry Sources | Extraction Calculation |
|---|---|---|---|
| 1 | `File_Delete_archived` | `FileEvent` / Sysmon | Count of `FileDeleteArchived` + backup file deletions (`.bak`, `.zip`, `.vss`) |
| 2 | `File_created` | `FileEvent` / Sysmon | Count of `FileCreate` events |
| 3 | `File_creation_time_changed`| `FileEvent` / Sysmon | Count of `FileTimeChanged` (timestomping) events |
| 4 | `Pipe_Created` | `PipeEvent` / Sysmon | Count of `PipeCreated` and `PipeConnected` events |
| 5 | `Process_Create` | `ProcessEvent` / Sysmon | Count of newly spawned process events |
| 6 | `Registry_value_set` | `RegistryEvent` / Sysmon | Count of `RegistryValueSet` persistence writes |
| 7 | `process-related` | `ProcessEvent` | Aggregate count of all process events in window |
| 8 | `network-related` | `NetworkEvent` | Outbound socket connection events in window |
| 9 | `file-related` | `FileEvent` | Aggregate count of all file creations, modifications, renames, deletions |
| 10| `suspicious_path` | `ProcessEvent` | 1 if any process executed from AppData/Temp/Downloads, else 0 |
| 11| `system_executable` | `ProcessEvent` | 1 if any process executed from System32/SysWOW64, else 0 |
| 12| `path_length` | `ProcessEvent` | Mean executable path character length |
| 13| `directory_depth` | `ProcessEvent` | Mean directory nesting depth (`path.count('\\')`) |
| 14| `process_name_length` | `ProcessEvent` | Mean process binary name length |
| 15| `process_vs_parent_freq_ratio`| `ProcessEvent` | Process vs parent execution frequency ratio |
| 16| `executable_depth_diff` | `ProcessEvent` | Parent-child directory nesting depth delta |
| 17| `parent_is_system_executable`| `ProcessEvent` | 1 if parent process is verified System32 binary, else 0 |
| 18| `extension_similarity` | `FileEvent` | 1 if file rename changed extension to non-standard suffix, else 0 |
| 19| `file_name_entropy` | `FileEvent` | Shannon entropy of touched file names |

---

## 4. Multi-Window Implementation
- **Supported Durations:** `5 seconds` (micro-burst detection), `10 seconds` (I/O & entropy rates), `30 seconds` (process tree & persistence).
- **Execution:** Coordinated multi-window evaluation (`evaluate_all_windows()`) runs at a configurable interval (default `2.0s`) on a dedicated background worker thread.
- **Empty Window Safety:** Evaluates to safe deterministic baselines (all count features = 0.0, entropy = 0.0), resulting in `Goodware` classification (risk score ~2/100, confidence ~98.8%), never falsely triggering ransomware alerts.

---

## 5. Model V2 & TreeSHAP Integration
- **Model Version:** Strictly uses `xgb_ransomware_v2` trained in Phase 1 on CSU-Ransomware-Data. Model V1 is excluded from live inference.
- **Risk Score Engine:** Reuses calibrated deterministic risk mapping:
  - `0–30`: LOW (Monitor)
  - `31–60`: MEDIUM (Warning)
  - `61–80`: HIGH (Admin Alert)
  - `81–100`: CRITICAL (Ransomware Containment Trigger)
- **Explainability:** Real-time TreeSHAP attributions calculate directional weights (`increases risk` / `decreases risk` / `neutral`) and top-5 contributing features for every detection.

---

## 6. DetectionResult Schema
```json
{
  "timestamp": 1756543800.12,
  "window_seconds": 10,
  "prediction": "Goodware",
  "confidence": 70.3,
  "risk_score": 48,
  "probabilities": {
    "Goodware": 0.7031,
    "Ransomware": 0.2969
  },
  "model_version": "xgb_ransomware_v2",
  "stage": 3,
  "features": { ... 19 features ... },
  "indicators": [
    {
      "label": "Abnormal parent-child frequency",
      "feature_name": "process_vs_parent_freq_ratio",
      "weight": 100,
      "shap_value": -1.0217,
      "direction": "decreases risk"
    }
  ],
  "explanation": "Observed endpoint telemetry stays within normal baseline limits...",
  "event_count": 791,
  "duration_ms": 378.97
}
```

---

## 7. Test Results Summary

### Combined Test Execution
```bash
pytest agent/tests ml/tests/test_ml_pipeline.py -v
```

### Result: **80/80 PASSED in 13.91s (100% Pass Rate)**
- **Phase 1 ML Tests (`ml/tests/test_ml_pipeline.py`):** 9/9 **PASSED**
- **Phase 2A Foundation Tests (`agent/tests/test_agent_foundation.py`):** 16/16 **PASSED**
- **Phase 2B Live Collector Tests (`agent/tests/test_live_collectors.py`):** 25/25 **PASSED**
- **Phase 2C Live Inference Tests (`agent/tests/test_phase2c.py`):** 30/30 **PASSED**

---

## 8. Windows Live Smoke Test Result
- **Script:** [`agent/smoke_test.py`](file:///c:/Users/Bharath/Downloads/ransomshield-complete-main/agent/smoke_test.py)
- **Status:** **PASS**
- **Execution:** Started agent with live collectors and inference engine, generated benign filesystem events (creation, modification, renaming), captured 1,017 live telemetry events, evaluated 5s/10s/30s sliding windows, ran Model V2 inference and TreeSHAP attribution, produced `Goodware` classification with 48/100 risk score and 70.3% confidence, and performed clean shutdown.

---

## 9. Integrity Verifications
- **Frontend State:** `src/` is completely untouched. Zero React components, TanStack routes, or UI files were modified.
- **Later Phases State:** FastAPI backend, MongoDB database, WebSockets, remote containment commands, and process termination are not implemented.

---

## 10. Phase 2C Readiness Verdict

**PHASE 2C IMPLEMENTATION VERIFIED — READY FOR PHASE 2D**
