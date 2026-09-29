# RansomShield AI — Phase 2B Validation Report

**Phase:** Phase 2B (Windows Endpoint Monitoring Agent — Live Collectors)  
**Status:** Completed & Verified  
**Operating Mode:** Read-Only Defensive Telemetry Collection  

---

> [!IMPORTANT]
> **DEFENSIVE MONITORING ONLY:**  
> Phase 2B implements live, non-destructive, read-only endpoint telemetry collection. The agent does NOT terminate processes, isolate networks, modify the registry, delete files, or contain endpoints.

---

## 1. Implementation Summary

Phase 2B implemented concrete, high-performance, real Windows endpoint telemetry collectors that feed strongly typed event records into the thread-safe `InMemoryTelemetryBuffer`.

The collectors capture real endpoint behavior across process lifecycle, filesystem modifications/renames, filename entropy, network connections, and Windows Event Log channels, directly supporting the 19-feature contract of **Model V2** (`xgb_ransomware_v2.json`).

---

## 2. Collector Status & Architecture

| Collector | Underlying Library | Operational Status | Event Model Produced | Description |
|---|---|---|---|---|
| **Process Collector** | `psutil` | **LIVE / ACTIVE** | `ProcessEvent` | Periodic process tree inspection, PID tracking/deduplication, parent-child hierarchy, suspicious path detection, System32 detection, executable path depth metrics. |
| **Filesystem Collector** | `watchdog` | **LIVE / ACTIVE** | `FileEvent` | Real-time filesystem observer on configured user directories, filename Shannon entropy calculation, extension modification/renaming tracking, archive deletion detection. |
| **Network Collector** | `psutil.net_connections` | **LIVE / ACTIVE** | `NetworkEvent` | Periodic socket enumeration, local/remote endpoints, protocol, connection status, PID association with graceful unprivileged fallback. |
| **Sysmon Collector** | `win32evtlog` | **OPTIONAL / GRACEFUL** | `SystemEvent` / `ProcessEvent` / `FileEvent` | Subscribes to `Microsoft-Windows-Sysmon/Operational` when Sysmon is installed. Reports unavailable cleanly without crashing when Sysmon is absent. |
| **Windows Event Log Collector** | `win32evtlog` | **LIVE / ACTIVE** | `SystemEvent` | Reads Application/System/Security event log channels with unprivileged fallback. |

---

## 3. Telemetry Flow

```
Windows Endpoint Telemetry
 ├── ProcessCollector   ───► ProcessEvent  ──┐
 ├── FileCollector      ───► FileEvent     ──┤
 ├── NetworkCollector   ───► NetworkEvent  ──┼──► InMemoryTelemetryBuffer (Thread-Safe)
 ├── SysmonCollector    ───► SystemEvent   ──┤        ├── 5-Second Window
 └── EventLogCollector  ───► SystemEvent   ──┘        ├── 10-Second Window
                                                      └── 30-Second Window
                                                               │
                                                               ▼
                                                  [Phase 2C] Feature Extractor
                                                               │
                                                               ▼
                                                  [Phase 1]  Model V2 Inference
```

---

## 4. Model V2 Feature Compatibility Mapping

The live collectors capture all the raw attributes required to compute the exact 19 Model V2 features:

| # | Model V2 Feature | Telemetry Source | Live Collector | Collection Mechanism |
|---|---|---|---|---|
| 1 | `File_Delete_archived` | `watchdog` / `Sysmon` | `FileCollector` | `FileDeleteArchived` event emitted on backup/archive deletions |
| 2 | `File_created` | `watchdog` / `Sysmon` | `FileCollector` | `FileCreate` event count in rolling window |
| 3 | `File_creation_time_changed` | `Sysmon` (Event 2) | `SysmonCollector` | Direct Sysmon Event 2 capture (or fallback heuristic) |
| 4 | `Pipe_Created` | `Sysmon` (Event 17/18) | `SysmonCollector` | Direct Named Pipe creation events |
| 5 | `Process_Create` | `psutil` / `Sysmon` | `ProcessCollector` | New PID discovery rate in rolling window |
| 6 | `Registry_value_set` | `Sysmon` (Event 13) | `SysmonCollector` | Registry modification events |
| 7 | `process-related` | `psutil` / `Sysmon` | `ProcessCollector` | Aggregate process lifecycle event count |
| 8 | `network-related` | `psutil` / `Sysmon` | `NetworkCollector` | Outbound socket connection count |
| 9 | `file-related` | `watchdog` | `FileCollector` | Aggregate file operations count in window |
| 10| `suspicious_path` | `psutil` | `ProcessCollector` | Binary flag for execution from AppData/Temp/Downloads |
| 11| `system_executable` | `psutil` | `ProcessCollector` | Binary flag for execution from C:\Windows\System32 |
| 12| `path_length` | `psutil` | `ProcessCollector` | Character length of process executable path |
| 13| `directory_depth` | `psutil` | `ProcessCollector` | Path directory separator count |
| 14| `process_name_length` | `psutil` | `ProcessCollector` | Process binary name length |
| 15| `process_vs_parent_freq_ratio`| `psutil` | `ProcessCollector` | Process vs parent execution frequency ratio |
| 16| `executable_depth_diff` | `psutil` | `ProcessCollector` | Parent-child directory nesting depth delta |
| 17| `parent_is_system_executable` | `psutil` | `ProcessCollector` | Parent process path in System32 verification |
| 18| `extension_similarity` | `watchdog` | `FileCollector` | Extension change metric on file rename events |
| 19| `file_name_entropy` | `watchdog` | `FileCollector` | Shannon entropy computed on modified file names |

---

## 5. Test Suite Verification

### Combined Test Execution
```bash
pytest agent/tests ml/tests/test_ml_pipeline.py -v
```

### Result: **50/50 PASSED (100% Pass Rate)**
- **Phase 2A Foundation Tests:** 16/16 PASSED
- **Phase 2B Live Collector Tests:** 25/25 PASSED
- **Phase 1 ML & Model V2 Tests:** 9/9 PASSED

---

## 6. Windows Requirements & Graceful Degradation

- **Supported OS:** Windows 10, Windows 11, Windows Server 2016+ (cross-platform degradation supported on macOS/Linux).
- **Core Dependencies:** `psutil`, `watchdog`, `pywin32`.
- **Privilege Level:** Runs as standard user. Unprivileged socket/event log errors (`AccessDenied`) are handled gracefully without terminating the agent.
- **Sysmon:** Optional. If Sysmon is absent, `SysmonCollector` marks itself unavailable without disrupting process, filesystem, or network telemetry.

---

## 7. Known Limitations

- Real-time kernel mini-filter drivers are not used (monitoring relies on user-space OS notifications and event subscriptions).
- Feature aggregation and live model scoring will be connected in **Phase 2C**.
