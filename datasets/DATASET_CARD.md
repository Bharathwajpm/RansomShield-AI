# RansomShield AI — Dataset Card: CSU-Ransomware-Data (SCReeD Project)

## 1. Dataset Summary

- **Dataset Name:** CSU-Ransomware-Data
- **Originating Organization:** Cyber Security Cooperative Research Centre (CSCRC) / Charles Sturt University (CSU)
- **Repository URL:** [https://github.com/CSCRC-SCREED/CSU-Ransomware-Data](https://github.com/CSCRC-SCREED/CSU-Ransomware-Data)
- **Raw Event Base:** Derived from 413,556 raw Windows Sysmon (System Monitor) events collected in a controlled enterprise endpoint testbed.
- **Samples in Primary Matrix (`Ransomware_Data.csv`):** 352,876 event observations (36,485 unique behavioral feature vectors).
- **Features:** 19 engineered behavioral telemetry features + 1 ground truth label (`Ware Type`).
- **Data Type:** Real endpoint behavioral telemetry (Sysmon Event IDs 1, 2, 3, 11, 13, 17/18, 23/26, process tree, and file-system path entropy).
- **License:** Open Access for Academic & Cybersecurity Research.
- **Classification:** **VERIFIED EXTERNAL REAL TELEMETRY DATASET**

---

## 2. Provenance & Research Methodology

The dataset was generated in a dedicated Windows sandbox testbed comparing standard enterprise workstation activities (installing software, running Office applications, web browsing, background OS updates) with live execution traces of active ransomware families (including LockBit, Medusa, and related strains). 

Sysmon was configured to record system-wide process creations, file modifications, file renames, named pipe creations, registry updates, and outbound network socket connections. The raw event stream was parsed and aggregated into behavioral feature vectors representing process-level and endpoint-level telemetry.

---

## 3. Class Distribution & Schema

### Labels (`Ware Type`)
- `Goodware` / `good` (Class `0`): 271,993 samples (77.08%) in full event stream; 30,605 samples (83.88%) deduplicated.
- `Ransomware` / `ransom` (Class `1`): 80,883 samples (22.92%) in full event stream; 5,880 samples (16.12%) deduplicated.

### Features & Windows Telemetry Grounding

| # | Feature Name in Dataset | Data Type | Telemetry Source | Collection Mechanism | Classification |
|---|---|---|---|---|---|
| 1 | `File_Delete_archived` | `int64` | `Sysmon` Event 23/26 | File Delete / Archive operations | **DIRECT** |
| 2 | `File_created` | `int64` | `Sysmon` Event 11 | File creation in user & temporary directories | **DIRECT** |
| 3 | `File_creation_time_changed` | `int64` | `Sysmon` Event 2 | File creation timestomping / timestamp tampering | **DIRECT** |
| 4 | `Pipe_Created` | `int64` | `Sysmon` Event 17/18 | Named pipe creation for inter-process communication | **DIRECT** |
| 5 | `Process_Create` | `int64` | `Sysmon` Event 1 | Process creation / execution event | **DIRECT** |
| 6 | `Registry_value_set` | `int64` | `Sysmon` Event 13 | Registry write to persistence & startup keys | **DIRECT** |
| 7 | `process-related` | `int64` | `Sysmon` / `psutil` | Process-related aggregate event flag | **DERIVED** |
| 8 | `network-related` | `int64` | `Sysmon` Event 3 / `psutil` | Outbound network connection attempt | **DIRECT** |
| 9 | `file-related` | `int64` | `watchdog` / `Sysmon` | File-system modification/access event flag | **DERIVED** |
| 10| `suspicious_path` | `int64` | `psutil` / `Sysmon` Event 1 | Binary executed from AppData / Temp / Downloads | **DERIVED** |
| 11| `system_executable` | `int64` | `psutil` / `Sysmon` Event 1 | Binary executed from C:\Windows\System32 | **DERIVED** |
| 12| `path_length` | `int64` | `psutil` | Character length of process image path | **DERIVED** |
| 13| `directory_depth` | `int64` | `psutil` | Directory nesting depth count | **DERIVED** |
| 14| `process_name_length` | `int64` | `psutil` | Character length of process name | **DERIVED** |
| 15| `process_vs_parent_freq_ratio`| `float64` | `psutil` Process Tree | Process vs parent execution frequency ratio | **DERIVED** |
| 16| `executable_depth_diff` | `int64` | `psutil` Process Tree | Directory depth delta between parent & child | **DERIVED** |
| 17| `parent_is_system_executable` | `int64` | `psutil` Process Tree | Parent binary resides in Windows System directory | **DERIVED** |
| 18| `extension_similarity` | `int64` | `watchdog` | File extension match / transformation indicator | **DERIVED** |
| 19| `file_name_entropy` | `float64` | `watchdog` / path analysis | Shannon entropy of touched file name strings | **DERIVED** |

---

## 4. Dataset Quality & Leakage Audit

1. **Target Leakage (PASS):** Target column `Ware Type` is isolated. No target proxy or future information is present in the feature columns.
2. **Missing Values (PASS):** 0 missing values across all 352,876 rows.
3. **Class Separation (REALISTIC):** Unlike synthetic benchmark data, real Sysmon events exhibit natural feature overlap between legitimate software operations and ransomware stages (e.g. software installers and compilers also perform rapid file creation and process spawns).
4. **Train/Test Splitting:** Stratified 80/20 train/test holdout evaluated both on the full event stream and on deduplicated behavioral states.

---

## 5. Dataset Roles in RansomShield AI

- **`datasets/raw/csu_sysmon_ransomware_data.csv`:** Real external Sysmon telemetry dataset used for **Model V2** (`xgb_ransomware_v2.json`).
- **`datasets/raw/ransomware_behavioral_dataset.csv`:** Synthetic benchmark dataset retained for pipeline test suites, unit testing, and demonstration purposes.
