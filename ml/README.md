# RansomShield AI — Machine Learning Subsystem

**Document Version:** 2.0.0  
**Phase:** Phase 1 (ML + Feature Pipeline)  
**Status:** Completed & Verified  

---

## 1. Subsystem Architecture

The ML subsystem provides offline training and low-latency real-time inference for ransomware detection using XGBoost and TreeSHAP explainability.

```
datasets/
├── raw/
│   ├── csu_sysmon_ransomware_data.csv    # Real verified Sysmon telemetry (CSU-Ransomware-Data)
│   └── ransomware_behavioral_dataset.csv # Synthetic benchmark dataset (Pipeline test / CI)
│
ml/
├── data/
│   └── loader.py              # Dataset loading, validation, and benchmark generator
├── features/
│   ├── feature_contract.py    # Master feature specifications for V2 (19 feats) & V1 (12 feats)
│   ├── entropy.py             # Shannon entropy engine (0.0 to 8.0)
│   ├── extractors.py          # Sliding window aggregator (5s, 10s, 30s)
│   └── preprocessor.py        # Zero-leakage transformer and serializer
├── training/
│   └── train_xgboost.py       # Stratified training pipeline for V2 & V1
├── inference/
│   ├── predictor.py           # Real-time inference engine & calibrated 0-100 risk scoring
│   └── explainer.py           # TreeSHAP feature attribution engine
├── evaluation/
│   └── evaluator.py           # Model benchmark evaluation and V1 vs V2 comparative reports
├── models/
│   ├── xgb_ransomware_v2.json # Model V2: Real Sysmon Telemetry XGBoost Classifier
│   ├── feature_meta_v2.json   # Model V2 metadata & feature contract
│   ├── preprocessor_v2.json   # Model V2 fitted preprocessor state
│   ├── xgb_ransomware_v1.json # Model V1: Synthetic Prototype Benchmark Classifier
│   ├── feature_meta.json      # Model V1 metadata
│   └── preprocessor.json      # Model V1 preprocessor
├── tests/
│   └── test_ml_pipeline.py    # Pytest test suite (9/9 passed)
├── DATASET_SELECTION.md       # Dataset evaluation, candidate comparison, and selection criteria
├── requirements.txt           # Minimal ML dependencies
└── README.md
```

---

## 2. Dataset Provenance & Comparison

### Model V2: Real CSU Sysmon Telemetry Dataset (Primary)
- **Dataset Name:** CSU-Ransomware-Data (SCReeD Project)
- **Originating Institution:** Cyber Security Cooperative Research Centre (CSCRC) / Charles Sturt University
- **Repository URL:** [https://github.com/CSCRC-SCREED/CSU-Ransomware-Data](https://github.com/CSCRC-SCREED/CSU-Ransomware-Data)
- **Observations:** 352,876 raw event records (36,485 unique behavioral states)
- **Features:** 19 engineered features derived from Windows Sysmon events (Event IDs 1, 2, 3, 11, 13, 17, 23/26) and process/path metadata.

### Model V1: Prototype Synthetic Benchmark (Legacy)
- **Source:** Deterministic statistical distribution generator
- **Observations:** 12,000 synthetic rows (12 features)
- **Role:** CI/CD pipeline tests and reference prototype.

---

## 3. V2 Feature Contract & Windows Telemetry Mapping

| # | Feature Name | Telemetry Source | Classification | Role in Ransomware Detection |
|---|---|---|---|---|
| 1 | `File_Delete_archived` | `Sysmon` Event 23/26 | **DIRECT** | Backup / shadow file deletion |
| 2 | `File_created` | `Sysmon` Event 11 | **DIRECT** | Encrypted payload drops & ransom notes |
| 3 | `File_creation_time_changed` | `Sysmon` Event 2 | **DIRECT** | Timestomping evasion |
| 4 | `Pipe_Created` | `Sysmon` Event 17/18 | **DIRECT** | Inter-process communication |
| 5 | `Process_Create` | `Sysmon` Event 1 | **DIRECT** | Process execution events |
| 6 | `Registry_value_set` | `Sysmon` Event 13 | **DIRECT** | Persistence & boot config tampering |
| 7 | `process-related` | `Sysmon` / `psutil` | **DERIVED** | Aggregate process creation activity |
| 8 | `network-related` | `Sysmon` Event 3 | **DIRECT** | Outbound C2 beaconing / exfiltration |
| 9 | `file-related` | `watchdog` / `Sysmon` | **DERIVED** | Mass file I/O operations |
| 10| `suspicious_path` | `psutil` / `Sysmon` 1 | **DERIVED** | Execution from AppData / Temp / Downloads |
| 11| `system_executable` | `psutil` / `Sysmon` 1 | **DERIVED** | Execution from `C:\Windows\System32` |
| 12| `path_length` | `psutil` | **DERIVED** | Anomaly metric for obfuscated paths |
| 13| `directory_depth` | `psutil` | **DERIVED** | Directory tree depth |
| 14| `process_name_length` | `psutil` | **DERIVED** | Obfuscated process names |
| 15| `process_vs_parent_freq_ratio`| `psutil` | **DERIVED** | Unusual parent-child relationships |
| 16| `executable_depth_diff` | `psutil` | **DERIVED** | Parent-child directory depth delta |
| 17| `parent_is_system_executable` | `psutil` | **DERIVED** | Parent binary system verification |
| 18| `extension_similarity` | `watchdog` | **DERIVED** | Extension change / `.locked` pattern |
| 19| `file_name_entropy` | `watchdog` | **DERIVED** | Shannon entropy of touched file names |

---

## 4. Evaluation Results (V1 vs V2)

```
==============================================================================
HISTORICAL EVALUATION COMPARISON
==============================================================================
Metric / Property              | Model V1 (Synthetic)   | Model V2 (Real Sysmon) 
------------------------------------------------------------------------------
Dataset Source                 | Repo Generator         | CSU-Ransomware-Data   
Provenance                     | Unverified (Synthetic) | Verified (CSCRC/CSU)  
Sample Count                   | 12,000                 | 36,485                
Features Count                 | 12 Features            | 19 Sysmon Features    
Accuracy                       | 99.96 %                | 95.96 %               
Ransomware Recall              | 99.72 %                | 93.88 %               
Ransomware Precision           | 100.00 %               | 83.20 %               
Ransomware F1-Score            | 99.91 %                | 88.21 %               
ROC-AUC                        | 100.00 %               | 99.25 %               
------------------------------------------------------------------------------
```

> **Disclaimer:** Labeled strictly as **HISTORICAL DATASET EVALUATION** for prototype and academic validation.

---

## 5. Execution & Reproduction Commands

### Train Models
```bash
python -m ml.training.train_xgboost
```

### Run Model Comparison
```bash
python -m ml.evaluation.evaluator
```

### Run Automated Tests
```bash
pytest ml/tests/test_ml_pipeline.py -v
```
