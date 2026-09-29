# RansomShield AI — Phase 1 Validation Report (Updated Post-Audit)

## 1. Overall Status

**READY FOR PHASE 2**

All audit findings have been systematically resolved:
1. Sourced and verified a real-world, externally hosted ransomware telemetry dataset from Charles Sturt University / Cyber Security Cooperative Research Centre (CSCRC-SCREED).
2. Defined and synchronized the Model V2 feature contract with 19 Sysmon and Windows endpoint telemetry features.
3. Created explicit provenance documentation in `datasets/DATASET_CARD.md` and candidate evaluation in `ml/DATASET_SELECTION.md`.
4. Retrained XGBoost Model V2 with zero data leakage, stratified holdout validation, and realistic class separation.
5. Saved Model V2 artifacts (`xgb_ransomware_v2.json`, `feature_meta_v2.json`, `preprocessor_v2.json`) alongside legacy V1 benchmark artifacts.
6. Verified real-time inference, calibrated 0–100 risk scoring, and TreeSHAP explainability.
7. All 9 unit and integration tests pass (100% pass rate).

---

## 2. Verified Dataset Provenance

- **Dataset Name:** CSU-Ransomware-Data (SCReeD Project)
- **Originating Institution:** Cyber Security Cooperative Research Centre (CSCRC) / Charles Sturt University
- **Repository URL:** [https://github.com/CSCRC-SCREED/CSU-Ransomware-Data](https://github.com/CSCRC-SCREED/CSU-Ransomware-Data)
- **Local Path:** `datasets/raw/csu_sysmon_ransomware_data.csv`
- **Total Observations:** 352,876 event rows (36,485 unique behavioral states)
- **Ground Truth Labels:** `Goodware` (0) and `Ransomware` (1)
- **Raw Event Base:** Derived from 413,556 raw Sysmon (System Monitor) events collected in a controlled enterprise sandbox testbed comparing regular operations with active ransomware execution (LockBit, Medusa, etc.).
- **Synthetic Benchmark Role:** `datasets/raw/ransomware_behavioral_dataset.csv` is retained and explicitly documented as `SYNTHETIC BENCHMARK / PIPELINE TEST DATA`.

---

## 3. Leakage Audit Resolution

| Audit Item | Status | Resolution / Verification |
|---|---|---|
| Target Leakage | **PASS** | Target column `Ware Type` / `label` is completely excluded from feature matrices. |
| Train/Test Overlap | **PASS** | Evaluated on deduplicated behavioral states with stratified 80/20 train/test split. |
| Preprocessing Leakage | **PASS** | `FeaturePreprocessor` is fit strictly on training data; holdout data is transformed using fitted statistics. |
| Feature Leakage | **PASS** | Features are raw/derived Sysmon event counts, path statistics, and entropy, reflecting realistic enterprise telemetry with natural class overlap. |
| Temporal Drift | **DOCUMENTED** | Features utilize rolling event windows. CSU dataset includes drift anomaly subsets for future temporal tracking. |

---

## 4. Model V2 Evaluation Summary

```
============================================================
HISTORICAL REAL TELEMETRY EVALUATION (MODEL V2)
============================================================
• Dataset:              CSU-Ransomware-Data (SCReeD)
• Test Set Size:        7,297 samples (Stratified 20% Holdout)
• Accuracy:             95.96%
• Ransomware Recall:    93.88%
• Ransomware Precision: 83.20%
• Ransomware F1-Score:  88.21%
• ROC-AUC:              99.25%
• 5-Fold CV F1-Score:   87.38% (+/- 1.01%)
• Confusion Matrix:     TN=5898, FP=223, FN=72, TP=1104
============================================================
```

---

## 5. Automated Test Suite

- **Command:** `pytest ml/tests/test_ml_pipeline.py -v`
- **Result:** **9 passed in 8.16s (100% pass rate)**
  - `test_feature_contract_definitions`: **PASSED**
  - `test_shannon_entropy`: **PASSED**
  - `test_sliding_window_aggregator`: **PASSED**
  - `test_real_csu_dataset_loading_and_validation`: **PASSED**
  - `test_preprocessor_zero_leakage_v2`: **PASSED**
  - `test_model_v2_training_and_artifacts`: **PASSED**
  - `test_model_v2_reload_and_inference`: **PASSED**
  - `test_model_v2_shap_explainability`: **PASSED**
  - `test_feature_ordering_integrity`: **PASSED**

---

## 6. Phase 2 Readiness

**READY FOR PHASE 2**
