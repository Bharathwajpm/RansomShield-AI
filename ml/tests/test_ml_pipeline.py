"""
RansomShield AI — Comprehensive ML Pipeline Test Suite (V2 Real & V1 Benchmark)
Phase 1: Machine Learning & Feature Pipeline

Tests:
- Feature contract specifications for V2 (19 features) and V1 (12 features)
- Shannon entropy calculator
- Sliding window aggregator
- Real CSU Sysmon dataset loading and validation
- Preprocessor fit/transform with zero data leakage
- Model V2 & V1 training, evaluation, and artifact serialization
- Model V2 reload, inference consistency, and calibrated risk scoring
- Native TreeSHAP feature attribution & explainability
- Strict feature ordering integrity
"""

import os
import json
import tempfile
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from ml.features.feature_contract import (
    V2_FEATURE_NAMES,
    V1_FEATURE_NAMES,
    V2_FEATURE_DEFINITIONS,
    V2_LABEL_MAPPING,
    V1_LABEL_MAPPING,
    get_v2_feature_contract_dict,
    get_v1_feature_contract_dict,
)
from ml.features.entropy import calculate_shannon_entropy, is_high_entropy
from ml.features.extractors import SlidingWindowAggregator, TelemetryEvent
from ml.features.preprocessor import FeaturePreprocessor
from ml.data.loader import (
    load_real_csu_dataset,
    validate_csu_dataset,
    generate_benchmark_dataset,
    load_dataset,
)
from ml.training.train_xgboost import train_v2_real_model, train_v1_benchmark_model
from ml.inference.predictor import RansomShieldPredictor, get_predictor
from ml.inference.explainer import RansomShieldExplainer


# 1. Feature Contract Tests
def test_feature_contract_definitions():
    assert len(V2_FEATURE_NAMES) == 19
    assert len(V2_FEATURE_DEFINITIONS) == 19
    
    contract_v2 = get_v2_feature_contract_dict()
    assert contract_v2["feature_count"] == 19
    assert "File_Delete_archived" in V2_FEATURE_NAMES
    assert "Registry_value_set" in V2_FEATURE_NAMES
    assert "file_name_entropy" in V2_FEATURE_NAMES
    assert "suspicious_path" in V2_FEATURE_NAMES
    
    for feat in V2_FEATURE_DEFINITIONS:
        assert feat.name in V2_FEATURE_NAMES
        assert feat.classification.value in ["DIRECT", "DERIVED", "APPROXIMATION"]


# 2. Entropy Calculator Tests
def test_shannon_entropy():
    assert calculate_shannon_entropy(b"\x00" * 1024) == 0.0
    assert calculate_shannon_entropy("") == 0.0
    
    plain_text = "The quick brown fox jumps over the lazy dog. Normal document text."
    ent_plain = calculate_shannon_entropy(plain_text)
    assert 3.0 < ent_plain < 5.2
    assert not is_high_entropy(plain_text)
    
    random_bytes = os.urandom(4096)
    ent_rand = calculate_shannon_entropy(random_bytes)
    assert ent_rand > 7.5
    assert is_high_entropy(random_bytes, threshold=7.2)


# 3. Sliding Window Aggregator Tests
def test_sliding_window_aggregator():
    agg = SlidingWindowAggregator(max_window_seconds=30)
    base_time = 1000.0
    
    agg.update_psutil_snapshot(cpu_usage_pct=45.0, memory_usage_pct=22.0, unsigned_proc_ratio=0.5)
    
    for i in range(5):
        agg.add_event(TelemetryEvent(base_time - i * 1.5, "watchdog", "FileModified", {"entropy": 7.8}))
        
    agg.add_event(TelemetryEvent(base_time - 15.0, "Sysmon", "ProcessCreate"))
    agg.add_event(TelemetryEvent(base_time - 5.0, "Sysmon", "ProcessCreate"))
    
    feats = agg.extract_features(current_time=base_time)
    assert len(feats) == 12
    assert feats["file_modification_rate"] == 30.0
    assert feats["write_entropy_avg"] == 7.8


# 4. Real CSU Sysmon Dataset Loader & Validation Tests
def test_real_csu_dataset_loading_and_validation():
    df, report = load_real_csu_dataset(deduplicate=True)
    assert report["status"] == "VALID"
    assert len(df) > 30000
    assert "label" in df.columns
    assert len(report["missing_features"]) == 0
    assert report["provenance"] == "Cyber Security Cooperative Research Centre (CSCRC) / Charles Sturt University"


# 5. Preprocessor Zero-Leakage Tests
def test_preprocessor_zero_leakage_v2():
    df, _ = load_real_csu_dataset(deduplicate=True)
    X = df[V2_FEATURE_NAMES]
    
    pre = FeaturePreprocessor(feature_names=V2_FEATURE_NAMES, version="v2")
    pre.fit(X[:1000])
    
    X_trans = pre.transform(X[1000:1500])
    assert X_trans.shape == (500, 19)
    assert not np.isnan(X_trans).any()
    
    d = pre.to_dict()
    pre_loaded = FeaturePreprocessor.from_dict(d)
    assert pre_loaded.is_fitted
    assert pre_loaded.feature_names == V2_FEATURE_NAMES


# 6. Model V2 Training & Artifacts Test
def test_model_v2_training_and_artifacts():
    clf, metrics, metadata = train_v2_real_model(export_artifacts=True)
    
    assert metrics["evaluation_type"] == "HISTORICAL REAL TELEMETRY EVALUATION"
    assert metrics["accuracy"] >= 90.0
    assert metrics["recall"] >= 90.0
    assert metrics["roc_auc"] >= 95.0
    
    models_dir = Path(__file__).resolve().parent.parent / "models"
    assert (models_dir / "xgb_ransomware_v2.json").exists()
    assert (models_dir / "feature_meta_v2.json").exists()
    assert (models_dir / "preprocessor_v2.json").exists()


# 7. Model V2 Reload & Inference Tests
def test_model_v2_reload_and_inference():
    predictor = RansomShieldPredictor(model_version="xgb_ransomware_v2")
    
    # Goodware sample (system binary in Windows System32)
    benign_sample = {
        "File_Delete_archived": 0,
        "File_created": 0,
        "File_creation_time_changed": 0,
        "Pipe_Created": 0,
        "Process_Create": 0,
        "Registry_value_set": 0,
        "process-related": 0,
        "network-related": 0,
        "file-related": 0,
        "suspicious_path": 0,
        "system_executable": 1,
        "path_length": 32,
        "directory_depth": 3,
        "process_name_length": 11,
        "process_vs_parent_freq_ratio": 1.0,
        "executable_depth_diff": 0,
        "parent_is_system_executable": 1,
        "extension_similarity": 0,
        "file_name_entropy": 0.0,
    }
    
    res_benign = predictor.predict(benign_sample)
    assert res_benign["prediction"] == "Goodware"
    assert res_benign["risk_score"] <= 35
    assert res_benign["model_version"] == "xgb_ransomware_v2"
    
    # Ransomware sample (obfuscated binary executing from user path with registry modification and file operations)
    ransomware_sample = {
        "File_Delete_archived": 0,
        "File_created": 0,
        "File_creation_time_changed": 0,
        "Pipe_Created": 0,
        "Process_Create": 0,
        "Registry_value_set": 1,
        "process-related": 0,
        "network-related": 0,
        "file-related": 1,
        "suspicious_path": 1,
        "system_executable": 0,
        "path_length": 170,
        "directory_depth": 5,
        "process_name_length": 68,
        "process_vs_parent_freq_ratio": 0.0058,
        "executable_depth_diff": 5,
        "parent_is_system_executable": 0,
        "extension_similarity": 0,
        "file_name_entropy": 0.0,
    }
    
    res_attack = predictor.predict(ransomware_sample)
    assert res_attack["prediction"] == "Ransomware"
    assert res_attack["confidence"] >= 80.0
    assert res_attack["risk_score"] >= 80
    assert res_attack["stage"] in [5, 6]


# 8. TreeSHAP Attribution Test on Model V2
def test_model_v2_shap_explainability():
    explainer = RansomShieldExplainer(version="v2")
    
    sample = {
        "File_Delete_archived": 0,
        "File_created": 0,
        "File_creation_time_changed": 0,
        "Pipe_Created": 0,
        "Process_Create": 0,
        "Registry_value_set": 1,
        "process-related": 0,
        "network-related": 0,
        "file-related": 1,
        "suspicious_path": 1,
        "system_executable": 0,
        "path_length": 170,
        "directory_depth": 5,
        "process_name_length": 68,
        "process_vs_parent_freq_ratio": 0.0058,
        "executable_depth_diff": 5,
        "parent_is_system_executable": 0,
        "extension_similarity": 0,
        "file_name_entropy": 0.0,
    }
    
    explanation = explainer.explain(sample, top_k=5)
    assert explanation["prediction"] == "Ransomware"
    assert len(explanation["indicators"]) == 5
    
    for ind in explanation["indicators"]:
        assert 0 <= ind["weight"] <= 100
        assert ind["direction"] in ["increases risk", "decreases risk", "neutral"]
        assert "label" in ind
        assert "shap_value" in ind


# 9. Strict Feature Ordering Integrity
def test_feature_ordering_integrity():
    p_v2 = get_predictor("v2")
    assert p_v2.feature_names == V2_FEATURE_NAMES
    assert len(p_v2.feature_names) == 19
    
    p_v1 = get_predictor("v1")
    assert p_v1.feature_names == V1_FEATURE_NAMES
    assert len(p_v1.feature_names) == 12
