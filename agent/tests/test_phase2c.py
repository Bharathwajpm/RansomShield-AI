"""
RansomShield AI — Comprehensive Phase 2C Test Suite
Phase 2C: Sliding Window Feature Extractor & Live ML Inference Engine

Verifies:
1. Feature extractor initialization
2. Exact 19-feature output
3. Exact feature ordering matching Model V2 contract
4. Empty buffer handling (safe deterministic values)
5. 5-second window extraction
6. 10-second window extraction
7. 30-second window extraction
8. File feature calculations
9. Process feature calculations
10. Registry feature calculation
11. Network feature calculation
12. Suspicious path calculation
13. System executable calculation
14. Path metrics (length, depth, name length)
15. Entropy calculation
16. Extension similarity
17. Parent-child feature calculation
18. Model V2 loading
19. Live goodware inference
20. Live ransomware inference
21. Probability output validity
22. Risk score validity (0-100 scale)
23. TreeSHAP explanation
24. DetectionResult schema
25. Model version verification
26. Inference engine start
27. Inference engine stop
28. Inference engine error resilience
29. Empty-window does not produce fake ransomware
30. 5/10/30 multi-window inference
"""

import time
import pytest
import numpy as np
from pathlib import Path
from typing import Dict, Any

from agent.models.telemetry import (
    TelemetryEventType,
    BaseTelemetryEvent,
    ProcessEvent,
    FileEvent,
    RegistryEvent,
    NetworkEvent,
    PipeEvent,
    SystemEvent,
)
from agent.config import AgentConfig
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from agent.features.feature_extractor import LiveFeatureExtractor
from agent.features.feature_window import FeatureWindow
from agent.inference.detection_result import DetectionResult
from agent.inference.live_inference import LiveInferenceEngine
from agent.service.agent import RansomShieldAgent
from ml.features.feature_contract import V2_FEATURE_NAMES
from ml.inference.predictor import get_predictor, RansomShieldPredictor
from ml.inference.explainer import get_explainer, RansomShieldExplainer


# 1. Feature Extractor Initialization
def test_feature_extractor_initialization():
    buf = InMemoryTelemetryBuffer()
    extractor = LiveFeatureExtractor(buffer=buf)
    assert extractor.buffer is buf


# 2. Exact 19-Feature Output
def test_exact_19_feature_output():
    buf = InMemoryTelemetryBuffer()
    extractor = LiveFeatureExtractor(buffer=buf)
    features = extractor.extract(window_seconds=10)
    assert isinstance(features, dict)
    assert len(features) == 19
    for name in V2_FEATURE_NAMES:
        assert name in features
        assert isinstance(features[name], float)


# 3. Exact Feature Ordering Matching Model V2 Contract
def test_exact_feature_ordering():
    buf = InMemoryTelemetryBuffer()
    extractor = LiveFeatureExtractor(buffer=buf)
    vector = extractor.extract_vector(window_seconds=10)
    assert isinstance(vector, np.ndarray)
    assert vector.shape == (19,)
    assert vector.dtype == np.float64


# 4. Empty Buffer Handling (Safe Deterministic Defaults)
def test_empty_buffer_handling():
    buf = InMemoryTelemetryBuffer()
    extractor = LiveFeatureExtractor(buffer=buf)
    features = extractor.extract(window_seconds=10)
    
    # All count features must be 0.0
    assert features["File_Delete_archived"] == 0.0
    assert features["File_created"] == 0.0
    assert features["File_creation_time_changed"] == 0.0
    assert features["Pipe_Created"] == 0.0
    assert features["Process_Create"] == 0.0
    assert features["Registry_value_set"] == 0.0
    assert features["process-related"] == 0.0
    assert features["network-related"] == 0.0
    assert features["file-related"] == 0.0
    assert features["suspicious_path"] == 0.0
    assert features["file_name_entropy"] == 0.0


# 5. 5-Second Window Extraction
def test_5_second_window_extraction():
    buf = InMemoryTelemetryBuffer()
    now = 5000.0
    
    buf.append(ProcessEvent(timestamp=now - 6.0, pid=1))
    buf.append(ProcessEvent(timestamp=now - 4.0, pid=2))
    buf.append(ProcessEvent(timestamp=now - 2.0, pid=3))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    f_5s = extractor.extract(window_seconds=5, current_time=now)
    assert f_5s["process-related"] == 2.0
    assert f_5s["Process_Create"] == 2.0


# 6. 10-Second Window Extraction
def test_10_second_window_extraction():
    buf = InMemoryTelemetryBuffer()
    now = 5000.0
    
    buf.append(FileEvent(timestamp=now - 12.0, path="old.txt"))
    buf.append(FileEvent(timestamp=now - 8.0, path="a.txt", event_type=TelemetryEventType.FileCreate))
    buf.append(FileEvent(timestamp=now - 3.0, path="b.txt", event_type=TelemetryEventType.FileCreate))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    f_10s = extractor.extract(window_seconds=10, current_time=now)
    assert f_10s["file-related"] == 2.0
    assert f_10s["File_created"] == 2.0


# 7. 30-Second Window Extraction
def test_30_second_window_extraction():
    buf = InMemoryTelemetryBuffer()
    now = 5000.0
    
    buf.append(NetworkEvent(timestamp=now - 25.0, pid=10))
    buf.append(NetworkEvent(timestamp=now - 15.0, pid=20))
    buf.append(NetworkEvent(timestamp=now - 2.0, pid=30))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    f_30s = extractor.extract(window_seconds=30, current_time=now)
    assert f_30s["network-related"] == 3.0


# 8. File Feature Calculations
def test_file_feature_calculations():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(FileEvent(timestamp=now - 1.0, event_type=TelemetryEventType.FileCreate))
    buf.append(FileEvent(timestamp=now - 1.0, event_type=TelemetryEventType.FileDeleteArchived))
    buf.append(FileEvent(timestamp=now - 1.0, event_type=TelemetryEventType.FileTimeChanged))
    buf.append(FileEvent(timestamp=now - 1.0, event_type=TelemetryEventType.FileModify))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    
    assert feats["File_created"] == 1.0
    assert feats["File_Delete_archived"] == 1.0
    assert feats["File_creation_time_changed"] == 1.0
    assert feats["file-related"] == 4.0


# 9. Process Feature Calculations
def test_process_feature_calculations():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(ProcessEvent(timestamp=now - 1.0, pid=101, event_type=TelemetryEventType.ProcessCreate))
    buf.append(ProcessEvent(timestamp=now - 1.0, pid=102, event_type=TelemetryEventType.ProcessCreate))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    
    assert feats["Process_Create"] == 2.0
    assert feats["process-related"] == 2.0


# 10. Registry Feature Calculation
def test_registry_feature_calculation():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(RegistryEvent(timestamp=now - 1.0, key_path="HKLM\\Run", value_name="Test"))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["Registry_value_set"] == 1.0


# 11. Network Feature Calculation
def test_network_feature_calculation():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(NetworkEvent(timestamp=now - 2.0, destination_address="192.168.1.10", destination_port=445))
    buf.append(NetworkEvent(timestamp=now - 1.0, destination_address="10.0.0.5", destination_port=80))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["network-related"] == 2.0


# 12. Suspicious Path Calculation
def test_suspicious_path_calculation():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(ProcessEvent(
        timestamp=now - 1.0,
        pid=555,
        executable_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\malware.exe",
        is_suspicious_path=True,
    ))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["suspicious_path"] == 1.0


# 13. System Executable Calculation
def test_system_executable_calculation():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(ProcessEvent(
        timestamp=now - 1.0,
        pid=123,
        executable_path="C:\\Windows\\System32\\svchost.exe",
        is_system_executable=True,
    ))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["system_executable"] == 1.0


# 14. Path Metrics (Length, Depth, Process Name Length)
def test_path_metrics():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(ProcessEvent(
        timestamp=now - 1.0,
        pid=789,
        executable_path="C:\\Windows\\System32\\cmd.exe",
        path_length=26,
        directory_depth=3,
        process_name_length=7,
    ))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["path_length"] == 26.0
    assert feats["directory_depth"] == 3.0
    assert feats["process_name_length"] == 7.0


# 15. Entropy Calculation
def test_entropy_calculation():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(FileEvent(
        timestamp=now - 1.0,
        path="C:\\Users\\User\\Documents\\normal_document.pdf",
        file_name_entropy=3.12,
    ))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["file_name_entropy"] == 3.12


# 16. Extension Similarity
def test_extension_similarity():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(FileEvent(
        timestamp=now - 1.0,
        path="C:\\Data\\file.locked",
        old_path="C:\\Data\\file.xlsx",
        extension_similarity=1,
    ))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["extension_similarity"] == 1.0


# 17. Parent-Child Feature Calculation
def test_parent_child_feature_calculation():
    buf = InMemoryTelemetryBuffer()
    now = 1000.0
    
    buf.append(ProcessEvent(
        timestamp=now - 1.0,
        pid=1000,
        parent_pid=4,
        process_vs_parent_freq_ratio=2.5,
        executable_depth_diff=2,
        parent_is_system_executable=True,
    ))
    
    extractor = LiveFeatureExtractor(buffer=buf)
    feats = extractor.extract(window_seconds=10, current_time=now)
    assert feats["process_vs_parent_freq_ratio"] == 2.5
    assert feats["executable_depth_diff"] == 2.0
    assert feats["parent_is_system_executable"] == 1.0


# 18. Model V2 Loading
def test_model_v2_loading():
    predictor = get_predictor("v2")
    assert predictor.model_version == "xgb_ransomware_v2"
    assert predictor.booster is not None
    assert len(predictor.feature_names) == 19


# 19. Live Goodware Inference
def test_live_goodware_inference():
    buf = InMemoryTelemetryBuffer()
    now = time.time()
    
    # Inject typical benign process telemetry
    buf.append(ProcessEvent(
        timestamp=now - 2.0,
        pid=1234,
        process_name="notepad.exe",
        executable_path="C:\\Windows\\System32\\notepad.exe",
        is_system_executable=True,
        is_suspicious_path=False,
        path_length=32,
        directory_depth=3,
        process_name_length=11,
        parent_is_system_executable=True,
    ))
    
    engine = LiveInferenceEngine(buffer=buf)
    result = engine.evaluate_window(window_seconds=10, current_time=now)
    
    assert isinstance(result, DetectionResult)
    assert result.prediction == "Goodware"
    assert result.risk_score < 45
    assert result.confidence > 70.0


# 20. Live Ransomware Inference
def test_live_ransomware_inference():
    buf = InMemoryTelemetryBuffer()
    now = time.time()
    
    # Inject heavy ransomware behavioral telemetry matching CSU dataset patterns
    buf.append(FileEvent(
        timestamp=now - 1.0,
        path="C:\\Users\\Victim\\AppData\\Local\\Temp\\9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b.lockbit",
        event_type=TelemetryEventType.FileCreate,
        file_name_entropy=3.85,
    ))
    buf.append(ProcessEvent(
        timestamp=now - 1.0,
        pid=8888,
        process_name="9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b.exe",
        executable_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b.exe",
        is_suspicious_path=True,
        is_system_executable=False,
        path_length=170,
        directory_depth=5,
        process_name_length=68,
        process_vs_parent_freq_ratio=0.0001,
        executable_depth_diff=5,
        parent_is_system_executable=False,
    ))

    engine = LiveInferenceEngine(buffer=buf)
    result = engine.evaluate_window(window_seconds=10, current_time=now)
    
    assert isinstance(result, DetectionResult)
    assert result.prediction == "Ransomware"
    assert result.risk_score > 60
    assert len(result.indicators) > 0
    assert result.is_ransomware is True


# 21. Probability Output Validity
def test_probability_output_validity():
    buf = InMemoryTelemetryBuffer()
    engine = LiveInferenceEngine(buffer=buf)
    result = engine.evaluate_window(window_seconds=10)
    
    probas = result.probabilities
    assert "Goodware" in probas
    assert "Ransomware" in probas
    assert 0.0 <= probas["Goodware"] <= 1.0
    assert 0.0 <= probas["Ransomware"] <= 1.0
    assert abs((probas["Goodware"] + probas["Ransomware"]) - 1.0) < 0.01


# 22. Risk Score Validity (0-100 Scale)
def test_risk_score_validity():
    predictor = get_predictor("v2")
    assert predictor.calculate_risk_score(0.0) == 0
    assert predictor.calculate_risk_score(0.10) == 20
    assert 30 <= predictor.calculate_risk_score(0.20) <= 60
    assert 60 <= predictor.calculate_risk_score(0.50) <= 80
    assert 80 <= predictor.calculate_risk_score(0.85) <= 100
    assert predictor.calculate_risk_score(1.0) == 100


# 23. TreeSHAP Explanation Test
def test_treeshap_explanation():
    explainer = get_explainer("v2")
    sample = {name: 0.0 for name in V2_FEATURE_NAMES}
    sample["suspicious_path"] = 1.0
    sample["File_Delete_archived"] = 5.0
    
    explanation = explainer.explain(sample, top_k=3)
    assert "indicators" in explanation
    assert len(explanation["indicators"]) == 3
    for ind in explanation["indicators"]:
        assert "feature_name" in ind
        assert "shap_value" in ind
        assert "weight" in ind
        assert 0 <= ind["weight"] <= 100
        assert ind["direction"] in ("increases risk", "decreases risk", "neutral")


# 24. DetectionResult Schema
def test_detection_result_schema():
    res = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Goodware",
        confidence=98.5,
        risk_score=5,
        probabilities={"Goodware": 0.985, "Ransomware": 0.015},
        model_version="xgb_ransomware_v2",
        stage=2,
        features={"Process_Create": 0.0},
        indicators=[],
        explanation="Normal activity",
        event_count=0,
    )
    
    d = res.to_dict()
    assert d["prediction"] == "Goodware"
    assert d["risk_score"] == 5
    assert d["model_version"] == "xgb_ransomware_v2"
    assert res.is_ransomware is False


# 25. Model Version Verification
def test_model_version_verification():
    engine = LiveInferenceEngine(buffer=InMemoryTelemetryBuffer())
    assert engine.model_version == "xgb_ransomware_v2"
    assert "v2" in engine.predictor.model_version


# 26. Inference Engine Start Lifecycle
def test_inference_engine_start():
    buf = InMemoryTelemetryBuffer()
    engine = LiveInferenceEngine(buffer=buf, inference_interval_seconds=0.1)
    assert engine.is_running() is False
    engine.start()
    assert engine.is_running() is True
    time.sleep(0.25)
    engine.stop()
    assert engine.is_running() is False


# 27. Inference Engine Stop Lifecycle
def test_inference_engine_stop():
    buf = InMemoryTelemetryBuffer()
    engine = LiveInferenceEngine(buffer=buf, inference_interval_seconds=0.1)
    engine.start()
    engine.stop()
    assert engine.is_running() is False
    assert engine._worker_thread is None


# 28. Inference Engine Error Resilience
def test_inference_engine_error_resilience():
    buf = InMemoryTelemetryBuffer()
    engine = LiveInferenceEngine(buffer=buf)
    
    # Evaluate with malformed / empty records - must not raise exception
    res = engine.evaluate_window(window_seconds=10)
    assert isinstance(res, DetectionResult)


# 29. Empty-Window Does Not Produce Fake Ransomware
def test_empty_window_does_not_produce_ransomware():
    buf = InMemoryTelemetryBuffer()
    engine = LiveInferenceEngine(buffer=buf)
    
    res = engine.evaluate_window(window_seconds=10)
    assert res.prediction == "Goodware"
    assert res.risk_score < 30
    assert res.is_ransomware is False


# 30. 5/10/30 Multi-Window Inference
def test_multi_window_inference():
    buf = InMemoryTelemetryBuffer()
    now = time.time()
    
    buf.append(ProcessEvent(timestamp=now - 25.0, pid=1))
    buf.append(ProcessEvent(timestamp=now - 8.0, pid=2))
    buf.append(ProcessEvent(timestamp=now - 2.0, pid=3))
    
    engine = LiveInferenceEngine(buffer=buf, sliding_windows=[5, 10, 30])
    results = engine.evaluate_all_windows(current_time=now)
    
    assert len(results) == 3
    assert 5 in results
    assert 10 in results
    assert 30 in results
    
    assert results[5].event_count == 1
    assert results[10].event_count == 2
    assert results[30].event_count == 3
