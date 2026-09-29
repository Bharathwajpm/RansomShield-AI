"""
RansomShield AI — Comprehensive Phase 2D Test Suite
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Verifies:
1. Benign result classification (INFO, ignored from alert creation)
2. Low risk classification (LOW severity)
3. Medium risk classification (MEDIUM severity)
4. High risk classification (HIGH severity)
5. Critical risk classification (CRITICAL severity)
6. Threshold boundary behavior
7. Configuration-driven thresholds
8. Alert creation
9. Alert ID uniqueness
10. SHAP indicators preserved
11. Reason generation
12. Alert acknowledgement
13. Alert resolution
14. Alert suppression
15. Duplicate detection suppression
16. Duplicate outside interval creates new alert
17. Different endpoints are not deduplicated
18. Different processes/PIDs can be distinguished
19. Thread-safe deduplication
20. Incident creation
21. Related alerts correlate
22. Unrelated alerts remain separate
23. Incident severity escalation
24. Incident update
25. Incident acknowledgement
26. Incident resolution
27. False positive transition
28. Invalid transition rejection
29. Alert storage/retrieval
30. Incident storage/retrieval
31. Bounded store behavior
32. Concurrent access to store
33. DetectionResult -> DecisionEngine integration
34. DecisionEngine -> AlertManager integration
35. AlertManager -> IncidentManager integration
36. Full detection-to-incident pipeline
37. Inference worker survives alert-processing exception
38. Agent start/stop with Phase 2D enabled
39. Phase 2D disabled through configuration
40. Reopening incident with explicit flag
"""

import time
import pytest
import threading
from typing import Dict, Any, List

from agent.inference.detection_result import DetectionResult
from agent.detection.severity import (
    AlertSeverity,
    IncidentSeverity,
    AlertStatus,
    IncidentStatus,
)
from agent.detection.deduplication import AlertDeduplicator
from agent.detection.incident_store import LocalIncidentStore
from agent.detection.alert_manager import DetectionAlert, AlertManager
from agent.detection.incident_manager import (
    Incident,
    IncidentStateMachine,
    InvalidStateTransitionError,
    IncidentManager,
)
from agent.detection.decision_engine import DetectionDecisionEngine
from agent.service.agent import RansomShieldAgent
from agent.config import AgentConfig
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer


# --- 1-7: DETECTION DECISION & SEVERITY TESTS ---

def test_benign_result_classification():
    engine = DetectionDecisionEngine()
    sev = engine.classify_severity(risk_score=5, is_ransomware=False)
    assert sev == AlertSeverity.INFO

    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Goodware",
        confidence=98.0,
        risk_score=5,
        probabilities={"Goodware": 0.98, "Ransomware": 0.02},
    )
    result = engine.process_detection(det)
    assert result is None  # Benign below min_alert_risk_score is ignored


def test_low_risk_classification():
    engine = DetectionDecisionEngine()
    sev = engine.classify_severity(risk_score=35, is_ransomware=False)
    assert sev == AlertSeverity.LOW


def test_medium_risk_classification():
    engine = DetectionDecisionEngine()
    sev = engine.classify_severity(risk_score=55, is_ransomware=False)
    assert sev == AlertSeverity.MEDIUM


def test_high_risk_classification():
    engine = DetectionDecisionEngine()
    sev1 = engine.classify_severity(risk_score=75, is_ransomware=False)
    assert sev1 == AlertSeverity.HIGH

    sev2 = engine.classify_severity(risk_score=50, is_ransomware=True)
    assert sev2 == AlertSeverity.HIGH  # Model predicted ransomware


def test_critical_risk_classification():
    engine = DetectionDecisionEngine()
    sev1 = engine.classify_severity(risk_score=90, is_ransomware=False)
    assert sev1 == AlertSeverity.CRITICAL

    sev2 = engine.classify_severity(risk_score=82, is_ransomware=True)
    assert sev2 == AlertSeverity.CRITICAL


def test_threshold_boundary_behavior():
    engine = DetectionDecisionEngine(
        low_risk_threshold=30,
        medium_risk_threshold=50,
        high_risk_threshold=70,
        critical_risk_threshold=85,
    )
    assert engine.classify_severity(29, False) == AlertSeverity.INFO
    assert engine.classify_severity(30, False) == AlertSeverity.LOW
    assert engine.classify_severity(49, False) == AlertSeverity.LOW
    assert engine.classify_severity(50, False) == AlertSeverity.MEDIUM
    assert engine.classify_severity(69, False) == AlertSeverity.MEDIUM
    assert engine.classify_severity(70, False) == AlertSeverity.HIGH
    assert engine.classify_severity(84, False) == AlertSeverity.HIGH
    assert engine.classify_severity(85, False) == AlertSeverity.CRITICAL


def test_configuration_driven_thresholds():
    engine = DetectionDecisionEngine(
        low_risk_threshold=20,
        medium_risk_threshold=40,
        high_risk_threshold=60,
        critical_risk_threshold=80,
    )
    assert engine.classify_severity(25, False) == AlertSeverity.LOW
    assert engine.classify_severity(45, False) == AlertSeverity.MEDIUM
    assert engine.classify_severity(65, False) == AlertSeverity.HIGH
    assert engine.classify_severity(85, False) == AlertSeverity.CRITICAL


# --- 8-14: ALERT MANAGEMENT TESTS ---

def test_alert_creation():
    mgr = AlertManager()
    alert, is_dup = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=92.5,
        risk_score=85,
        severity=AlertSeverity.CRITICAL,
        reason="Test alert reason",
    )
    assert isinstance(alert, DetectionAlert)
    assert alert.alert_id.startswith("alt-")
    assert alert.endpoint_id == "host-01"
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.status == AlertStatus.ACTIVE
    assert is_dup is False


def test_alert_id_uniqueness():
    mgr = AlertManager()
    ids = set()
    for _ in range(100):
        alert, _ = mgr.create_alert(
            endpoint_id=f"host-{_}",
            prediction="Ransomware",
            confidence=90.0,
            risk_score=80,
            severity=AlertSeverity.HIGH,
        )
        ids.add(alert.alert_id)
    assert len(ids) == 100


def test_shap_indicators_preserved_on_alert():
    mgr = AlertManager()
    inds = [
        {"label": "Obfuscated process name", "feature_name": "process_name_length", "weight": 95},
        {"label": "Suspicious path", "feature_name": "suspicious_path", "weight": 80},
    ]
    alert, _ = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=95.0,
        risk_score=90,
        severity=AlertSeverity.CRITICAL,
        indicators=inds,
    )
    assert len(alert.indicators) == 2
    assert alert.indicators[0]["feature_name"] == "process_name_length"


def test_reason_generation():
    engine = DetectionDecisionEngine()
    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=91.8,
        risk_score=95,
        probabilities={"Goodware": 0.082, "Ransomware": 0.918},
        indicators=[
            {"label": "Obfuscated process name length", "feature_name": "process_name_length", "direction": "increases risk", "weight": 100},
            {"label": "Abnormal path length", "feature_name": "path_length", "direction": "increases risk", "weight": 80},
        ],
    )
    reason = engine.generate_detection_reason(det, AlertSeverity.CRITICAL)
    assert "CRITICAL" in reason
    assert "Obfuscated process name length" in reason
    assert "Abnormal path length" in reason


def test_alert_acknowledgement():
    mgr = AlertManager()
    alert, _ = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
    )
    assert alert.status == AlertStatus.ACTIVE
    
    success = mgr.acknowledge_alert(alert.alert_id)
    assert success is True
    assert alert.status == AlertStatus.ACKNOWLEDGED


def test_alert_resolution():
    mgr = AlertManager()
    alert, _ = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
    )
    success = mgr.resolve_alert(alert.alert_id)
    assert success is True
    assert alert.status == AlertStatus.RESOLVED


def test_alert_suppression():
    mgr = AlertManager()
    alert, _ = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
    )
    success = mgr.suppress_alert(alert.alert_id)
    assert success is True
    assert alert.status == AlertStatus.SUPPRESSED


# --- 15-19: DEDUPLICATION TESTS ---

def test_duplicate_detection_suppression():
    mgr = AlertManager(deduplication_seconds=10.0)
    now = 1000.0

    alert1, is_dup1 = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
        indicators=[{"feature_name": "suspicious_path"}],
        current_time=now,
    )
    assert is_dup1 is False
    assert alert1.status == AlertStatus.ACTIVE

    # Second identical alert 2 seconds later (within 10s window)
    alert2, is_dup2 = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
        indicators=[{"feature_name": "suspicious_path"}],
        current_time=now + 2.0,
    )
    assert is_dup2 is True
    assert alert2.status == AlertStatus.SUPPRESSED
    assert alert2.suppression_count == 1


def test_duplicate_outside_interval_creates_new_alert():
    mgr = AlertManager(deduplication_seconds=10.0)
    now = 1000.0

    alert1, is_dup1 = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
        current_time=now,
    )
    assert is_dup1 is False

    # Second alert 15 seconds later (outside 10s window)
    alert2, is_dup2 = mgr.create_alert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
        current_time=now + 15.0,
    )
    assert is_dup2 is False
    assert alert2.alert_id != alert1.alert_id


def test_different_endpoints_not_deduplicated():
    mgr = AlertManager(deduplication_seconds=10.0)
    now = 1000.0

    a1, is_dup1 = mgr.create_alert(endpoint_id="host-A", prediction="Ransomware", confidence=90.0, risk_score=80, severity=AlertSeverity.HIGH, current_time=now)
    a2, is_dup2 = mgr.create_alert(endpoint_id="host-B", prediction="Ransomware", confidence=90.0, risk_score=80, severity=AlertSeverity.HIGH, current_time=now)
    assert is_dup1 is False
    assert is_dup2 is False


def test_different_processes_distinguished_in_dedup():
    mgr = AlertManager(deduplication_seconds=10.0)
    now = 1000.0

    a1, is_dup1 = mgr.create_alert(
        endpoint_id="host-A",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
        metadata={"process_name": "malware1.exe"},
        current_time=now,
    )
    a2, is_dup2 = mgr.create_alert(
        endpoint_id="host-A",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
        metadata={"process_name": "malware2.exe"},
        current_time=now,
    )
    assert is_dup1 is False
    assert is_dup2 is False


def test_thread_safe_deduplication():
    mgr = AlertManager(deduplication_seconds=5.0)
    num_threads = 10
    alerts_per_thread = 20

    def worker(t_id):
        for i in range(alerts_per_thread):
            mgr.create_alert(
                endpoint_id="host-shared",
                prediction="Ransomware",
                confidence=90.0,
                risk_score=80,
                severity=AlertSeverity.HIGH,
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Only 1 unique alert should have been saved in store, rest suppressed
    active = mgr.get_active_alerts()
    assert len(active) == 1
    assert active[0].suppression_count == (num_threads * alerts_per_thread) - 1


# --- 20-28: INCIDENT MANAGEMENT & STATE MACHINE TESTS ---

def test_incident_creation():
    inc_mgr = IncidentManager()
    alert = DetectionAlert(
        endpoint_id="host-01",
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        severity=AlertSeverity.HIGH,
    )
    inc = inc_mgr.correlate_alert(alert)
    assert isinstance(inc, Incident)
    assert inc.incident_id.startswith("inc-")
    assert inc.status == IncidentStatus.OPEN
    assert inc.severity == IncidentSeverity.HIGH
    assert inc.detection_count == 1
    assert alert.alert_id in inc.alert_ids


def test_related_alerts_correlate():
    inc_mgr = IncidentManager(correlation_window_seconds=30.0)
    now = 1000.0

    a1 = DetectionAlert(endpoint_id="host-01", prediction="Ransomware", confidence=80.0, risk_score=70, severity=AlertSeverity.MEDIUM)
    inc1 = inc_mgr.correlate_alert(a1, current_time=now)

    a2 = DetectionAlert(endpoint_id="host-01", prediction="Ransomware", confidence=95.0, risk_score=90, severity=AlertSeverity.CRITICAL)
    inc2 = inc_mgr.correlate_alert(a2, current_time=now + 5.0)

    # Must be correlated into the same incident
    assert inc1.incident_id == inc2.incident_id
    assert inc2.detection_count == 2
    assert a1.alert_id in inc2.alert_ids
    assert a2.alert_id in inc2.alert_ids


def test_unrelated_alerts_remain_separate():
    inc_mgr = IncidentManager(correlation_window_seconds=10.0)
    now = 1000.0

    # Alert 1 on host-01
    a1 = DetectionAlert(endpoint_id="host-01", risk_score=80, severity=AlertSeverity.HIGH)
    inc1 = inc_mgr.correlate_alert(a1, current_time=now)

    # Alert 2 on host-02 (different endpoint)
    a2 = DetectionAlert(endpoint_id="host-02", risk_score=80, severity=AlertSeverity.HIGH)
    inc2 = inc_mgr.correlate_alert(a2, current_time=now)

    # Alert 3 on host-01 after 20s (outside 10s correlation window)
    a3 = DetectionAlert(endpoint_id="host-01", risk_score=80, severity=AlertSeverity.HIGH)
    inc3 = inc_mgr.correlate_alert(a3, current_time=now + 20.0)

    assert inc1.incident_id != inc2.incident_id
    assert inc1.incident_id != inc3.incident_id


def test_incident_severity_escalation():
    inc_mgr = IncidentManager(correlation_window_seconds=30.0)
    now = 1000.0

    a1 = DetectionAlert(endpoint_id="host-01", risk_score=55, severity=AlertSeverity.MEDIUM)
    inc = inc_mgr.correlate_alert(a1, current_time=now)
    assert inc.severity == IncidentSeverity.MEDIUM

    # Escalating alert arrives
    a2 = DetectionAlert(endpoint_id="host-01", risk_score=95, severity=AlertSeverity.CRITICAL)
    inc = inc_mgr.correlate_alert(a2, current_time=now + 2.0)
    assert inc.severity == IncidentSeverity.CRITICAL
    assert inc.highest_risk_score == 95


def test_incident_update():
    inc_mgr = IncidentManager(correlation_window_seconds=30.0)
    now = 1000.0

    a1 = DetectionAlert(endpoint_id="host-01", risk_score=70, severity=AlertSeverity.HIGH, indicators=[{"feature_name": "path_length"}])
    inc = inc_mgr.correlate_alert(a1, current_time=now)

    a2 = DetectionAlert(endpoint_id="host-01", risk_score=85, severity=AlertSeverity.HIGH, indicators=[{"feature_name": "entropy"}])
    inc = inc_mgr.correlate_alert(a2, current_time=now + 10.0)

    assert inc.last_detection == now + 10.0
    assert inc.highest_risk_score == 85
    assert len(inc.top_indicators) == 2


def test_incident_acknowledgement():
    inc_mgr = IncidentManager()
    alert = DetectionAlert(endpoint_id="host-01", risk_score=80, severity=AlertSeverity.HIGH)
    inc = inc_mgr.correlate_alert(alert)
    assert inc.status == IncidentStatus.OPEN

    success = inc_mgr.acknowledge_incident(inc.incident_id)
    assert success is True
    assert inc.status == IncidentStatus.ACKNOWLEDGED


def test_incident_resolution():
    inc_mgr = IncidentManager()
    alert = DetectionAlert(endpoint_id="host-01", risk_score=80, severity=AlertSeverity.HIGH)
    inc = inc_mgr.correlate_alert(alert)

    success = inc_mgr.resolve_incident(inc.incident_id, resolution_note="Host scrubbed")
    assert success is True
    assert inc.status == IncidentStatus.RESOLVED
    assert inc.resolution_note == "Host scrubbed"


def test_false_positive_transition():
    inc_mgr = IncidentManager()
    alert = DetectionAlert(endpoint_id="host-01", risk_score=80, severity=AlertSeverity.HIGH)
    inc = inc_mgr.correlate_alert(alert)

    success = inc_mgr.mark_false_positive(inc.incident_id, reason="Dev tool approved")
    assert success is True
    assert inc.status == IncidentStatus.FALSE_POSITIVE


def test_invalid_transition_rejection():
    # Attempting to move from RESOLVED -> ACKNOWLEDGED directly must raise
    with pytest.raises(InvalidStateTransitionError):
        IncidentStateMachine.validate_transition(IncidentStatus.RESOLVED, IncidentStatus.ACKNOWLEDGED)

    # Attempting to move from FALSE_POSITIVE -> OPEN directly must raise
    with pytest.raises(InvalidStateTransitionError):
        IncidentStateMachine.validate_transition(IncidentStatus.FALSE_POSITIVE, IncidentStatus.OPEN)


def test_reopening_incident_with_explicit_flag():
    inc_mgr = IncidentManager()
    alert = DetectionAlert(endpoint_id="host-01", risk_score=80, severity=AlertSeverity.HIGH)
    inc = inc_mgr.correlate_alert(alert)
    inc_mgr.resolve_incident(inc.incident_id)
    assert inc.status == IncidentStatus.RESOLVED

    # Reopen explicitly
    success = inc_mgr.reopen_incident(inc.incident_id, reason="Recurring payload detected")
    assert success is True
    assert inc.status == IncidentStatus.OPEN
    assert "Reopened" in inc.summary


# --- 29-32: INCIDENT STORE TESTS ---

def test_alert_storage_retrieval():
    store = LocalIncidentStore()
    alert = DetectionAlert(alert_id="alt-123", endpoint_id="host-01", risk_score=75)
    store.save_alert(alert)

    retrieved = store.get_alert("alt-123")
    assert retrieved is not None
    assert retrieved.risk_score == 75

    listed = store.list_alerts()
    assert len(listed) == 1


def test_incident_storage_retrieval():
    store = LocalIncidentStore()
    inc = Incident(incident_id="inc-456", endpoint_id="host-01", highest_risk_score=90)
    store.save_incident(inc)

    retrieved = store.get_incident("inc-456")
    assert retrieved is not None
    assert retrieved.highest_risk_score == 90

    listed = store.list_incidents()
    assert len(listed) == 1


def test_bounded_store_behavior():
    store = LocalIncidentStore(max_alerts=5, max_incidents=3)
    
    for i in range(10):
        store.save_alert(DetectionAlert(alert_id=f"alt-{i}", risk_score=i))
    assert len(store.list_alerts(limit=100)) == 5
    # Oldest alerts 0-4 should have been evicted
    assert store.get_alert("alt-0") is None
    assert store.get_alert("alt-9") is not None

    for i in range(10):
        store.save_incident(Incident(incident_id=f"inc-{i}", highest_risk_score=i))
    assert len(store.list_incidents(limit=100)) == 3
    assert store.get_incident("inc-0") is None
    assert store.get_incident("inc-9") is not None


def test_concurrent_store_access():
    store = LocalIncidentStore()
    num_threads = 8
    items_per_thread = 50

    def worker(t_id):
        for i in range(items_per_thread):
            a_id = f"alt-{t_id}-{i}"
            store.save_alert(DetectionAlert(alert_id=a_id, risk_score=i))
            _ = store.get_alert(a_id)
            _ = store.list_alerts(limit=10)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(store.list_alerts(limit=1000)) == num_threads * items_per_thread


# --- 33-40: END-TO-END PIPELINE & AGENT INTEGRATION TESTS ---

def test_detection_to_decision_engine():
    decision_engine = DetectionDecisionEngine()
    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=92.0,
        risk_score=85,
        probabilities={"Goodware": 0.08, "Ransomware": 0.92},
        indicators=[{"label": "Archive deletion", "feature_name": "File_Delete_archived", "direction": "increases risk", "weight": 90}],
    )

    res = decision_engine.process_detection(det)
    assert res is not None
    alert, incident = res
    assert alert.severity == AlertSeverity.CRITICAL
    assert incident is not None
    assert incident.status == IncidentStatus.OPEN
    assert alert.alert_id in incident.alert_ids


def test_full_detection_to_incident_pipeline():
    cfg = AgentConfig(
        enable_detection_decisions=True,
        enable_alerting=True,
        enable_incident_management=True,
    )
    agent = RansomShieldAgent(config=cfg)
    
    # Inject high risk detection
    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=95.0,
        risk_score=92,
        probabilities={"Goodware": 0.05, "Ransomware": 0.95},
        indicators=[{"label": "Suspicious execution", "feature_name": "suspicious_path", "direction": "increases risk", "weight": 95}],
    )
    agent._on_detection_result(det)

    active_alerts = agent.get_active_alerts()
    active_incidents = agent.get_active_incidents()
    
    assert len(active_alerts) == 1
    assert len(active_incidents) == 1
    assert active_alerts[0].risk_score == 92
    assert active_incidents[0].highest_risk_score == 92


def test_inference_worker_survives_alert_exception(monkeypatch):
    decision_engine = DetectionDecisionEngine()
    
    def buggy_correlate(*args, **kwargs):
        raise RuntimeError("Simulated internal alert error")

    monkeypatch.setattr(decision_engine.incident_manager, "correlate_alert", buggy_correlate)

    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=90.0,
        risk_score=80,
        probabilities={"Goodware": 0.1, "Ransomware": 0.9},
    )

    # Must handle internal exception safely without raising to the caller
    res = decision_engine.process_detection(det)
    assert res is None


def test_agent_start_stop_with_phase2d_enabled():
    cfg = AgentConfig(
        enable_detection_decisions=True,
        enable_alerting=True,
        enable_incident_management=True,
    )
    agent = RansomShieldAgent(config=cfg)
    agent.start()
    assert agent._is_running is True
    
    status = agent.status()
    assert "alerts" in status
    assert "incidents" in status
    assert "Phase 2D" in status["phase"]
    
    agent.stop()
    assert agent._is_running is False


def test_phase2d_disabled_through_configuration():
    cfg = AgentConfig(enable_alerting=False)
    agent = RansomShieldAgent(config=cfg)
    
    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=95.0,
        risk_score=90,
        probabilities={"Goodware": 0.05, "Ransomware": 0.95},
    )
    agent._on_detection_result(det)
    
    # When alerting is disabled, no alerts should be stored
    assert len(agent.get_alerts()) == 0
    assert len(agent.get_incidents()) == 0


def test_agent_alert_incident_lifecycle_helpers():
    cfg = AgentConfig()
    agent = RansomShieldAgent(config=cfg)
    
    det = DetectionResult(
        timestamp=time.time(),
        window_seconds=10,
        prediction="Ransomware",
        confidence=95.0,
        risk_score=92,
        probabilities={"Goodware": 0.05, "Ransomware": 0.95},
        indicators=[{"label": "Test", "feature_name": "suspicious_path", "direction": "increases risk", "weight": 95}],
    )
    agent._on_detection_result(det)
    
    alerts = agent.get_alerts()
    incidents = agent.get_incidents()
    assert len(alerts) == 1
    assert len(incidents) == 1
    
    a_id = alerts[0].alert_id
    inc_id = incidents[0].incident_id
    
    # Test agent lifecycle helper methods
    assert agent.acknowledge_alert(a_id) is True
    assert alerts[0].status == AlertStatus.ACKNOWLEDGED
    
    assert agent.resolve_alert(a_id) is True
    assert alerts[0].status == AlertStatus.RESOLVED
    
    assert agent.acknowledge_incident(inc_id) is True
    assert incidents[0].status == IncidentStatus.ACKNOWLEDGED
    
    assert agent.resolve_incident(inc_id, "Verified by SOC") is True
    assert incidents[0].status == IncidentStatus.RESOLVED


def test_incident_store_clear():
    store = LocalIncidentStore()
    store.save_alert(DetectionAlert(alert_id="a1"))
    store.save_incident(Incident(incident_id="i1"))
    assert len(store.list_alerts()) == 1
    assert len(store.list_incidents()) == 1
    
    store.clear()
    assert len(store.list_alerts()) == 0
    assert len(store.list_incidents()) == 0

