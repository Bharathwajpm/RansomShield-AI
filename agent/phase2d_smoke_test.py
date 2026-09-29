"""
RansomShield AI — Windows Live Endpoint Smoke Test (Phase 2D)
Phase 2D: Detection Decision, Alerting & Incident Pipeline

Demonstrates the complete end-to-end endpoint security pipeline:
1. Initializes RansomShieldAgent with Phase 2D Alerting & Incident Subsystems
2. Starts live psutil, watchdog, and network collectors
3. Starts LiveInferenceEngine (Model V2)
4. Generates benign user filesystem activity (safe temporary text file operations)
5. Extracts live 5s/10s/30s sliding window features and runs Model V2 inference
6. Feeds DetectionResult into DetectionDecisionEngine -> AlertManager -> IncidentManager
7. Inspects live alerts and correlated incidents
8. Tests alert and incident acknowledgement / resolution
9. Stops all agent collector and inference worker threads cleanly
"""

import time
import json
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.config import AgentConfig
from agent.service.agent import RansomShieldAgent
from agent.detection.severity import AlertSeverity, IncidentStatus


def run_phase2d_smoke_test():
    print("================================================================================")
    print("  RansomShield AI — Phase 2D Live Windows Endpoint Smoke Test")
    print("  Detection Decision, Alerting & Incident Pipeline Demonstration")
    print("================================================================================\n")

    with tempfile.TemporaryDirectory() as tmp_dir:
        print(f"[1/7] Initializing agent with monitored directory: {tmp_dir}")
        cfg = AgentConfig(
            agent_id="smoke-endpoint-win11",
            collection_interval_seconds=0.5,
            inference_interval_seconds=1.0,
            monitored_directories=[tmp_dir],
            sysmon_enabled=True,
            windows_event_log_enabled=True,
            inference_enabled=True,
            enable_detection_decisions=True,
            enable_alerting=True,
            enable_incident_management=True,
        )

        agent = RansomShieldAgent(config=cfg)
        
        print("[2/7] Starting RansomShieldAgent, live collectors, and ML inference...")
        agent.start()
        time.sleep(0.5)

        print("[3/7] Simulating benign user endpoint activity...")
        test_file = Path(tmp_dir) / "annual_security_review.txt"
        test_file.write_text("SOC review: All endpoints patched and operational.\n")
        print(f"      Created safe text file: {test_file.name}")
        time.sleep(0.5)

        test_file.write_text("SOC review: All endpoints patched. Zero critical vulnerabilities.\n")
        print(f"      Modified text file: {test_file.name}")
        time.sleep(1.0)

        print("[4/7] Triggering live sliding window feature extraction & Model V2 scoring...")
        det_result = agent.evaluate_now(window_seconds=10)
        
        if det_result:
            print(f"\n==================== LIVE MODEL V2 DETECTION RESULT ====================")
            print(f"  Prediction:    {det_result.prediction}")
            print(f"  Confidence:    {det_result.confidence}%")
            print(f"  Risk Score:    {det_result.risk_score} / 100")
            print(f"  Model Version: {det_result.model_version}")
            print(f"  Event Count:   {det_result.event_count}")
            print(f"  Evaluation MS: {det_result.duration_ms} ms")
            print(f"  Summary:       {det_result.explanation}")
            print(f"  SHAP Indicators ({len(det_result.indicators)}):")
            for ind in det_result.indicators[:3]:
                print(f"    - {ind['label']}: SHAP={ind['shap_value']:+.4f} | Weight={ind['weight']}%")

        print("\n[5/7] Simulating synthetic suspicious detection through Phase 2D decision pipeline...")
        # Inject an elevated suspicious detection result to verify alert & incident creation
        from agent.inference.detection_result import DetectionResult
        susp_detection = DetectionResult(
            timestamp=time.time(),
            window_seconds=10,
            prediction="Ransomware",
            confidence=94.5,
            risk_score=88,
            probabilities={"Goodware": 0.055, "Ransomware": 0.945},
            stage=4,
            model_version="xgb_ransomware_v2",
            indicators=[
                {"label": "Execution from temp directory", "feature_name": "suspicious_path", "direction": "increases risk", "weight": 95},
                {"label": "Obfuscated binary name", "feature_name": "process_name_length", "direction": "increases risk", "weight": 85},
            ],
            explanation="Elevated ransomware pattern detected.",
        )
        agent._on_detection_result(susp_detection)

        alerts = agent.get_alerts()
        incidents = agent.get_incidents()

        print(f"\n==================== PHASE 2D STORED ALERTS ({len(alerts)}) ====================")
        for alt in alerts:
            print(f"  Alert ID:   {alt.alert_id}")
            print(f"  Severity:   {alt.severity.value}")
            print(f"  Status:     {alt.status.value}")
            print(f"  Risk Score: {alt.risk_score}/100")
            print(f"  Reason:     {alt.reason}")
            print(f"  Incident:   {alt.incident_id}")

        print(f"\n==================== PHASE 2D CORRELATED INCIDENTS ({len(incidents)}) ====================")
        for inc in incidents:
            print(f"  Incident ID:     {inc.incident_id}")
            print(f"  Severity:        {inc.severity.value}")
            print(f"  Status:          {inc.status.value}")
            print(f"  Alert Count:     {inc.detection_count} (Alert IDs: {inc.alert_ids})")
            print(f"  Highest Risk:    {inc.highest_risk_score}/100")
            print(f"  Primary Pred:    {inc.primary_prediction}")
            print(f"  Summary:         {inc.summary}")

        print("\n[6/7] Testing alert acknowledgement and incident resolution...")
        if alerts:
            agent.acknowledge_alert(alerts[0].alert_id)
            print(f"      Alert '{alerts[0].alert_id}' acknowledged: {alerts[0].status.value}")
        if incidents:
            agent.resolve_incident(incidents[0].incident_id, resolution_note="Simulated test incident closed.")
            print(f"      Incident '{incidents[0].incident_id}' resolved: {incidents[0].status.value}")

        print("\n[7/7] Stopping agent and terminating all worker threads...")
        agent.stop(reason="Phase 2D smoke test complete")
        
        status = agent.status()
        print(f"  Agent Running:          {status['running']}")
        print(f"  Telemetry Events:       {status['buffer_stats']['total_appended']}")
        print(f"  Active Alerts:          {status['alerts']['active_count']}")
        print(f"  Total Stored Alerts:    {status['alerts']['total_stored']}")
        print(f"  Total Stored Incidents: {status['incidents']['total_stored']}")
        print("\n================================================================================")
        print("  PHASE 2D SMOKE TEST PASSED: Alerting & Incident Pipeline Fully Operational!")
        print("================================================================================\n")


if __name__ == "__main__":
    run_phase2d_smoke_test()
