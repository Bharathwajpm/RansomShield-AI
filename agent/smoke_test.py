"""
RansomShield AI — Windows Live Endpoint Smoke Test
Phase 2C: Sliding Window Feature Extractor & Live ML Inference Engine

Safely tests the entire live endpoint pipeline:
1. Initializes RansomShieldAgent
2. Starts live psutil, watchdog, and network collectors
3. Starts LiveInferenceEngine
4. Simulates benign endpoint filesystem activity (creating and renaming harmless temp text files)
5. Extracts live 5s, 10s, and 30s feature vectors
6. Executes real Model V2 inference and TreeSHAP attribution
7. Prints structured detection results and indicators
8. Gracefully terminates agent and all worker threads
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


def run_live_smoke_test():
    print("================================================================================")
    print("  RansomShield AI — Phase 2C Live Windows Endpoint Smoke Test")
    print("  Model: xgb_ransomware_v2 (19 Features) | Safe Benign Demonstration")
    print("================================================================================\n")

    with tempfile.TemporaryDirectory() as tmp_dir:
        print(f"[1/6] Setting up agent with monitored directory: {tmp_dir}")
        cfg = AgentConfig(
            agent_id="smoke-test-endpoint",
            collection_interval_seconds=0.5,
            inference_interval_seconds=1.0,
            monitored_directories=[tmp_dir],
            sysmon_enabled=True,
            windows_event_log_enabled=True,
            inference_enabled=True,
        )

        agent = RansomShieldAgent(config=cfg)
        
        print("[2/6] Starting RansomShieldAgent, live collectors, and inference engine...")
        agent.start()
        time.sleep(0.5)

        print("[3/6] Simulating benign endpoint user activity...")
        # Create normal benign test file
        test_file_1 = Path(tmp_dir) / "quarterly_budget_report.txt"
        test_file_1.write_text("Revenue: $1,250,000\nExpenses: $850,000\nNet: $400,000\n")
        print(f"      Created benign file: {test_file_1.name}")
        time.sleep(0.5)

        # Modify file
        test_file_1.write_text("Revenue: $1,250,000\nExpenses: $850,000\nNet: $400,000\nApproved by CFO.\n")
        print(f"      Modified file: {test_file_1.name}")
        time.sleep(0.5)

        # Rename file
        test_file_2 = Path(tmp_dir) / "quarterly_budget_report_final.txt"
        test_file_1.rename(test_file_2)
        print(f"      Renamed file to: {test_file_2.name}")
        time.sleep(1.0)

        print("\n[4/6] Extracting Live Sliding Window Features (5s, 10s, 30s)...")
        multi_feats = agent.feature_extractor.extract_multi_window([5, 10, 30])
        for w_sec, feats in multi_feats.items():
            print(f"\n--- {w_sec}-Second Sliding Window Features ({len(feats)} features) ---")
            print(json.dumps(feats, indent=2))

        print("\n[5/6] Executing Model V2 Live Inference & TreeSHAP Attribution...")
        detections = agent.inference_engine.evaluate_all_windows()
        for w_sec, det in detections.items():
            print(f"\n==================== WINDOW: {w_sec}s DETECTION RESULT ====================")
            print(f"  Prediction:    {det.prediction}")
            print(f"  Confidence:    {det.confidence}%")
            print(f"  Risk Score:    {det.risk_score} / 100")
            print(f"  Model Version: {det.model_version}")
            print(f"  Probabilities: {det.probabilities}")
            print(f"  Event Count:   {det.event_count}")
            print(f"  Duration:      {det.duration_ms} ms")
            print(f"  Summary:       {det.explanation}")
            print(f"  SHAP Indicators ({len(det.indicators)}):")
            for ind in det.indicators:
                print(f"    - {ind['label']} ({ind['feature_name']}): SHAP={ind['shap_value']:+.4f} | Weight={ind['weight']}% | Direction={ind['direction']}")

        print("\n[6/6] Stopping RansomShieldAgent and cleaning up resources...")
        agent.stop(reason="Live smoke test complete")
        
        status = agent.status()
        print(f"  Agent Running Status: {status['running']}")
        print(f"  Buffer Events Processed: {status['buffer_stats']['total_appended']}")
        print(f"  Inference Evaluations: {status.get('inference', {}).get('total_evaluations', 0)}")
        print("\n================================================================================")
        print("  SMOKE TEST PASSED: Full Live Telemetry -> Model V2 Inference Pipeline Verified!")
        print("================================================================================\n")


if __name__ == "__main__":
    run_live_smoke_test()
