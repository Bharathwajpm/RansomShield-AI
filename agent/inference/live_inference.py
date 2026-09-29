"""
RansomShield AI — Live ML Inference Engine
Phase 2C: Sliding Window Feature Extractor & Live ML Inference

Periodically aggregates live telemetry from the InMemoryTelemetryBuffer across
5s, 10s, and 30s sliding windows, extracts the 19 Model V2 features, executes
XGBoost Model V2 inference, computes calibrated risk scores, and generates
TreeSHAP feature attributions into structured DetectionResult records.
"""

import time
import threading
import logging
from typing import Dict, Any, List, Optional, Callable
from collections import deque

from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from agent.features.feature_extractor import LiveFeatureExtractor
from agent.inference.detection_result import DetectionResult
from ml.inference.predictor import RansomShieldPredictor, get_predictor
from ml.inference.explainer import RansomShieldExplainer, get_explainer


logger = logging.getLogger("RansomShieldInference")


class LiveInferenceEngine:
    """
    Continuous live inference engine running Model V2 against rolling telemetry windows.
    """

    def __init__(
        self,
        buffer: InMemoryTelemetryBuffer,
        sliding_windows: Optional[List[int]] = None,
        inference_interval_seconds: float = 2.0,
        model_version: str = "xgb_ransomware_v2",
        predictor: Optional[RansomShieldPredictor] = None,
        explainer: Optional[RansomShieldExplainer] = None,
    ):
        self.buffer = buffer
        self.sliding_windows = sliding_windows or [5, 10, 30]
        self.inference_interval_seconds = inference_interval_seconds
        self.model_version = model_version
        
        self.feature_extractor = LiveFeatureExtractor(buffer=self.buffer)
        self.predictor = predictor or get_predictor(self.model_version)
        self.explainer = explainer or get_explainer(self.model_version)

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        self._latest_results: Dict[int, DetectionResult] = {}
        self._history: deque = deque(maxlen=200)
        self._callbacks: List[Callable[[DetectionResult], None]] = []
        self._is_running: bool = False

    def is_running(self) -> bool:
        return self._is_running

    def register_callback(self, callback: Callable[[DetectionResult], None]) -> None:
        """Registers a callback hook invoked when a new DetectionResult is produced."""
        with self._lock:
            self._callbacks.append(callback)

    def start(self) -> None:
        """Starts background inference evaluation loop."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._inference_loop,
                name="LiveInferenceWorker",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info(f"[INFERENCE_STARTED] Live inference engine started (Interval: {self.inference_interval_seconds}s)")

    def stop(self) -> None:
        """Stops background inference evaluation thread cleanly."""
        with self._lock:
            if not self._is_running:
                return
            self._stop_event.set()
            self._is_running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.5)
            self._worker_thread = None
            logger.info("[INFERENCE_COMPLETED] Live inference engine stopped cleanly.")

    def _inference_loop(self) -> None:
        """Continuous background inference loop."""
        while not self._stop_event.is_set():
            try:
                self.evaluate_all_windows()
            except Exception as e:
                logger.error(f"[INFERENCE_ERROR] Live inference evaluation error: {e}", exc_info=False)

            self._stop_event.wait(timeout=self.inference_interval_seconds)

    def evaluate_window(
        self,
        window_seconds: int = 10,
        current_time: Optional[float] = None,
    ) -> DetectionResult:
        """
        Extracts features, runs Model V2 inference, and generates TreeSHAP explanation for a window.
        """
        start_eval_ts = time.time()
        if current_time is None:
            current_time = start_eval_ts

        # 1. Extract 19 Model V2 features
        events = self.buffer.get_events(window_seconds=float(window_seconds), current_time=current_time)
        event_count = len(events)
        features = self.feature_extractor._compute_features(events)

        if event_count == 0:
            logger.debug(f"[EMPTY_TELEMETRY_WINDOW] Zero events in {window_seconds}s window. Applying deterministic baseline.")

        # 2. Run Model V2 Inference
        pred_dict = self.predictor.predict(features)
        
        # 3. Generate TreeSHAP explanations
        try:
            shap_dict = self.explainer.explain(features, top_k=5)
            indicators = shap_dict.get("indicators", [])
            explanation = shap_dict.get("explanation", "")
        except Exception:
            indicators = []
            explanation = f"Prediction: {pred_dict['prediction']} (Confidence: {pred_dict['confidence']}%)"

        duration_ms = round((time.time() - start_eval_ts) * 1000.0, 2)

        # 4. Construct typed DetectionResult
        result = DetectionResult(
            timestamp=current_time,
            window_seconds=window_seconds,
            prediction=pred_dict["prediction"],
            confidence=pred_dict["confidence"],
            risk_score=pred_dict["risk_score"],
            probabilities=pred_dict["probabilities"],
            model_version=self.model_version,
            stage=pred_dict["stage"],
            features=features,
            indicators=indicators,
            explanation=explanation,
            event_count=event_count,
            duration_ms=duration_ms,
        )

        with self._lock:
            self._latest_results[window_seconds] = result
            self._history.append(result)

        # Invoke registered callbacks
        for cb in self._callbacks:
            try:
                cb(result)
            except Exception:
                pass

        logger.debug(
            f"[DETECTION_RESULT_CREATED] Window: {window_seconds}s | "
            f"Prediction: {result.prediction} | Risk: {result.risk_score} | Events: {event_count}"
        )

        return result

    def evaluate_all_windows(self, current_time: Optional[float] = None) -> Dict[int, DetectionResult]:
        """Evaluates all configured sliding windows (e.g. 5s, 10s, 30s)."""
        results: Dict[int, DetectionResult] = {}
        for w in self.sliding_windows:
            results[w] = self.evaluate_window(window_seconds=w, current_time=current_time)
        return results

    def get_latest_result(self, window_seconds: int = 10) -> Optional[DetectionResult]:
        """Returns the most recent detection result for the specified window."""
        with self._lock:
            return self._latest_results.get(window_seconds)

    def get_all_latest_results(self) -> Dict[int, DetectionResult]:
        """Returns the latest detection results across all windows."""
        with self._lock:
            return dict(self._latest_results)

    def status(self) -> Dict[str, Any]:
        """Returns diagnostic status of the live inference engine."""
        latest_summary = {}
        with self._lock:
            for w, res in self._latest_results.items():
                latest_summary[f"{w}s"] = {
                    "prediction": res.prediction,
                    "confidence": res.confidence,
                    "risk_score": res.risk_score,
                    "event_count": res.event_count,
                }

        return {
            "running": self._is_running,
            "model_version": self.model_version,
            "inference_interval_seconds": self.inference_interval_seconds,
            "sliding_windows": self.sliding_windows,
            "total_evaluations": len(self._history),
            "latest_predictions": latest_summary,
        }
