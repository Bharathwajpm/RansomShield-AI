"""
RansomShield AI — Reusable Inference Engine (V2 Real & V1 Benchmark)
Phase 1: Machine Learning & Feature Pipeline

Loads the serialized XGBoost model artifact and feature metadata,
enforces strict feature ordering, computes predictions and confidence,
and calculates calibrated 0–100 risk scores.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Union, Optional
import numpy as np
import xgboost as xgb

from ml.features.feature_contract import (
    V2_FEATURE_NAMES,
    V1_FEATURE_NAMES,
    V2_LABEL_MAPPING,
    V1_LABEL_MAPPING,
)
from ml.features.preprocessor import FeaturePreprocessor


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = PROJECT_ROOT / "ml" / "models"


class RansomShieldPredictor:
    """
    Production inference engine supporting Model V2 (Real Sysmon Telemetry)
    and Model V1 (Synthetic Prototype Benchmark).
    """
    
    def __init__(
        self,
        model_version: str = "xgb_ransomware_v2",
        model_path: Optional[str] = None,
        meta_path: Optional[str] = None,
        preprocessor_path: Optional[str] = None,
    ):
        self.model_version = model_version
        
        if model_version == "xgb_ransomware_v2":
            self.model_path = Path(model_path) if model_path else MODELS_DIR / "xgb_ransomware_v2.json"
            self.meta_path = Path(meta_path) if meta_path else MODELS_DIR / "feature_meta_v2.json"
            self.preprocessor_path = Path(preprocessor_path) if preprocessor_path else MODELS_DIR / "preprocessor_v2.json"
            self.feature_names = V2_FEATURE_NAMES
            self.label_mapping = V2_LABEL_MAPPING
        else:
            self.model_path = Path(model_path) if model_path else MODELS_DIR / "xgb_ransomware_v1.json"
            self.meta_path = Path(meta_path) if meta_path else MODELS_DIR / "feature_meta.json"
            self.preprocessor_path = Path(preprocessor_path) if preprocessor_path else MODELS_DIR / "preprocessor.json"
            self.feature_names = V1_FEATURE_NAMES
            self.label_mapping = V1_LABEL_MAPPING
            
        self.booster: Optional[xgb.Booster] = None
        self.metadata: Dict[str, Any] = {}
        self.preprocessor: Optional[FeaturePreprocessor] = None
        
        self.load_model()
        
    def load_model(self) -> None:
        """Loads the XGBoost model and metadata from disk."""
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at {self.model_path}. Run ml/training/train_xgboost.py first."
            )
            
        self.booster = xgb.Booster()
        self.booster.load_model(str(self.model_path))
        
        if self.meta_path.exists():
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
            self.feature_names = self.metadata.get("feature_names", self.feature_names)
            self.label_mapping = self.metadata.get("label_mapping", self.label_mapping)
            
        if self.preprocessor_path.exists():
            with open(self.preprocessor_path, "r", encoding="utf-8") as f:
                prep_dict = json.load(f)
            self.preprocessor = FeaturePreprocessor.from_dict(prep_dict)
        else:
            self.preprocessor = FeaturePreprocessor(self.feature_names, version="v2" if "v2" in self.model_version else "v1")
            
    def _prepare_vector(self, features: Union[Dict[str, float], List[float], np.ndarray]) -> np.ndarray:
        """Enforces deterministic feature ordering matching feature metadata."""
        if isinstance(features, dict):
            vector = np.array([float(features.get(name, 0.0)) for name in self.feature_names], dtype=np.float64)
        elif isinstance(features, (list, tuple)):
            if len(features) != len(self.feature_names):
                raise ValueError(f"Expected {len(self.feature_names)} features, got {len(features)}.")
            vector = np.array(features, dtype=np.float64)
        elif isinstance(features, np.ndarray):
            if features.ndim == 1:
                if len(features) != len(self.feature_names):
                    raise ValueError(f"Expected {len(self.feature_names)} features, got {len(features)}.")
                vector = features.astype(np.float64)
            else:
                vector = features.reshape(-1).astype(np.float64)
        else:
            raise TypeError(f"Unsupported features type: {type(features)}")
            
        return vector.reshape(1, -1)

    def calculate_risk_score(self, p_ransomware: float) -> int:
        """
        Transforms the model probability into a deterministic 0–100 Risk Score:
          - LOW:      0–30  (Monitor)
          - MEDIUM:  31–60  (Warning)
          - HIGH:    61–80  (Admin Alert)
          - CRITICAL:81–100 (Containment: Block + Isolate)
        """
        if p_ransomware >= 0.70:
            score = 80.0 + (p_ransomware - 0.70) / 0.30 * 20.0
        elif p_ransomware >= 0.40:
            score = 60.0 + (p_ransomware - 0.40) / 0.30 * 20.0
        elif p_ransomware >= 0.15:
            score = 30.0 + (p_ransomware - 0.15) / 0.25 * 30.0
        else:
            score = (p_ransomware / 0.15) * 30.0
            
        return int(np.clip(round(score), 0, 100))

    def predict(self, features: Union[Dict[str, float], List[float], np.ndarray]) -> Dict[str, Any]:
        """
        Executes real-time inference on a feature vector.
        """
        X = self._prepare_vector(features)
        dmatrix = xgb.DMatrix(X, feature_names=self.feature_names)
        raw_pred = self.booster.predict(dmatrix)[0]
        
        if np.ndim(raw_pred) == 0:
            p_ransomware = float(raw_pred)
            p_goodware = 1.0 - p_ransomware
            probas = {"Goodware": round(p_goodware, 4), "Ransomware": round(p_ransomware, 4)}
            pred_label = "Ransomware" if p_ransomware >= 0.5 else "Goodware"
            confidence = round((p_ransomware if p_ransomware >= 0.5 else p_goodware) * 100.0, 1)
        else:
            probas_arr = raw_pred
            pred_idx = int(np.argmax(probas_arr))
            pred_label = self.label_mapping.get(str(pred_idx), self.label_mapping.get(pred_idx, "UNKNOWN"))
            confidence = round(float(probas_arr[pred_idx] * 100.0), 1)
            p_ransomware = float(probas_arr[-1])
            probas = {str(k): round(float(v), 4) for k, v in zip(self.label_mapping.values(), probas_arr)}
            
        risk_score = self.calculate_risk_score(p_ransomware)
        
        # Determine pipeline stage
        if pred_label in ("Goodware", "BENIGN") and risk_score < 30:
            stage = 2
        elif risk_score < 60:
            stage = 3
        elif risk_score < 80:
            stage = 4
        else:
            stage = 6
            
        return {
            "prediction": pred_label,
            "confidence": confidence,
            "risk_score": risk_score,
            "probabilities": probas,
            "stage": stage,
            "model_version": self.model_version,
        }


_v2_predictor: Optional[RansomShieldPredictor] = None
_v1_predictor: Optional[RansomShieldPredictor] = None

def get_predictor(version: str = "v2") -> RansomShieldPredictor:
    """Returns singleton instance of the predictor for the requested version."""
    global _v2_predictor, _v1_predictor
    if version == "v2" or version == "xgb_ransomware_v2":
        if _v2_predictor is None:
            _v2_predictor = RansomShieldPredictor(model_version="xgb_ransomware_v2")
        return _v2_predictor
    else:
        if _v1_predictor is None:
            _v1_predictor = RansomShieldPredictor(model_version="xgb_ransomware_v1")
        return _v1_predictor


if __name__ == "__main__":
    p_v2 = get_predictor("v2")
    
    # Real Sysmon Benign Sample
    benign_v2 = {
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
        "path_length": 35,
        "directory_depth": 3,
        "process_name_length": 12,
        "process_vs_parent_freq_ratio": 1.0,
        "executable_depth_diff": 0,
        "parent_is_system_executable": 1,
        "extension_similarity": 0,
        "file_name_entropy": 0.0,
    }
    
    # Real Sysmon Ransomware Sample (Active file deletion, high entropy, suspicious path)
    ransomware_v2 = {
        "File_Delete_archived": 1,
        "File_created": 1,
        "File_creation_time_changed": 1,
        "Pipe_Created": 0,
        "Process_Create": 1,
        "Registry_value_set": 1,
        "process-related": 1,
        "network-related": 0,
        "file-related": 1,
        "suspicious_path": 1,
        "system_executable": 0,
        "path_length": 85,
        "directory_depth": 7,
        "process_name_length": 18,
        "process_vs_parent_freq_ratio": 4.5,
        "executable_depth_diff": 3,
        "parent_is_system_executable": 0,
        "extension_similarity": 1,
        "file_name_entropy": 4.25,
    }
    
    print("--- MODEL V2 BENIGN SAMPLE TEST ---")
    print(json.dumps(p_v2.predict(benign_v2), indent=2))
    
    print("\n--- MODEL V2 RANSOMWARE SAMPLE TEST ---")
    print(json.dumps(p_v2.predict(ransomware_v2), indent=2))
