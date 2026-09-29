"""
RansomShield AI — Explainable AI & TreeSHAP Attribution Engine
Phase 1: Machine Learning & Feature Pipeline

Provides real-time feature attribution and directional explanations using
XGBoost's native high-performance TreeSHAP implementation (pred_contribs=True).
"""

from typing import Dict, Any, List, Union, Optional
import numpy as np
import xgboost as xgb

from ml.inference.predictor import get_predictor, RansomShieldPredictor


class RansomShieldExplainer:
    """
    Computes exact TreeSHAP contributions and human-readable feature attributions
    for model predictions across V2 and V1 models.
    """
    
    def __init__(self, predictor: Optional[RansomShieldPredictor] = None, version: str = "v2"):
        self.predictor = predictor or get_predictor(version)
        
    def explain(
        self,
        features: Union[Dict[str, float], List[float], np.ndarray],
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Computes SHAP feature attribution weights and directional impacts for a sample.
        """
        X = self.predictor._prepare_vector(features)
        dmatrix = xgb.DMatrix(X, feature_names=self.predictor.feature_names)
        
        # XGBoost native TreeSHAP returns raw contributions
        raw_contribs = self.predictor.booster.predict(dmatrix, pred_contribs=True)[0]
        pred_result = self.predictor.predict(features)
        prediction = pred_result["prediction"]
        
        if raw_contribs.ndim == 2:
            # Multiclass
            target_class_idx = -1
            class_contribs = raw_contribs[target_class_idx, :-1]
            base_value = float(raw_contribs[target_class_idx, -1])
        else:
            # Binary logistic
            class_contribs = raw_contribs[:-1]
            base_value = float(raw_contribs[-1])
            
        feature_names = self.predictor.feature_names
        
        readable_labels = {
            "File_Delete_archived": "File deletion & archive removal",
            "File_created": "Mass file creation",
            "File_creation_time_changed": "File timestomping evasion",
            "Pipe_Created": "Named pipe creation",
            "Process_Create": "Process creation event",
            "Registry_value_set": "Registry persistence writes",
            "process-related": "Elevated process activity",
            "network-related": "Outbound network connection",
            "file-related": "Elevated file system I/O",
            "suspicious_path": "Execution from user/temp directory",
            "system_executable": "Legitimate system binary path",
            "path_length": "Abnormal path length",
            "directory_depth": "Directory nesting depth",
            "process_name_length": "Obfuscated process name length",
            "process_vs_parent_freq_ratio": "Abnormal parent-child frequency",
            "executable_depth_diff": "Parent-child directory discrepancy",
            "parent_is_system_executable": "System parent binary verification",
            "extension_similarity": "File extension alteration",
            "file_name_entropy": "High file name entropy",
            # Legacy V1 labels
            "file_modification_rate": "Rapid file modification",
            "file_rename_rate": "High file rename rate",
            "file_deletion_rate": "File deletion rate",
            "write_entropy_avg": "High write entropy (Encryption)",
            "high_entropy_ratio": "Encrypted file ratio",
            "cpu_usage_pct": "Unusual CPU activity",
            "memory_usage_pct": "Memory pressure",
            "process_creation_rate": "Abnormal process creation",
            "unsigned_proc_ratio": "Unsigned process behavior",
            "registry_write_rate": "Registry persistence writes",
            "network_connection_count": "Network anomaly",
            "shadow_copy_tamper": "Shadow copy deletion attempt",
        }
        
        abs_contribs = np.abs(class_contribs)
        max_abs = float(np.max(abs_contribs)) if float(np.max(abs_contribs)) > 0 else 1.0
        sorted_indices = np.argsort(-abs_contribs)
        
        indicators = []
        detailed_explanations = []
        
        for idx in sorted_indices[:top_k]:
            fname = feature_names[idx]
            label = readable_labels.get(fname, fname)
            shap_val = float(class_contribs[idx])
            
            ui_weight = int(round((abs(shap_val) / max_abs) * 95.0 + 5.0))
            ui_weight = min(100, max(0, ui_weight))
            
            if shap_val > 0.05:
                direction = "increases risk"
            elif shap_val < -0.05:
                direction = "decreases risk"
            else:
                direction = "neutral"
                
            indicators.append({
                "label": label,
                "feature_name": fname,
                "weight": ui_weight,
                "shap_value": round(shap_val, 4),
                "direction": direction,
            })
            
            detailed_explanations.append(
                f"{label} ({direction}, contribution: {shap_val:+.3f})"
            )
            
        if prediction in ("Ransomware", "RANSOMWARE"):
            human_summary = (
                "The model detected active ransomware behavior based on file operations, "
                "path anomaly indicators, and process execution telemetry."
            )
        elif prediction == "SUSPICIOUS":
            human_summary = (
                "Unusual endpoint activity observed deviating from learned baseline. "
                "Elevation in process creation and file operations detected."
            )
        else:
            human_summary = (
                "Observed endpoint telemetry stays within normal baseline limits. "
                "No indicators consistent with ransomware behavior."
            )
            
        return {
            "prediction": prediction,
            "confidence": pred_result["confidence"],
            "risk_score": pred_result["risk_score"],
            "base_value": round(base_value, 4),
            "indicators": indicators,
            "detailed_explanations": detailed_explanations,
            "explanation": human_summary,
            "stage": pred_result["stage"],
            "model_version": self.predictor.model_version,
        }


_v2_explainer: Optional[RansomShieldExplainer] = None

def get_explainer(version: str = "v2") -> RansomShieldExplainer:
    global _v2_explainer
    if _v2_explainer is None:
        _v2_explainer = RansomShieldExplainer(version=version)
    return _v2_explainer


if __name__ == "__main__":
    import json
    
    explainer = RansomShieldExplainer(version="v2")
    
    sample = {
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
    
    res = explainer.explain(sample)
    print("=== MODEL V2 SHAP ATTRIBUTION REPORT ===")
    print(json.dumps(res, indent=2))
