"""
RansomShield AI — XGBoost Behavioral Classifier Training Pipeline
Phase 1: Machine Learning & Feature Pipeline

Trains, evaluates, and exports the XGBoost ransomware detection models:
- Model V2 (Default): Trained on verified CSU Sysmon Ransomware Telemetry (19 features)
- Model V1 (Legacy): Trained on Prototype Synthetic Benchmark (12 features)
"""

import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
import xgboost as xgb

from ml.features.feature_contract import (
    V2_FEATURE_NAMES,
    V1_FEATURE_NAMES,
    V2_LABEL_MAPPING,
    V1_LABEL_MAPPING,
    get_v2_feature_contract_dict,
    get_v1_feature_contract_dict,
)
from ml.features.preprocessor import FeaturePreprocessor
from ml.data.loader import load_real_csu_dataset, generate_benchmark_dataset, ensure_directories


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = PROJECT_ROOT / "ml" / "models"


def ensure_models_dir():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)


def train_v2_real_model(
    test_size: float = 0.20,
    random_state: int = 42,
    export_artifacts: bool = True,
) -> Tuple[xgb.XGBClassifier, Dict[str, Any], Dict[str, Any]]:
    """
    Trains Model V2 on the verified CSU Sysmon ransomware telemetry dataset.
    """
    ensure_models_dir()
    
    print("=" * 70)
    print("RANSOMSHIELD AI — MODEL V2 TRAINING (VERIFIED CSU SYSMON TELEMETRY)")
    print("=" * 70)
    
    # 1. Load Real Dataset
    print("\n[Step 1/6] Loading & Validating CSU Sysmon Dataset...")
    df, validation_report = load_real_csu_dataset(deduplicate=True)
    print(f"  [+] Loaded {len(df)} unique behavioral states with {len(V2_FEATURE_NAMES)} Sysmon features.")
    print(f"  [+] Provenance: {validation_report['provenance']}")
    print(f"  [+] Class Distribution: {df['label'].value_counts().to_dict()} (0=Goodware, 1=Ransomware)")
    
    X_raw = df[V2_FEATURE_NAMES]
    y_raw = df["label"].values.astype(int)
    
    # 2. Stratified Split
    print("\n[Step 2/6] Splitting Dataset (80% Train / 20% Holdout Test, Stratified)...")
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        X_raw,
        y_raw,
        test_size=test_size,
        random_state=random_state,
        stratify=y_raw,
    )
    print(f"  [+] Training Set:     {len(X_train_df)} samples")
    print(f"  [+] Test Holdout Set: {len(X_test_df)} samples")
    
    # 3. Fit Preprocessor on Train Only
    print("\n[Step 3/6] Fitting Preprocessor (Zero Data Leakage)...")
    preprocessor = FeaturePreprocessor(feature_names=V2_FEATURE_NAMES, version="v2")
    preprocessor.fit(X_train_df)
    
    X_train = preprocessor.transform(X_train_df)
    X_test = preprocessor.transform(X_test_df)
    
    # 4. Train XGBoost
    print("\n[Step 4/6] Training XGBoost Classifier...")
    model_params = {
        "n_estimators": 140,
        "max_depth": 5,
        "learning_rate": 0.08,
        "subsample": 0.85,
        "colsample_bytree": 0.85,
        "min_child_weight": 2,
        "gamma": 0.1,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "random_state": random_state,
        "tree_method": "hist",
    }
    
    clf = xgb.XGBClassifier(**model_params)
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring="f1")
    print(f"  [+] 5-Fold Cross-Validation Ransomware F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    
    clf.fit(
        X_train,
        y_train,
        eval_set=[(X_train, y_train), (X_test, y_test)],
        verbose=False,
    )
    print("  [+] XGBoost Model V2 training complete.")
    
    # 5. Evaluation
    print("\n[Step 5/6] Evaluating on Holdout Test Set...")
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    metrics = {
        "evaluation_type": "HISTORICAL REAL TELEMETRY EVALUATION",
        "dataset_name": "CSU-Ransomware-Data (SCReeD)",
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "roc_auc": round(roc_auc * 100, 2),
        "cv_f1_mean": round(float(cv_scores.mean()) * 100, 2),
        "cv_f1_std": round(float(cv_scores.std()) * 100, 2),
        "confusion_matrix": cm,
    }
    
    print("\n" + "-" * 50)
    print("MODEL V2 REAL TELEMETRY EVALUATION METRICS:")
    print("-" * 50)
    print(f"  * Accuracy:            {metrics['accuracy']}%")
    print(f"  * Ransomware Precision:{metrics['precision']}%")
    print(f"  * Ransomware Recall:   {metrics['recall']}%")
    print(f"  * Ransomware F1-Score: {metrics['f1_score']}%")
    print(f"  * ROC-AUC:             {metrics['roc_auc']}%")
    print(f"  * Confusion Matrix:    TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
    print("-" * 50)
    
    # 6. Export Artifacts
    metadata = {}
    if export_artifacts:
        print("\n[Step 6/6] Exporting Model V2 Artifacts...")
        model_file = MODELS_DIR / "xgb_ransomware_v2.json"
        meta_file = MODELS_DIR / "feature_meta_v2.json"
        preprocessor_file = MODELS_DIR / "preprocessor_v2.json"
        
        clf.save_model(str(model_file))
        print(f"  [+] Saved Model V2:     {model_file}")
        
        metadata = {
            "model_name": "RansomShield AI Behavioral Classifier (Real Sysmon Telemetry)",
            "model_version": "xgb_ransomware_v2",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "framework": f"xgboost-{xgb.__version__}",
            "random_seed": random_state,
            "dataset_info": {
                "name": "CSU-Ransomware-Data",
                "source": "https://github.com/CSCRC-SCREED/CSU-Ransomware-Data",
                "total_samples": len(df),
                "training_samples": len(X_train),
                "test_samples": len(X_test),
            },
            "feature_contract": get_v2_feature_contract_dict(),
            "feature_names": V2_FEATURE_NAMES,
            "feature_count": len(V2_FEATURE_NAMES),
            "label_mapping": V2_LABEL_MAPPING,
            "hyperparameters": model_params,
            "evaluation_metrics": metrics,
            "disclaimer": "Metrics represent evaluation on historical Windows Sysmon dynamic analysis telemetry.",
        }
        
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        print(f"  [+] Saved Metadata V2:  {meta_file}")
        
        with open(preprocessor_file, "w", encoding="utf-8") as f:
            json.dump(preprocessor.to_dict(), f, indent=2)
        print(f"  [+] Saved Preprocessor V2: {preprocessor_file}")
        
    return clf, metrics, metadata


def train_v1_benchmark_model(
    test_size: float = 0.20,
    random_state: int = 42,
    export_artifacts: bool = True,
) -> Tuple[xgb.XGBClassifier, Dict[str, Any], Dict[str, Any]]:
    """
    Trains the legacy Model V1 on the synthetic benchmark dataset.
    """
    ensure_models_dir()
    
    print("\n" + "=" * 70)
    print("RANSOMSHIELD AI — MODEL V1 TRAINING (SYNTHETIC BENCHMARK PROTOTYPE)")
    print("=" * 70)
    
    df = generate_benchmark_dataset()
    X_raw = df[V1_FEATURE_NAMES]
    y_raw = df["label"].values.astype(int)
    
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        X_raw, y_raw, test_size=test_size, random_state=random_state, stratify=y_raw
    )
    
    preprocessor = FeaturePreprocessor(feature_names=V1_FEATURE_NAMES, version="v1")
    preprocessor.fit(X_train_df)
    
    X_train = preprocessor.transform(X_train_df)
    X_test = preprocessor.transform(X_test_df)
    
    clf = xgb.XGBClassifier(
        n_estimators=140,
        max_depth=4,
        learning_rate=0.08,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=random_state,
        tree_method="hist",
    )
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    
    metrics = {
        "evaluation_type": "SYNTHETIC BENCHMARK EVALUATION",
        "accuracy": round(acc * 100, 2),
        "f1_score_macro": round(f1 * 100, 2),
    }
    
    if export_artifacts:
        model_file = MODELS_DIR / "xgb_ransomware_v1.json"
        meta_file = MODELS_DIR / "feature_meta.json"
        preprocessor_file = MODELS_DIR / "preprocessor.json"
        
        clf.save_model(str(model_file))
        
        metadata = {
            "model_name": "RansomShield AI Behavioral Classifier (Synthetic Benchmark)",
            "model_version": "xgb_ransomware_v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "feature_contract": get_v1_feature_contract_dict(),
            "feature_names": V1_FEATURE_NAMES,
            "feature_count": len(V1_FEATURE_NAMES),
            "label_mapping": V1_LABEL_MAPPING,
            "evaluation_metrics": metrics,
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        with open(preprocessor_file, "w", encoding="utf-8") as f:
            json.dump(preprocessor.to_dict(), f, indent=2)
            
    print(f"  [+] Model V1 exported: {acc * 100:.2f}% accuracy (Synthetic Benchmark)")
    return clf, metrics, metadata


def train_all():
    """Trains both Model V2 (Real Sysmon) and Model V1 (Benchmark)."""
    clf_v2, metrics_v2, meta_v2 = train_v2_real_model()
    clf_v1, metrics_v1, meta_v1 = train_v1_benchmark_model()
    print("\n" + "=" * 70)
    print("ALL MODELS TRAINED AND SAVED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    train_all()
