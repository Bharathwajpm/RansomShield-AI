"""
RansomShield AI — Dataset Loader & Validator (V2 Real & V1 Benchmark)
Phase 1: Machine Learning & Feature Pipeline

Loads and validates the verified real-world CSU Sysmon ransomware telemetry dataset,
with fallback support for the synthetic benchmark dataset.
"""

import os
import urllib.request
from pathlib import Path
from typing import Tuple, Dict, Any, Optional, List
import numpy as np
import pandas as pd

from ml.features.feature_contract import (
    V2_FEATURE_NAMES,
    V1_FEATURE_NAMES,
    V2_LABEL_MAPPING,
    V1_LABEL_MAPPING,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"
RAW_DATA_DIR = DATASETS_DIR / "raw"
PROCESSED_DATA_DIR = DATASETS_DIR / "processed"

CSU_DATASET_URL = (
    "https://raw.githubusercontent.com/CSCRC-SCREED/CSU-Ransomware-Data/main/dataset/Ransomware_Data.csv"
)
CSU_DATASET_LOCAL_PATH = RAW_DATA_DIR / "csu_sysmon_ransomware_data.csv"
SYNTHETIC_DATASET_LOCAL_PATH = RAW_DATA_DIR / "ransomware_behavioral_dataset.csv"


def ensure_directories():
    """Ensures datasets directories exist."""
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)


def download_csu_dataset_if_missing() -> Path:
    """Downloads the verified CSU Sysmon Ransomware dataset if not already present locally."""
    ensure_directories()
    if not CSU_DATASET_LOCAL_PATH.exists():
        print(f"[+] Downloading verified CSU Sysmon Ransomware Dataset from {CSU_DATASET_URL}...")
        urllib.request.urlretrieve(CSU_DATASET_URL, CSU_DATASET_LOCAL_PATH)
        print(f"[+] Download complete: {CSU_DATASET_LOCAL_PATH} ({os.path.getsize(CSU_DATASET_LOCAL_PATH)} bytes)")
    return CSU_DATASET_LOCAL_PATH


def validate_csu_dataset(df: pd.DataFrame) -> Dict[str, Any]:
    """Validates the schema, columns, missing values, and labels of the CSU Sysmon dataset."""
    missing_feats = [f for f in V2_FEATURE_NAMES if f not in df.columns]
    
    report = {
        "dataset_name": "CSU-Ransomware-Data (SCReeD)",
        "provenance": "Cyber Security Cooperative Research Centre (CSCRC) / Charles Sturt University",
        "url": "https://github.com/CSCRC-SCREED/CSU-Ransomware-Data",
        "num_rows": len(df),
        "num_columns": len(df.columns),
        "missing_values": int(df.isnull().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "class_distribution": df["Ware Type"].value_counts().to_dict() if "Ware Type" in df.columns else {},
        "missing_features": missing_feats,
        "status": "VALID" if not missing_feats else "INVALID",
    }
    return report


def load_real_csu_dataset(
    deduplicate: bool = True,
    max_samples: Optional[int] = None,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Loads and preprocesses the verified CSU Sysmon ransomware telemetry dataset.
    
    Args:
        deduplicate: If True, operates on unique behavioral feature vectors (36,485 samples).
                     If False, loads all 352,876 raw event observation rows.
        max_samples: Optional cap on row count for rapid validation.
    """
    path = download_csu_dataset_if_missing()
    df = pd.read_csv(path)
    
    # Map 'Ware Type' to standard binary integer label: 0 = Goodware, 1 = Ransomware
    df["label"] = df["Ware Type"].apply(lambda x: 1 if str(x).strip().lower() in ("ransom", "ransomware") else 0)
    
    validation = validate_csu_dataset(df)
    
    if deduplicate:
        # Deduplicate on the 19 feature columns + label
        df = df.drop_duplicates(subset=V2_FEATURE_NAMES + ["label"]).reset_index(drop=True)
        validation["deduplicated_rows"] = len(df)
        validation["deduplicated_class_distribution"] = df["label"].value_counts().to_dict()
        
    if max_samples and len(df) > max_samples:
        df = df.sample(n=max_samples, random_state=42).reset_index(drop=True)
        
    return df, validation


def generate_benchmark_dataset(
    n_samples: int = 12000,
    random_state: int = 42,
    output_path: Optional[Path] = None,
) -> pd.DataFrame:
    """Generates the V1 prototype synthetic benchmark dataset for pipeline and unit testing."""
    np.random.seed(random_state)
    n_benign = int(n_samples * 0.70)
    n_suspicious = int(n_samples * 0.15)
    n_ransomware = n_samples - n_benign - n_suspicious
    
    rows = []
    for _ in range(n_benign):
        rows.append({
            "file_modification_rate": round(float(np.random.gamma(2.0, 6.0)), 2),
            "file_rename_rate": round(float(np.random.exponential(1.5)), 2),
            "file_deletion_rate": round(float(np.random.exponential(1.2)), 2),
            "write_entropy_avg": round(float(np.clip(np.random.normal(3.8, 0.4), 1.0, 6.2)), 4),
            "high_entropy_ratio": round(float(np.random.beta(0.5, 25.0)), 4),
            "cpu_usage_pct": round(float(np.clip(np.random.gamma(3.0, 6.0), 2.0, 65.0)), 2),
            "memory_usage_pct": round(float(np.clip(np.random.normal(14.0, 5.0), 4.0, 45.0)), 2),
            "process_creation_rate": round(float(np.random.poisson(3.5)), 2),
            "unsigned_proc_ratio": round(float(np.random.beta(0.2, 10.0)), 4),
            "registry_write_rate": round(float(np.random.poisson(5.0)), 2),
            "network_connection_count": round(float(np.random.poisson(8.0)), 2),
            "shadow_copy_tamper": 0.0,
            "label": 0,
            "label_name": "BENIGN",
        })
    for _ in range(n_suspicious):
        rows.append({
            "file_modification_rate": round(float(np.random.gamma(8.0, 18.0)), 2),
            "file_rename_rate": round(float(np.random.gamma(4.0, 8.0)), 2),
            "file_deletion_rate": round(float(np.random.gamma(3.0, 5.0)), 2),
            "write_entropy_avg": round(float(np.clip(np.random.normal(5.8, 0.6), 3.5, 7.1)), 4),
            "high_entropy_ratio": round(float(np.random.uniform(0.05, 0.35)), 4),
            "cpu_usage_pct": round(float(np.random.uniform(40.0, 85.0)), 2),
            "memory_usage_pct": round(float(np.random.uniform(20.0, 60.0)), 2),
            "process_creation_rate": round(float(np.random.poisson(12.0)), 2),
            "unsigned_proc_ratio": round(float(np.random.uniform(0.2, 0.7)), 4),
            "registry_write_rate": round(float(np.random.poisson(22.0)), 2),
            "network_connection_count": round(float(np.random.poisson(25.0)), 2),
            "shadow_copy_tamper": 0.0,
            "label": 1,
            "label_name": "SUSPICIOUS",
        })
    for _ in range(n_ransomware):
        rows.append({
            "file_modification_rate": round(float(np.random.gamma(25.0, 45.0)), 2),
            "file_rename_rate": round(float(np.random.gamma(20.0, 35.0)), 2),
            "file_deletion_rate": round(float(np.random.gamma(8.0, 12.0)), 2),
            "write_entropy_avg": round(float(np.clip(np.random.normal(7.75, 0.15), 7.25, 7.99)), 4),
            "high_entropy_ratio": round(float(np.random.uniform(0.70, 0.98)), 4),
            "cpu_usage_pct": round(float(np.random.uniform(70.0, 99.0)), 2),
            "memory_usage_pct": round(float(np.random.uniform(30.0, 85.0)), 2),
            "process_creation_rate": round(float(np.random.poisson(18.0)), 2),
            "unsigned_proc_ratio": round(float(np.random.uniform(0.75, 1.0)), 4),
            "registry_write_rate": round(float(np.random.poisson(65.0)), 2),
            "network_connection_count": round(float(np.random.poisson(35.0)), 2),
            "shadow_copy_tamper": 1.0,
            "label": 2,
            "label_name": "RANSOMWARE",
        })
        
    df = pd.DataFrame(rows).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    if output_path is None:
        ensure_directories()
        output_path = SYNTHETIC_DATASET_LOCAL_PATH
    df.to_csv(output_path, index=False)
    return df


def load_dataset(
    dataset_path: Optional[str] = None,
    dataset_version: str = "v2",
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Unified dataset loader.
    Defaults to 'v2' (verified CSU Sysmon dataset).
    """
    if dataset_version == "v2" or (dataset_path and "csu" in str(dataset_path).lower()):
        return load_real_csu_dataset()
    else:
        # Load or generate V1 synthetic benchmark
        ensure_directories()
        if not SYNTHETIC_DATASET_LOCAL_PATH.exists():
            generate_benchmark_dataset()
        df = pd.read_csv(SYNTHETIC_DATASET_LOCAL_PATH)
        return df, {"dataset_name": "V1 Synthetic Benchmark", "num_rows": len(df), "status": "VALID"}


if __name__ == "__main__":
    df_v2, val_v2 = load_real_csu_dataset()
    print("=== RansomShield AI Dataset Loader Report (V2 Real Sysmon) ===")
    print(f"Dataset Name:       {val_v2['dataset_name']}")
    print(f"Original Source:    {val_v2['provenance']}")
    print(f"Total Unique Rows:  {len(df_v2)}")
    print(f"Features:           {len(V2_FEATURE_NAMES)}")
    print(f"Class Distribution: {val_v2['deduplicated_class_distribution']}")
    print(f"Validation Status:  {val_v2['status']}")
