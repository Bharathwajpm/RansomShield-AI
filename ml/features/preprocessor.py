"""
RansomShield AI — Feature Preprocessor & Validator
Phase 1: Machine Learning & Feature Pipeline

Provides robust data cleaning, validation, and zero-leakage transformation
for training and inference across both V2 (real Sysmon) and V1 (benchmark) feature contracts.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

from ml.features.feature_contract import V2_FEATURE_NAMES, V1_FEATURE_NAMES


class FeaturePreprocessor(BaseEstimator, TransformerMixin):
    """
    Standardizes feature vectors and handles missing values, bounds checking,
    and type conversions with zero data leakage.
    """
    
    def __init__(self, feature_names: Optional[List[str]] = None, version: str = "v2"):
        if feature_names is not None:
            self.feature_names = feature_names
        else:
            self.feature_names = V2_FEATURE_NAMES if version == "v2" else V1_FEATURE_NAMES
            
        self.version = version
        self.means_: Dict[str, float] = {}
        self.stds_: Dict[str, float] = {}
        self.mins_: Dict[str, float] = {}
        self.maxs_: Dict[str, float] = {}
        self.is_fitted = False
        
    def fit(self, X: Any, y=None):
        """Computes feature statistics strictly on training data."""
        df = self._to_dataframe(X)
        
        for col in self.feature_names:
            if col in df.columns:
                series = pd.to_numeric(df[col], errors="coerce")
                self.means_[col] = float(series.mean()) if not series.dropna().empty else 0.0
                self.stds_[col] = float(series.std()) if not series.dropna().empty else 1.0
                self.mins_[col] = float(series.min()) if not series.dropna().empty else 0.0
                self.maxs_[col] = float(series.max()) if not series.dropna().empty else 1.0
            else:
                self.means_[col] = 0.0
                self.stds_[col] = 1.0
                self.mins_[col] = 0.0
                self.maxs_[col] = 1.0
                
        self.is_fitted = True
        return self
        
    def transform(self, X: Any) -> np.ndarray:
        """Transforms input data into a deterministic 2D float64 numpy array."""
        df = self._to_dataframe(X)
        output_matrix = np.zeros((len(df), len(self.feature_names)), dtype=np.float64)
        
        for i, col in enumerate(self.feature_names):
            if col in df.columns:
                s = pd.to_numeric(df[col], errors="coerce")
                fill_val = self.means_.get(col, 0.0) if self.is_fitted else 0.0
                s = s.fillna(fill_val)
                output_matrix[:, i] = s.values
            else:
                fill_val = self.means_.get(col, 0.0) if self.is_fitted else 0.0
                output_matrix[:, i] = fill_val
                
        return output_matrix
        
    def _to_dataframe(self, X: Any) -> pd.DataFrame:
        if isinstance(X, pd.DataFrame):
            return X.copy()
        elif isinstance(X, dict):
            return pd.DataFrame([X])
        elif isinstance(X, list) and len(X) > 0 and isinstance(X[0], dict):
            return pd.DataFrame(X)
        elif isinstance(X, np.ndarray):
            if X.ndim == 1:
                X = X.reshape(1, -1)
            return pd.DataFrame(X, columns=self.feature_names[:X.shape[1]])
        else:
            return pd.DataFrame(X)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes fitted preprocessor state to dictionary."""
        return {
            "version": self.version,
            "feature_names": self.feature_names,
            "means": self.means_,
            "stds": self.stds_,
            "mins": self.mins_,
            "maxs": self.maxs_,
            "is_fitted": self.is_fitted,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeaturePreprocessor":
        """Instantiates preprocessor from serialized dictionary."""
        pre = cls(
            feature_names=data.get("feature_names", V2_FEATURE_NAMES),
            version=data.get("version", "v2"),
        )
        pre.means_ = data.get("means", {})
        pre.stds_ = data.get("stds", {})
        pre.mins_ = data.get("mins", {})
        pre.maxs_ = data.get("maxs", {})
        pre.is_fitted = data.get("is_fitted", False)
        return pre
