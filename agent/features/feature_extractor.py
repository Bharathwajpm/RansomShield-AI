"""
RansomShield AI — Real-Time Sliding Window Feature Extractor
Phase 2C: Sliding Window Feature Extractor & Live ML Inference

Extracts the exact 19 Model V2 behavioral feature vector from raw telemetry
events stored in the InMemoryTelemetryBuffer across 5s, 10s, and 30s sliding windows.
"""

import time
from typing import List, Dict, Any, Optional
import numpy as np

from agent.models.telemetry import (
    BaseTelemetryEvent,
    ProcessEvent,
    FileEvent,
    RegistryEvent,
    NetworkEvent,
    PipeEvent,
    SystemEvent,
    TelemetryEventType,
)
from agent.buffers.memory_buffer import InMemoryTelemetryBuffer
from agent.features.feature_window import FeatureWindow
from ml.features.feature_contract import V2_FEATURE_NAMES
from ml.features.entropy import calculate_shannon_entropy


class LiveFeatureExtractor:
    """
    Extracts the strictly ordered 19 Model V2 features from live telemetry events.
    """

    def __init__(self, buffer: InMemoryTelemetryBuffer):
        self.buffer = buffer

    def extract(self, window_seconds: int = 10, current_time: Optional[float] = None) -> Dict[str, float]:
        """
        Extracts the 19 Model V2 features for the specified window duration.
        """
        if current_time is None:
            current_time = time.time()

        events = self.buffer.get_events(window_seconds=float(window_seconds), current_time=current_time)
        return self._compute_features(events)

    def extract_window(self, window_seconds: int = 10, current_time: Optional[float] = None) -> FeatureWindow:
        """
        Extracts features and returns an encapsulated FeatureWindow object.
        """
        if current_time is None:
            current_time = time.time()

        events = self.buffer.get_events(window_seconds=float(window_seconds), current_time=current_time)
        features = self._compute_features(events)

        return FeatureWindow(
            window_seconds=window_seconds,
            start_time=current_time - float(window_seconds),
            end_time=current_time,
            event_count=len(events),
            features=features,
        )

    def extract_vector(self, window_seconds: int = 10, current_time: Optional[float] = None) -> np.ndarray:
        """
        Extracts features as a 1D numpy array strictly matching V2_FEATURE_NAMES ordering.
        """
        features_dict = self.extract(window_seconds=window_seconds, current_time=current_time)
        return np.array([features_dict[name] for name in V2_FEATURE_NAMES], dtype=np.float64)

    def extract_multi_window(
        self,
        windows: Optional[List[int]] = None,
        current_time: Optional[float] = None,
    ) -> Dict[int, Dict[str, float]]:
        """
        Extracts feature dictionaries across multiple sliding windows (e.g. 5s, 10s, 30s).
        """
        if windows is None:
            windows = [5, 10, 30]
        if current_time is None:
            current_time = time.time()

        results: Dict[int, Dict[str, float]] = {}
        for w in windows:
            results[w] = self.extract(window_seconds=w, current_time=current_time)
        return results

    def _compute_features(self, events: List[BaseTelemetryEvent]) -> Dict[str, float]:
        """
        Computes the exact 19 Model V2 features from a list of telemetry events.
        """
        # Event type counters
        file_delete_archived_count = 0
        file_created_count = 0
        file_creation_time_changed_count = 0
        pipe_created_count = 0
        process_create_count = 0
        registry_value_set_count = 0
        
        process_related_count = 0
        network_related_count = 0
        file_related_count = 0

        # Process metrics
        suspicious_paths = []
        system_executables = []
        path_lengths = []
        directory_depths = []
        process_name_lengths = []
        freq_ratios = []
        depth_diffs = []
        parent_system_execs = []

        # File metrics
        extension_similarities = []
        file_name_entropies = []

        for ev in events:
            ev_type = ev.event_type

            # --- PROCESS TELEMETRY ---
            if isinstance(ev, ProcessEvent) or ev_type == TelemetryEventType.ProcessCreate:
                process_related_count += 1
                if ev_type == TelemetryEventType.ProcessCreate:
                    process_create_count += 1

                if isinstance(ev, ProcessEvent):
                    if ev.is_suspicious_path is not None:
                        suspicious_paths.append(1 if ev.is_suspicious_path else 0)
                    if ev.is_system_executable is not None:
                        system_executables.append(1 if ev.is_system_executable else 0)
                    if ev.path_length is not None and ev.path_length > 0:
                        path_lengths.append(ev.path_length)
                    if ev.directory_depth is not None and ev.directory_depth > 0:
                        directory_depths.append(ev.directory_depth)
                    if ev.process_name_length is not None and ev.process_name_length > 0:
                        process_name_lengths.append(ev.process_name_length)
                    if ev.process_vs_parent_freq_ratio is not None:
                        freq_ratios.append(ev.process_vs_parent_freq_ratio)
                    if ev.executable_depth_diff is not None:
                        depth_diffs.append(ev.executable_depth_diff)
                    if ev.parent_is_system_executable is not None:
                        parent_system_execs.append(1 if ev.parent_is_system_executable else 0)

            # --- FILE TELEMETRY ---
            elif isinstance(ev, FileEvent) or ev_type in (
                TelemetryEventType.FileCreate,
                TelemetryEventType.FileModify,
                TelemetryEventType.FileDelete,
                TelemetryEventType.FileRename,
                TelemetryEventType.FileTimeChanged,
                TelemetryEventType.FileDeleteArchived,
            ):
                file_related_count += 1
                
                if ev_type == TelemetryEventType.FileCreate:
                    file_created_count += 1
                elif ev_type == TelemetryEventType.FileDeleteArchived:
                    file_delete_archived_count += 1
                elif ev_type == TelemetryEventType.FileTimeChanged:
                    file_creation_time_changed_count += 1
                elif ev_type == TelemetryEventType.FileDelete:
                    # Check if deleted file is an archive/backup
                    path_str = getattr(ev, "path", "")
                    if any(path_str.lower().endswith(ext) for ext in [".bak", ".zip", ".7z", ".rar", ".tar", ".gz", ".vss"]):
                        file_delete_archived_count += 1

                if isinstance(ev, FileEvent):
                    if ev.extension_similarity is not None:
                        extension_similarities.append(ev.extension_similarity)
                    if ev.file_name_entropy is not None and ev.file_name_entropy > 0.0:
                        file_name_entropies.append(ev.file_name_entropy)
                    elif ev.path:
                        import os
                        fname = os.path.basename(ev.path)
                        if fname:
                            file_name_entropies.append(calculate_shannon_entropy(fname))

            # --- REGISTRY TELEMETRY ---
            elif isinstance(ev, RegistryEvent) or ev_type == TelemetryEventType.RegistryValueSet:
                if ev_type == TelemetryEventType.RegistryValueSet:
                    registry_value_set_count += 1

            # --- NETWORK TELEMETRY ---
            elif isinstance(ev, NetworkEvent) or ev_type == TelemetryEventType.NetworkConnection:
                network_related_count += 1

            # --- PIPE TELEMETRY ---
            elif isinstance(ev, PipeEvent) or ev_type in (
                TelemetryEventType.PipeCreated,
                TelemetryEventType.PipeConnected,
            ):
                pipe_created_count += 1
                process_related_count += 1

            # --- SYSTEM & SYSMON TELEMETRY ---
            elif isinstance(ev, SystemEvent):
                sys_id = ev.sysmon_event_id
                if sys_id == 1:
                    process_create_count += 1
                    process_related_count += 1
                elif sys_id == 2:
                    file_creation_time_changed_count += 1
                    file_related_count += 1
                elif sys_id == 3:
                    network_related_count += 1
                elif sys_id == 11:
                    file_created_count += 1
                    file_related_count += 1
                elif sys_id in (23, 26):
                    file_delete_archived_count += 1
                    file_related_count += 1
                elif sys_id == 13:
                    registry_value_set_count += 1
                elif sys_id in (17, 18):
                    pipe_created_count += 1

        # Aggregate process-related metrics
        suspicious_path_val = 1.0 if any(s == 1 for s in suspicious_paths) else 0.0
        system_executable_val = 1.0 if any(s == 1 for s in system_executables) else 0.0
        path_length_val = float(np.mean(path_lengths)) if path_lengths else 0.0
        directory_depth_val = float(np.mean(directory_depths)) if directory_depths else 0.0
        process_name_length_val = float(np.mean(process_name_lengths)) if process_name_lengths else 0.0
        freq_ratio_val = float(np.mean(freq_ratios)) if freq_ratios else 0.0
        depth_diff_val = float(np.mean(depth_diffs)) if depth_diffs else 0.0
        parent_is_system_val = 1.0 if any(p == 1 for p in parent_system_execs) else 0.0

        # Aggregate file-related metrics
        extension_similarity_val = 1.0 if any(e == 1 for e in extension_similarities) else 0.0
        file_name_entropy_val = float(np.mean(file_name_entropies)) if file_name_entropies else 0.0

        # Build exact 19 Model V2 feature dictionary
        features: Dict[str, float] = {
            "File_Delete_archived": float(file_delete_archived_count),
            "File_created": float(file_created_count),
            "File_creation_time_changed": float(file_creation_time_changed_count),
            "Pipe_Created": float(pipe_created_count),
            "Process_Create": float(process_create_count),
            "Registry_value_set": float(registry_value_set_count),
            "process-related": float(process_related_count),
            "network-related": float(network_related_count),
            "file-related": float(file_related_count),
            "suspicious_path": suspicious_path_val,
            "system_executable": system_executable_val,
            "path_length": round(path_length_val, 2),
            "directory_depth": round(directory_depth_val, 2),
            "process_name_length": round(process_name_length_val, 2),
            "process_vs_parent_freq_ratio": round(freq_ratio_val, 4),
            "executable_depth_diff": round(depth_diff_val, 2),
            "parent_is_system_executable": parent_is_system_val,
            "extension_similarity": extension_similarity_val,
            "file_name_entropy": round(file_name_entropy_val, 4),
        }

        return features
