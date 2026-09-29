"""
RansomShield AI — Feature Contract (V1 Benchmark & V2 Real Sysmon Telemetry)
Phase 1: Machine Learning & Feature Pipeline

Defines the exact model feature specifications, data types, telemetry sources,
and mapping classifications for both:
- Model V2: Real CSU Sysmon Telemetry Dataset (19 features)
- Model V1: Prototype Synthetic Benchmark Dataset (12 features)
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import enum


class TelemetrySource(str, enum.Enum):
    WATCHDOG = "watchdog"
    PSUTIL = "psutil"
    SYSMON = "Sysmon"
    WINDOWS_EVENT_LOG = "Windows Event Log"
    HYBRID = "Hybrid"


class MappingClassification(str, enum.Enum):
    DIRECT = "DIRECT"              # Directly provided by collector event
    DERIVED = "DERIVED"            # Calculated via deterministic math/heuristic from collector
    APPROXIMATION = "APPROXIMATION"# Approximation of hardware/kernel counter
    UNAVAILABLE = "UNAVAILABLE"    # Not supported


class DataType(str, enum.Enum):
    FLOAT = "float64"
    INT = "int64"
    BOOL = "bool"


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    description: str
    data_type: DataType
    source: TelemetrySource
    classification: MappingClassification
    calculation: str
    training_availability: str
    live_agent_availability: str
    category: str


# =====================================================================
# V2 REAL SYSMON TELEMETRY FEATURE CONTRACT (19 Features)
# Source: CSU-Ransomware-Data (SCReeD Project / Charles Sturt University)
# Derived from 413,556 raw Windows Sysmon events
# =====================================================================

V2_FEATURE_DEFINITIONS: List[FeatureDefinition] = [
    FeatureDefinition(
        name="File_Delete_archived",
        description="Sysmon Event 23/26 indicator for file deletion and archiving operations.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 23 (FileDelete) or Event 26 (FileDeleteDetected)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via win32evtlog to Microsoft-Windows-Sysmon/Operational",
        category="File Activity",
    ),
    FeatureDefinition(
        name="File_created",
        description="Sysmon Event 11 indicator for file creation operations.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 11 (FileCreate)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via win32evtlog to Sysmon Event 11",
        category="File Activity",
    ),
    FeatureDefinition(
        name="File_creation_time_changed",
        description="Sysmon Event 2 indicator for file creation time alteration (timestomping).",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 2 (FileCreateTime)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via win32evtlog to Sysmon Event 2",
        category="File Activity",
    ),
    FeatureDefinition(
        name="Pipe_Created",
        description="Sysmon Event 17/18 indicator for named pipe creation and connection.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 17 (PipeCreated) or 18 (PipeConnected)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via win32evtlog to Sysmon Event 17/18",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="Process_Create",
        description="Sysmon Event 1 indicator for new process execution.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 1 (ProcessCreate)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via win32evtlog to Sysmon Event 1 or psutil process listener",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="Registry_value_set",
        description="Sysmon Event 13 indicator for registry key modification.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 13 (RegistryValueSet)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via win32evtlog to Sysmon Event 13",
        category="System Behavior",
    ),
    FeatureDefinition(
        name="process-related",
        description="Aggregate indicator flag for process lifecycle operations.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DERIVED,
        calculation="Aggregated count of process-related Sysmon events in time window",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Aggregated in agent sliding window buffer",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="network-related",
        description="Sysmon Event 3 indicator for outbound network connections.",
        data_type=DataType.INT,
        source=TelemetrySource.SYSMON,
        classification=MappingClassification.DIRECT,
        calculation="Sysmon Event ID 3 (NetworkConnect) or psutil.net_connections()",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Subscribed via Sysmon Event 3",
        category="Network Behavior",
    ),
    FeatureDefinition(
        name="file-related",
        description="Aggregate indicator flag for file I/O operations.",
        data_type=DataType.INT,
        source=TelemetrySource.WATCHDOG,
        classification=MappingClassification.DERIVED,
        calculation="Aggregated count of file-related events in time window",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Aggregated via watchdog / Sysmon event queues",
        category="File Activity",
    ),
    FeatureDefinition(
        name="suspicious_path",
        description="Binary flag (1/0) indicating process execution from user writable or temporary paths (AppData/Temp/Downloads).",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="1 if exe path starts with AppData, Temp, Downloads or Users directory else 0",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Evaluated from psutil.Process(pid).exe()",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="system_executable",
        description="Binary flag (1/0) indicating process execution from Windows System directories.",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="1 if exe path starts with C:\\Windows\\System32 else 0",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Evaluated from psutil.Process(pid).exe()",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="path_length",
        description="Character string length of the executable path.",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="len(psutil.Process(pid).exe())",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from psutil.Process(pid).exe()",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="directory_depth",
        description="Nesting depth (count of path separators) of the executable directory.",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="path.count('\\')",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from psutil process path string",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="process_name_length",
        description="Character string length of the process binary name.",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="len(psutil.Process(pid).name())",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from psutil.Process(pid).name()",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="process_vs_parent_freq_ratio",
        description="Relative execution frequency ratio between candidate process and parent process.",
        data_type=DataType.FLOAT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="freq(child_proc) / freq(parent_proc)",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from agent process history table",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="executable_depth_diff",
        description="Directory nesting depth difference between parent process and child process.",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="abs(depth(child_exe) - depth(parent_exe))",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from psutil parent-child process tree",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="parent_is_system_executable",
        description="Binary flag (1/0) indicating whether the parent process is a verified system binary.",
        data_type=DataType.INT,
        source=TelemetrySource.PSUTIL,
        classification=MappingClassification.DERIVED,
        calculation="1 if parent exe is in C:\\Windows\\System32 else 0",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from psutil parent process inspection",
        category="Process Behavior",
    ),
    FeatureDefinition(
        name="extension_similarity",
        description="Metric indicating file extension similarity or transformation pattern.",
        data_type=DataType.INT,
        source=TelemetrySource.WATCHDOG,
        classification=MappingClassification.DERIVED,
        calculation="1 if file rename alters original extension to non-standard suffix else 0",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated from watchdog FileMovedEvent extension delta",
        category="File Activity",
    ),
    FeatureDefinition(
        name="file_name_entropy",
        description="Shannon entropy of touched file name and path strings.",
        data_type=DataType.FLOAT,
        source=TelemetrySource.WATCHDOG,
        classification=MappingClassification.DERIVED,
        calculation="Shannon entropy calculated on file path strings",
        training_availability="Present in CSU-Ransomware-Data",
        live_agent_availability="Calculated via Shannon entropy on watchdog file event paths",
        category="File Activity",
    ),
]

V2_FEATURE_NAMES: List[str] = [f.name for f in V2_FEATURE_DEFINITIONS]
V2_LABEL_MAPPING = {
    0: "Goodware",
    1: "Ransomware",
}

# Alias for active default model (V2)
FEATURE_DEFINITIONS = V2_FEATURE_DEFINITIONS
FEATURE_NAMES = V2_FEATURE_NAMES
LABEL_MAPPING = V2_LABEL_MAPPING


# =====================================================================
# V1 LEGACY BENCHMARK FEATURE CONTRACT (12 Features)
# =====================================================================

V1_FEATURE_NAMES: List[str] = [
    "file_modification_rate",
    "file_rename_rate",
    "file_deletion_rate",
    "write_entropy_avg",
    "high_entropy_ratio",
    "cpu_usage_pct",
    "memory_usage_pct",
    "process_creation_rate",
    "unsigned_proc_ratio",
    "registry_write_rate",
    "network_connection_count",
    "shadow_copy_tamper",
]

V1_LABEL_MAPPING = {
    0: "BENIGN",
    1: "SUSPICIOUS",
    2: "RANSOMWARE",
}


def get_v2_feature_contract_dict() -> Dict[str, Any]:
    """Returns the V2 feature contract dictionary for metadata export."""
    return {
        "version": "v2",
        "dataset_name": "CSU-Ransomware-Data (SCReeD)",
        "source": "https://github.com/CSCRC-SCREED/CSU-Ransomware-Data",
        "features": [
            {
                "name": f.name,
                "description": f.description,
                "data_type": f.data_type.value,
                "source": f.source.value,
                "classification": f.classification.value,
                "calculation": f.calculation,
                "training_availability": f.training_availability,
                "live_agent_availability": f.live_agent_availability,
                "category": f.category,
            }
            for f in V2_FEATURE_DEFINITIONS
        ],
        "feature_names": V2_FEATURE_NAMES,
        "feature_count": len(V2_FEATURE_NAMES),
        "label_mapping": V2_LABEL_MAPPING,
    }


def get_v1_feature_contract_dict() -> Dict[str, Any]:
    """Returns the legacy V1 feature contract dictionary."""
    return {
        "version": "v1",
        "dataset_name": "Synthetic Prototype Benchmark",
        "feature_names": V1_FEATURE_NAMES,
        "feature_count": len(V1_FEATURE_NAMES),
        "label_mapping": V1_LABEL_MAPPING,
    }


if __name__ == "__main__":
    import json
    print(f"RansomShield AI V2 Feature Contract (CSU Sysmon) — Total Features: {len(V2_FEATURE_NAMES)}")
    print(json.dumps(get_v2_feature_contract_dict(), indent=2))
