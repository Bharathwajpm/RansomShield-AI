# RansomShield AI — Dataset Selection & Evaluation

**Document Version:** 2.0.0  
**Phase:** Phase 1 ML Pipeline Refinement  
**Subject:** Selection of Verified External Telemetry Dataset for Model V2  

---

## 1. Selection Criteria & Requirements

To replace the prototype synthetic benchmark dataset with an authentic, scientifically defensible dataset, we evaluated candidates against six mandatory criteria:

1. **Behavioral Telemetry Grounding:** Must represent dynamic, behavioral host telemetry (file modifications, process trees, network sockets, registry writes, or Sysmon events) rather than static PE binary opcodes or byte histograms.
2. **Windows Collector Compatibility:** Features must be realistically collectable by the future Windows Monitoring Agent (`psutil`, `watchdog`, `win32evtlog` for Sysmon and Event Logs).
3. **Verified Provenance:** Must originate from a credible academic, government, or open-science institution with documented research methodology and accessible raw data.
4. **Class Realism & Overlap:** Must exhibit natural class overlap, realistic variance, and non-trivial decision boundaries (avoiding artificial 100% separable distributions).
5. **Format & Integrity:** Must be structured tabular data (CSV/Parquet) with clean labels and verifiable event counts.
6. **Reproducibility:** Must be freely accessible to researchers without proprietary NDA restrictions.

---

## 2. Candidates Evaluated

| Dataset Candidate | Source / Institution | Data Modality | Telemetry Compatibility | Decision & Rationale |
|---|---|---|---|---|
| **CSU-Ransomware-Data (SCReeD)** | Charles Sturt University / Cyber Security CRC | 413,556 raw Sysmon events / 19 engineered features | **Direct (100%)** — maps to Sysmon Event IDs 1, 2, 3, 11, 13, 17, 23 and psutil/watchdog | **SELECTED** — Best alignment with endpoint telemetry architecture. |
| **RanSAP (2022/2024)** | Academic Research (Manabu Hirano) | Block-level storage I/O traces | **Partial (60%)** — Focuses on SCSI/SATA disk driver blocks, less on process/registry | Candidate for secondary storage benchmarking. |
| **UGRansome** | University of Granada | Network NetFlow / IP flow logs | **Partial (40%)** — Network layer only; lacks file and registry telemetry | Lacks endpoint-level process and file details. |
| **Kaggle API Call Sequences** | Various Cuckoo Sandbox dumps | Windows API sequences | **Indirect (50%)** — Sequence-based API hooks; harder to compute in lightweight kernel/event collector | High CPU overhead for live endpoint agents. |

---

## 3. Selected Dataset: CSU-Ransomware-Data (SCReeD)

- **Official Repository:** `https://github.com/CSCRC-SCREED/CSU-Ransomware-Data`
- **Primary Data File:** `dataset/Ransomware_Data.csv` (Saved locally as `datasets/raw/csu_sysmon_ransomware_data.csv`)
- **Total Observations:** 352,876 event rows
- **Labels:** `Goodware` (0) and `Ransomware` (1)
- **Features:** 19 telemetry features derived directly from Windows Sysmon events and file/process metadata.

---

## 4. Feature Mapping Matrix (V2 Real Feature Contract)

| Feature | Windows Source | Classification | Role in Ransomware Detection |
|---|---|---|---|
| `File_Delete_archived` | Sysmon Event 23/26 | **DIRECT** | Ransomware deleting backups or original unencrypted files |
| `File_created` | Sysmon Event 11 | **DIRECT** | Creation of encrypted files or ransom notes |
| `File_creation_time_changed` | Sysmon Event 2 | **DIRECT** | Timestomping evasion techniques |
| `Pipe_Created` | Sysmon Event 17/18 | **DIRECT** | Inter-process communication and privilege escalation |
| `Process_Create` | Sysmon Event 1 | **DIRECT** | Execution of malicious payload or shadow copy killers |
| `Registry_value_set` | Sysmon Event 13 | **DIRECT** | Persistence in Run keys or safe mode tampering |
| `process-related` | Sysmon / psutil | **DERIVED** | Aggregate process creation activity |
| `network-related` | Sysmon Event 3 | **DIRECT** | Command & Control communication / exfiltration |
| `file-related` | watchdog / Sysmon | **DERIVED** | Mass file I/O operations |
| `suspicious_path` | psutil / Sysmon 1 | **DERIVED** | Execution from `AppData`, `Temp`, `Downloads` |
| `system_executable` | psutil / Sysmon 1 | **DERIVED** | Binary located in `C:\Windows\System32` |
| `path_length` | psutil | **DERIVED** | Anomaly indicator for deeply nested obfuscated paths |
| `directory_depth` | psutil | **DERIVED** | Directory tree depth |
| `process_name_length` | psutil | **DERIVED** | Randomly generated / obfuscated process names |
| `process_vs_parent_freq_ratio`| psutil | **DERIVED** | Unusual parent-child process relationships |
| `executable_depth_diff` | psutil | **DERIVED** | Discrepancy between parent and child directory depths |
| `parent_is_system_executable`| psutil | **DERIVED** | Legitimate system parent vs untrusted parent |
| `extension_similarity` | watchdog | **DERIVED** | Extension manipulation (e.g. `.docx` -> `.lockbit`) |
| `file_name_entropy` | watchdog | **DERIVED** | Shannon entropy of modified file names |
