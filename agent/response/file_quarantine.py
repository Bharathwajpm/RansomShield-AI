"""
RansomShield AI — Safe File Quarantine Handler
Phase 4: Defensive Response & Endpoint Containment

Provides reversible, non-destructive file quarantine with pre/post SHA-256
cryptographic verification, path traversal defense, and sidecar metadata tracking.
"""

import os
import json
import time
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from agent.response.action_models import (
    ActionResult,
    ResponseActionStatus,
    VerificationStatus,
)

logger = logging.getLogger("RansomShield.Response.Quarantine")

# Protected system paths that must NEVER be quarantined
PROTECTED_SYSTEM_PATHS = (
    "\\windows\\system32",
    "\\windows\\syswow64",
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
)


def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Calculates SHA-256 hash of a file in streaming chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class FileQuarantineHandler:
    """
    Manages safe isolation and quarantine of suspicious or ransomware artifacts.
    Never deletes files directly; safely moves them with cryptographic auditing.
    """

    def __init__(self, quarantine_dir: str = "data/quarantine", dry_run: bool = True):
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.dry_run = dry_run
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def validate_path(self, target_path: str) -> Tuple[bool, str, str]:
        """
        Validates target file path against directory traversal, UNC network shares,
        null bytes, and protected system files.
        Returns (is_valid, normalized_path, error_message).
        """
        if not target_path or not isinstance(target_path, str) or not target_path.strip():
            return False, "", "Empty file path provided."

        raw = target_path.strip()

        # Disallow null bytes (null byte injection)
        if "\x00" in raw or "\0" in raw:
            return False, "", "Null byte detected in file path."

        # Disallow UNC network share paths (\\server\share or //server/share)
        if raw.startswith(("\\\\", "//")):
            return False, "", "UNC network share paths are forbidden for quarantine."

        # Disallow directory traversal indicators
        if ".." in raw.replace("/", "\\").split("\\"):
            return False, "", "Directory traversal ('..') detected in path."

        normalized = os.path.normpath(raw)

        # Disallow relative traversal remaining after normpath
        if ".." in normalized.split(os.sep):
            return False, normalized, "Directory traversal ('..') detected in path."

        # Check protected OS directories
        lower_norm = normalized.lower()
        for protected in PROTECTED_SYSTEM_PATHS:
            if protected in lower_norm:
                return False, normalized, f"Target path points inside protected system directory: {protected}"

        return True, normalized, ""

    def quarantine_file(
        self,
        file_path: str,
        action_id: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        dry_run: Optional[bool] = None,
    ) -> ActionResult:
        """
        Quarantines a file by calculating pre-hash, moving it to quarantine store,
        and cryptographically verifying the destination file.
        """
        start_time = time.time()
        effective_dry_run = self.dry_run if dry_run is None else dry_run

        # Step 1: Validate path security
        is_valid, clean_path, error_msg = self.validate_path(file_path)
        if not is_valid:
            logger.warning(f"[QUARANTINE_REFUSED] Invalid path '{file_path}': {error_msg}")
            return ActionResult(
                status=ResponseActionStatus.REFUSED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Refused: {error_msg}",
                details={"target_path": file_path, "reason": error_msg},
            )

        # Step 2: Verify file exists
        if not os.path.isfile(clean_path):
            logger.warning(f"[QUARANTINE_FAILED] File not found: {clean_path}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"File not found: {clean_path}",
                details={"target_path": clean_path, "not_found": True},
            )

        # Step 3: Compute pre-quarantine SHA-256
        try:
            pre_hash = compute_sha256(clean_path)
        except Exception as e:
            logger.error(f"[QUARANTINE_FAILED] Failed to hash '{clean_path}': {e}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Could not hash target file: {e}",
                details={"target_path": clean_path, "error": str(e)},
            )

        # Step 4: Verify expected hash (if provided)
        if expected_sha256 and expected_sha256.lower() != pre_hash.lower():
            logger.warning(
                f"[QUARANTINE_REFUSED] Hash mismatch for '{clean_path}'. Expected: {expected_sha256}, Actual: {pre_hash}"
            )
            return ActionResult(
                status=ResponseActionStatus.REFUSED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Refused: SHA-256 mismatch. Expected {expected_sha256}, found {pre_hash}",
                details={"expected_sha256": expected_sha256, "actual_sha256": pre_hash},
            )

        # Step 5: Dry-Run execution check
        if effective_dry_run:
            logger.info(f"[DRY_RUN] Validated quarantine for '{clean_path}' (SHA-256: {pre_hash}). Skipping live move.")
            return ActionResult(
                status=ResponseActionStatus.SUCCESS,
                verification_status=VerificationStatus.VERIFIED_SUCCESS,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"[DRY_RUN] File validated for quarantine. Hash: {pre_hash}",
                details={
                    "target_path": clean_path,
                    "sha256": pre_hash,
                    "quarantine_dir": self.quarantine_dir,
                    "dry_run": True,
                },
            )

        # Step 6: Live Quarantine Move
        dest_filename = f"{pre_hash}.quarantine"
        dest_path = os.path.join(self.quarantine_dir, dest_filename)
        sidecar_path = os.path.join(self.quarantine_dir, f"{pre_hash}.json")

        try:
            # Move file to quarantine vault
            shutil.move(clean_path, dest_path)

            # Write sidecar metadata
            metadata = {
                "action_id": action_id or "manual",
                "original_path": clean_path,
                "quarantined_at": time.time(),
                "sha256": pre_hash,
                "file_size": os.path.getsize(dest_path),
            }
            with open(sidecar_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            # Step 7: Post-Quarantine Verification
            source_gone = not os.path.exists(clean_path)
            dest_exists = os.path.isfile(dest_path)
            dest_hash = compute_sha256(dest_path) if dest_exists else ""
            hash_verified = (dest_hash.lower() == pre_hash.lower())

            if source_gone and dest_exists and hash_verified:
                logger.info(f"[QUARANTINE_SUCCESS] Successfully quarantined '{clean_path}' to '{dest_path}'")
                return ActionResult(
                    status=ResponseActionStatus.SUCCESS,
                    verification_status=VerificationStatus.VERIFIED_SUCCESS,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message=f"Successfully quarantined file to {dest_path}",
                    details={
                        "original_path": clean_path,
                        "quarantine_path": dest_path,
                        "sha256": dest_hash,
                    },
                )
            else:
                logger.error(
                    f"[QUARANTINE_VERIFICATION_FAILED] source_gone={source_gone}, dest_exists={dest_exists}, hash_verified={hash_verified}"
                )
                return ActionResult(
                    status=ResponseActionStatus.FAILED,
                    verification_status=VerificationStatus.VERIFIED_FAILURE,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message="Quarantine verification failed: destination file hash mismatch or source still exists.",
                    details={
                        "source_gone": source_gone,
                        "dest_exists": dest_exists,
                        "hash_verified": hash_verified,
                    },
                )

        except Exception as e:
            logger.exception(f"Unexpected error quarantining '{clean_path}': {e}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Error executing quarantine: {e}",
                details={"target_path": clean_path, "error": str(e)},
            )
