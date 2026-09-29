"""
RansomShield AI — Process Response Handler
Phase 4: Defensive Response & Endpoint Containment

Implements safe, verified process termination with strict guards against
terminating protected operating system binaries, PID reuse detection,
and dry-run safety.
"""

import os
import time
import logging
from typing import Dict, Any, Optional, Set
import psutil

from agent.response.action_models import (
    ResponseAction,
    ActionResult,
    ResponseActionStatus,
    VerificationStatus,
)

logger = logging.getLogger("RansomShield.Response.Process")

# Critical Windows and core system processes that must NEVER be terminated
PROTECTED_PROCESS_NAMES: Set[str] = {
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "system",
    "registry",
    "ransomshield",
    "python.exe",  # When running the agent itself
}

PROTECTED_PIDS: Set[int] = {0, 4}


class ProcessResponseHandler:
    """
    Handles process termination containment actions with strict safety invariants.
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        # Add current agent process PID to protected list
        self._current_pid = os.getpid()

    def is_protected(self, pid: int, process_name: Optional[str] = None) -> Tuple_Bool_Str:
        """
        Validates if a PID or process name is protected by defensive invariants.
        Returns (is_protected, reason).
        """
        if pid in PROTECTED_PIDS:
            return True, f"PID {pid} is a protected core system process."

        if pid == self._current_pid:
            return True, f"PID {pid} is the RansomShield Agent process itself."

        if process_name:
            clean_name = process_name.strip().lower()
            if clean_name in PROTECTED_PROCESS_NAMES:
                return True, f"Process name '{process_name}' is in the protected system binaries list."

        return False, ""

    def terminate_process(
        self,
        pid: int,
        expected_process_name: Optional[str] = None,
        expected_sha256: Optional[str] = None,
        dry_run: Optional[bool] = None,
        timeout: float = 3.0,
    ) -> ActionResult:
        """
        Safely terminates a process after verifying identity and system protection guards.
        """
        start_time = time.time()
        effective_dry_run = self.dry_run if dry_run is None else dry_run

        # Step 1: Check PID protected list
        protected, reason = self.is_protected(pid)
        if protected:
            logger.warning(f"[TERMINATE_REFUSED] Protected PID {pid}: {reason}")
            return ActionResult(
                status=ResponseActionStatus.REFUSED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Refused: {reason}",
                details={"pid": pid, "reason": reason},
            )

        # Step 2: Check process existence
        try:
            proc = psutil.Process(pid)
            actual_name = proc.name()
        except psutil.NoSuchProcess:
            logger.info(f"[TERMINATE_SUCCESS] Process {pid} does not exist (already terminated).")
            return ActionResult(
                status=ResponseActionStatus.SUCCESS,
                verification_status=VerificationStatus.VERIFIED_SUCCESS,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Process {pid} was not found (already inactive).",
                details={"pid": pid, "already_dead": True},
            )
        except psutil.AccessDenied as e:
            logger.error(f"[TERMINATE_FAILED] Access denied inspecting PID {pid}: {e}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Access denied accessing PID {pid}",
                details={"pid": pid, "error": str(e)},
            )

        # Step 3: Check protected process names
        protected, reason = self.is_protected(pid, actual_name)
        if protected:
            logger.warning(f"[TERMINATE_REFUSED] Protected process '{actual_name}' (PID {pid}): {reason}")
            return ActionResult(
                status=ResponseActionStatus.REFUSED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Refused: {reason}",
                details={"pid": pid, "name": actual_name, "reason": reason},
            )

        # Step 4: Validate PID reuse (if expected name provided)
        if expected_process_name:
            if actual_name.lower() != expected_process_name.lower():
                logger.warning(
                    f"[TERMINATE_REFUSED] PID reuse detected. PID {pid} is '{actual_name}', expected '{expected_process_name}'"
                )
                return ActionResult(
                    status=ResponseActionStatus.REFUSED,
                    verification_status=VerificationStatus.VERIFIED_FAILURE,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message=f"Refused: PID reuse detected. Current process is '{actual_name}', expected '{expected_process_name}'.",
                    details={"pid": pid, "actual_name": actual_name, "expected_name": expected_process_name},
                )

        # Step 5: Dry-Run execution check
        if effective_dry_run:
            logger.info(f"[DRY_RUN] Validated termination for PID {pid} ('{actual_name}'). Skipping live kill.")
            return ActionResult(
                status=ResponseActionStatus.SUCCESS,
                verification_status=VerificationStatus.VERIFIED_SUCCESS,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"[DRY_RUN] Verified process {pid} ('{actual_name}') is eligible for termination.",
                details={"pid": pid, "process_name": actual_name, "dry_run": True},
            )

        # Step 6: Live Termination
        try:
            proc.terminate()
            # Wait for process to exit cleanly
            gone, alive = psutil.wait_procs([proc], timeout=timeout)
            if alive:
                # Force kill if graceful terminate timed out
                logger.warning(f"Process {pid} did not exit gracefully; issuing SIGKILL.")
                proc.kill()
                gone, alive = psutil.wait_procs([proc], timeout=timeout)

            # Step 7: Post-Termination Verification
            if not psutil.pid_exists(pid):
                logger.info(f"[TERMINATE_SUCCESS] Terminated PID {pid} ('{actual_name}') verified dead.")
                return ActionResult(
                    status=ResponseActionStatus.SUCCESS,
                    verification_status=VerificationStatus.VERIFIED_SUCCESS,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message=f"Successfully terminated process {pid} ('{actual_name}').",
                    details={"pid": pid, "process_name": actual_name},
                )
            else:
                logger.error(f"[TERMINATE_FAILED] PID {pid} still alive after termination attempt.")
                return ActionResult(
                    status=ResponseActionStatus.FAILED,
                    verification_status=VerificationStatus.VERIFIED_FAILURE,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message=f"Failed to verify process {pid} termination; process remains active.",
                    details={"pid": pid, "process_name": actual_name},
                )
        except psutil.NoSuchProcess:
            return ActionResult(
                status=ResponseActionStatus.SUCCESS,
                verification_status=VerificationStatus.VERIFIED_SUCCESS,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Process {pid} successfully terminated.",
                details={"pid": pid, "process_name": actual_name},
            )
        except Exception as e:
            logger.exception(f"Unexpected error terminating PID {pid}: {e}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Error terminating process {pid}: {e}",
                details={"pid": pid, "error": str(e)},
            )


# Type helper
Tuple_Bool_Str = tuple[bool, str]
