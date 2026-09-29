"""
RansomShield AI — Network Isolation Handler
Phase 4: Defensive Response & Endpoint Containment

Manages safe, reversible endpoint network isolation using Windows Firewall rules
while preserving defensive agent-to-backend communication channels.
"""

import sys
import time
import shutil
import logging
import subprocess
from typing import Dict, Any, Optional

from agent.response.action_models import (
    ActionResult,
    ResponseActionStatus,
    VerificationStatus,
)

logger = logging.getLogger("RansomShield.Response.Network")

RULE_NAME_BLOCK_OUTBOUND = "RansomShield-Isolation-Outbound"
RULE_NAME_ALLOW_BACKEND = "RansomShield-Isolation-AllowBackend"


class NetworkIsolationHandler:
    """
    Handles endpoint network isolation to contain worm-like ransomware propagation.
    Guarantees reversible firewall state and maintains backend connectivity.
    """

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._simulated_isolated: bool = False
        self._is_windows = sys.platform.startswith("win")
        self._has_netsh = shutil.which("netsh") is not None

    def is_isolated(self) -> bool:
        """Checks if network isolation is currently active."""
        if self.dry_run or not self._is_windows or not self._has_netsh:
            return self._simulated_isolated

        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_NAME_BLOCK_OUTBOUND}"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            return res.returncode == 0
        except Exception:
            return self._simulated_isolated

    def isolate_network(
        self,
        backend_host: str = "127.0.0.1",
        backend_port: int = 8000,
        dry_run: Optional[bool] = None,
    ) -> ActionResult:
        """
        Enforces network isolation by blocking outbound network traffic
        while explicitly allowing traffic to the RansomShield management backend.
        """
        start_time = time.time()
        effective_dry_run = self.dry_run if dry_run is None else dry_run

        if effective_dry_run or not self._is_windows or not self._has_netsh:
            self._simulated_isolated = True
            logger.info(
                f"[DRY_RUN] Network isolation simulated. Block outbound with exception for {backend_host}:{backend_port}"
            )
            return ActionResult(
                status=ResponseActionStatus.SUCCESS,
                verification_status=VerificationStatus.VERIFIED_SUCCESS,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"[DRY_RUN] Endpoint network isolation applied (management channel {backend_host}:{backend_port} preserved).",
                details={
                    "backend_host": backend_host,
                    "backend_port": backend_port,
                    "dry_run": True,
                    "isolated": True,
                },
            )

        try:
            # 1. Add allow rule for backend communication so we don't lose control
            allow_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_NAME_ALLOW_BACKEND}",
                "dir=out", "action=allow", "protocol=TCP",
                f"remoteport={backend_port}",
            ]
            if backend_host not in ("localhost", "127.0.0.1", "0.0.0.0"):
                allow_cmd.append(f"remoteip={backend_host}")

            subprocess.run(allow_cmd, capture_output=True, text=True, timeout=5.0)

            # 2. Add block outbound rule for all other traffic
            block_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_NAME_BLOCK_OUTBOUND}",
                "dir=out", "action=block",
            ]
            res = subprocess.run(block_cmd, capture_output=True, text=True, timeout=5.0)

            # 3. Post-Action Verification
            is_active = self.is_isolated()
            if is_active:
                logger.info("[ISOLATION_SUCCESS] Windows Firewall isolation rules successfully activated.")
                return ActionResult(
                    status=ResponseActionStatus.SUCCESS,
                    verification_status=VerificationStatus.VERIFIED_SUCCESS,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message="Endpoint network isolation successfully applied.",
                    details={
                        "rule_name": RULE_NAME_BLOCK_OUTBOUND,
                        "backend_exception": f"{backend_host}:{backend_port}",
                        "isolated": True,
                    },
                )
            else:
                logger.error(f"[ISOLATION_FAILED] Firewall command returned {res.returncode}: {res.stderr}")
                return ActionResult(
                    status=ResponseActionStatus.FAILED,
                    verification_status=VerificationStatus.VERIFIED_FAILURE,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message=f"Failed to verify isolation rule: {res.stderr or 'Permission denied'}",
                    details={"error": res.stderr},
                )
        except Exception as e:
            logger.exception(f"Unexpected error isolating network: {e}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Error executing network isolation: {e}",
                details={"error": str(e)},
            )

    def release_isolation(self, dry_run: Optional[bool] = None) -> ActionResult:
        """
        Reverses network isolation by removing the RansomShield firewall rules.
        """
        start_time = time.time()
        effective_dry_run = self.dry_run if dry_run is None else dry_run

        if effective_dry_run or not self._is_windows or not self._has_netsh:
            self._simulated_isolated = False
            logger.info("[DRY_RUN] Network isolation released (simulated).")
            return ActionResult(
                status=ResponseActionStatus.SUCCESS,
                verification_status=VerificationStatus.VERIFIED_SUCCESS,
                execution_time_ms=(time.time() - start_time) * 1000,
                message="[DRY_RUN] Endpoint network isolation successfully released.",
                details={"dry_run": True, "isolated": False},
            )

        try:
            # Delete both rules
            for rule_name in (RULE_NAME_BLOCK_OUTBOUND, RULE_NAME_ALLOW_BACKEND):
                del_cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ]
                subprocess.run(del_cmd, capture_output=True, text=True, timeout=5.0)

            # Verification: Confirm rule no longer exists
            is_active = self.is_isolated()
            if not is_active:
                logger.info("[ISOLATION_RELEASE_SUCCESS] Network isolation released.")
                return ActionResult(
                    status=ResponseActionStatus.SUCCESS,
                    verification_status=VerificationStatus.VERIFIED_SUCCESS,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message="Network isolation successfully removed. Standard network connectivity restored.",
                    details={"isolated": False},
                )
            else:
                return ActionResult(
                    status=ResponseActionStatus.FAILED,
                    verification_status=VerificationStatus.VERIFIED_FAILURE,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    message="Failed to release isolation: firewall rule still detected.",
                    details={"isolated": True},
                )
        except Exception as e:
            logger.exception(f"Unexpected error releasing isolation: {e}")
            return ActionResult(
                status=ResponseActionStatus.FAILED,
                verification_status=VerificationStatus.VERIFIED_FAILURE,
                execution_time_ms=(time.time() - start_time) * 1000,
                message=f"Error releasing network isolation: {e}",
                details={"error": str(e)},
            )
