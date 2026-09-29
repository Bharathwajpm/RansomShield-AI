"""
RansomShield AI — Agent Response & Containment Test Suite
Phase 4: Defensive Response & Endpoint Containment

Tests defensive containment safety invariants:
- Protected system process safeguards (PIDs, critical Windows binaries)
- PID reuse detection
- Path traversal defenses in file quarantine
- SHA-256 cryptographic pre/post verification
- Network isolation dry run and reversibility
- Policy engine recommendation logic
"""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from agent.response.action_models import (
    ResponseAction,
    ResponseActionType,
    ResponseActionStatus,
    RiskLevel,
    VerificationStatus,
)
from agent.response.process_response import ProcessResponseHandler, PROTECTED_PROCESS_NAMES
from agent.response.file_quarantine import FileQuarantineHandler, compute_sha256
from agent.response.network_isolation import NetworkIsolationHandler
from agent.response.action_policy import ResponsePolicyEngine
from agent.response.response_engine import ResponseEngine
from agent.detection.severity import AlertSeverity


def test_process_termination_protected_pids():
    """Confirms that PIDs 0, 4, and agent's own PID are strictly refused."""
    handler = ProcessResponseHandler(dry_run=False)
    
    # PID 0
    res0 = handler.terminate_process(pid=0)
    assert res0.status == ResponseActionStatus.REFUSED
    assert res0.verification_status == VerificationStatus.VERIFIED_FAILURE

    # PID 4 (System)
    res4 = handler.terminate_process(pid=4)
    assert res4.status == ResponseActionStatus.REFUSED
    assert res4.verification_status == VerificationStatus.VERIFIED_FAILURE

    # Own PID
    own_pid = os.getpid()
    res_own = handler.terminate_process(pid=own_pid)
    assert res_own.status == ResponseActionStatus.REFUSED


def test_process_termination_protected_binaries():
    """Confirms that critical Windows system binaries cannot be terminated."""
    handler = ProcessResponseHandler(dry_run=False)

    for binary in ["csrss.exe", "lsass.exe", "services.exe", "explorer.exe", "svchost.exe"]:
        is_prot, reason = handler.is_protected(pid=99999, process_name=binary)
        assert is_prot is True
        assert "protected" in reason.lower()


def test_process_termination_pid_reuse_rejection():
    """Confirms that process name mismatch triggers PID reuse refusal."""
    handler = ProcessResponseHandler(dry_run=False)
    
    # Mock psutil.Process to simulate PID reuse
    with patch("psutil.Process") as mock_proc_cls:
        mock_proc = MagicMock()
        mock_proc.name.return_value = "legitimate_app.exe"
        mock_proc_cls.return_value = mock_proc

        result = handler.terminate_process(
            pid=12345,
            expected_process_name="ransomware_payload.exe",
        )
        assert result.status == ResponseActionStatus.REFUSED
        assert "PID reuse" in result.message


def test_process_termination_dry_run():
    """Confirms dry-run mode validates eligibility without terminating."""
    handler = ProcessResponseHandler(dry_run=True)

    with patch("psutil.Process") as mock_proc_cls:
        mock_proc = MagicMock()
        mock_proc.name.return_value = "suspicious_miner.exe"
        mock_proc_cls.return_value = mock_proc

        result = handler.terminate_process(
            pid=2468,
            expected_process_name="suspicious_miner.exe",
            dry_run=True,
        )
        assert result.status == ResponseActionStatus.SUCCESS
        assert result.verification_status == VerificationStatus.VERIFIED_SUCCESS
        assert "[DRY_RUN]" in result.message
        # Confirm terminate was NOT called on process
        mock_proc.terminate.assert_not_called()


def test_process_termination_already_dead():
    """Confirms attempting to terminate a non-existent PID gracefully returns success."""
    import psutil
    handler = ProcessResponseHandler(dry_run=False)

    with patch("psutil.Process", side_effect=psutil.NoSuchProcess(pid=99999)):
        result = handler.terminate_process(pid=99999)
        assert result.status == ResponseActionStatus.SUCCESS
        assert result.verification_status == VerificationStatus.VERIFIED_SUCCESS


def test_file_quarantine_path_traversal_rejection():
    """Confirms directory traversal attempts are strictly refused."""
    with tempfile.TemporaryDirectory() as q_dir:
        handler = FileQuarantineHandler(quarantine_dir=q_dir, dry_run=False)

        res = handler.quarantine_file("C:\\safe\\path\\..\\..\\Windows\\System32\\calc.exe")
        assert res.status == ResponseActionStatus.REFUSED
        assert "Directory traversal" in res.message or "protected" in res.message


def test_file_quarantine_protected_system_dir():
    """Confirms files inside protected OS directories are refused."""
    with tempfile.TemporaryDirectory() as q_dir:
        handler = FileQuarantineHandler(quarantine_dir=q_dir, dry_run=False)

        res = handler.quarantine_file("C:\\Windows\\System32\\cmd.exe")
        assert res.status == ResponseActionStatus.REFUSED


def test_file_quarantine_sha256_pre_post_verification():
    """
    Confirms end-to-end safe file quarantine:
    1. Pre-hash calculation
    2. Atomic move to quarantine vault
    3. Source file absence
    4. Destination file cryptographic hash verification
    """
    with tempfile.TemporaryDirectory() as work_dir, tempfile.TemporaryDirectory() as q_dir:
        # Create a sample threat file
        test_file = os.path.join(work_dir, "suspicious_payload.bin")
        payload_bytes = b"RANSOM_SAMPLE_TEST_CONTENT_ABC123"
        with open(test_file, "wb") as f:
            f.write(payload_bytes)

        expected_hash = compute_sha256(test_file)

        handler = FileQuarantineHandler(quarantine_dir=q_dir, dry_run=False)
        result = handler.quarantine_file(test_file, action_id="test-action-1")

        assert result.status == ResponseActionStatus.SUCCESS
        assert result.verification_status == VerificationStatus.VERIFIED_SUCCESS
        assert not os.path.exists(test_file)  # Source file moved

        # Verify vault contains quarantined file named after hash
        quarantine_dest = os.path.join(q_dir, f"{expected_hash}.quarantine")
        assert os.path.isfile(quarantine_dest)
        assert compute_sha256(quarantine_dest) == expected_hash

        # Verify sidecar metadata
        sidecar = os.path.join(q_dir, f"{expected_hash}.json")
        assert os.path.isfile(sidecar)


def test_file_quarantine_dry_run():
    """Confirms dry-run quarantine hashes and verifies without removing the original file."""
    with tempfile.TemporaryDirectory() as work_dir, tempfile.TemporaryDirectory() as q_dir:
        test_file = os.path.join(work_dir, "benign_file.txt")
        with open(test_file, "w") as f:
            f.write("important business document")

        handler = FileQuarantineHandler(quarantine_dir=q_dir, dry_run=True)
        result = handler.quarantine_file(test_file)

        assert result.status == ResponseActionStatus.SUCCESS
        assert result.verification_status == VerificationStatus.VERIFIED_SUCCESS
        assert "[DRY_RUN]" in result.message
        assert os.path.exists(test_file)  # File preserved in dry-run


def test_network_isolation_dry_run():
    """Confirms network isolation can be simulated and safely reversed."""
    handler = NetworkIsolationHandler(dry_run=True)
    assert not handler.is_isolated()

    # Isolate
    res_iso = handler.isolate_network(backend_host="127.0.0.1", backend_port=8000)
    assert res_iso.status == ResponseActionStatus.SUCCESS
    assert res_iso.verification_status == VerificationStatus.VERIFIED_SUCCESS
    assert handler.is_isolated() is True

    # Release
    res_rel = handler.release_isolation()
    assert res_rel.status == ResponseActionStatus.SUCCESS
    assert res_rel.verification_status == VerificationStatus.VERIFIED_SUCCESS
    assert handler.is_isolated() is False


def test_response_policy_engine_recommendations():
    """Confirms policy engine maps alert severity to appropriate actions."""
    policy = ResponsePolicyEngine(require_approval_for_isolation=True, dry_run_default=True)

    # CRITICAL alert
    actions_crit = policy.evaluate_alert(
        severity=AlertSeverity.CRITICAL,
        pid=1234,
        process_name="lockbit.exe",
        file_path="C:\\Users\\test\\lockbit.exe",
        sha256="abc123def456",
    )
    action_types = [a.action_type for a in actions_crit]
    assert ResponseActionType.TERMINATE_PROCESS in action_types
    assert ResponseActionType.QUARANTINE_FILE in action_types
    assert ResponseActionType.ISOLATE_NETWORK in action_types

    # Network isolation should require approval
    iso_action = next(a for a in actions_crit if a.action_type == ResponseActionType.ISOLATE_NETWORK)
    assert iso_action.requires_approval is True

    # MEDIUM alert
    actions_med = policy.evaluate_alert(
        severity=AlertSeverity.MEDIUM,
        file_path="C:\\Users\\test\\sample.tmp",
    )
    assert len(actions_med) == 1
    assert actions_med[0].action_type == ResponseActionType.QUARANTINE_FILE
    assert actions_med[0].risk_level == RiskLevel.MEDIUM


def test_response_engine_action_execution_flow():
    """Confirms ResponseEngine dispatches actions and records history correctly."""
    with tempfile.TemporaryDirectory() as q_dir:
        engine = ResponseEngine(dry_run=True, quarantine_dir=q_dir)

        action = ResponseAction(
            action_type=ResponseActionType.ISOLATE_NETWORK,
            target="endpoint",
            parameters={"backend_host": "127.0.0.1", "backend_port": 8000},
            risk_level=RiskLevel.HIGH,
            requires_approval=False,
            status=ResponseActionStatus.APPROVED,
        )

        result = engine.execute_action(action)
        assert result.status == ResponseActionStatus.SUCCESS
        assert result.verification_status == VerificationStatus.VERIFIED_SUCCESS

        stored = engine.get_action(action.action_id)
        assert stored is not None
        assert stored.status == ResponseActionStatus.SUCCESS
        assert len(engine.list_actions()) >= 1
