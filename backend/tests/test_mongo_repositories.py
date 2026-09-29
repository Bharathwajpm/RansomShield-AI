"""
RansomShield AI — MongoDB Repositories Comprehensive CRUD & Filter Tests
Phase 3B: MongoDB Persistence Layer
"""

import time
import asyncio
import pytest

from backend.config.settings import Settings
from backend.database.mongodb import MongoDBManager
from backend.repositories.mongo_agent_repository import MongoAgentRepository
from backend.repositories.mongo_alert_repository import MongoAlertRepository
from backend.repositories.mongo_incident_repository import MongoIncidentRepository
from backend.repositories.mongo_detection_repository import MongoDetectionRepository

from backend.schemas.agent import AgentResponse
from backend.schemas.alert import AlertResponse
from backend.schemas.incident import IncidentResponse
from backend.schemas.detection import DetectionResponse


async def _get_connected_mgr():
    settings = Settings(
        mongodb_uri="mongodb://localhost:27017",
        mongodb_database="ransomshield_repo_test_db",
        mongodb_server_selection_timeout_ms=1500,
    )
    mgr = MongoDBManager(settings=settings)
    connected = await mgr.connect()
    assert connected is True, "MongoDB must be running on localhost:27017 for Phase 3B integration tests"
    await mgr.agents_collection.delete_many({})
    await mgr.alerts_collection.delete_many({})
    await mgr.incidents_collection.delete_many({})
    await mgr.detections_collection.delete_many({})
    return mgr


# --- AGENT REPOSITORY TESTS ---

def test_mongo_agent_crud():
    async def _test():
        db_mgr = await _get_connected_mgr()
        repo = MongoAgentRepository(db_manager=db_mgr)
        now = time.time()

        agent = AgentResponse(
            agent_id="host-test-01",
            hostname="DESKTOP-SEC01",
            os_name="Windows",
            os_version="11 Pro",
            agent_version="0.1.0",
            status="online",
            last_seen=now,
            ip_address="192.168.1.100",
            monitored_directories=["C:\\Data"],
            registered_at=now,
        )

        # Create
        created = await repo.create(agent)
        assert created.agent_id == "host-test-01"

        # Get by ID
        fetched = await repo.get_by_id("host-test-01")
        assert fetched is not None
        assert fetched.hostname == "DESKTOP-SEC01"
        assert fetched.ip_address == "192.168.1.100"

        # Update
        updated = await repo.update("host-test-01", {"status": "offline"})
        assert updated is not None
        assert updated.status == "offline"

        # Heartbeat
        hb_updated = await repo.update_heartbeat("host-test-01")
        assert hb_updated is not None
        assert hb_updated.status == "online"
        assert hb_updated.last_seen >= now

        # List
        agents = await repo.list(limit=10)
        assert len(agents) == 1
        assert agents[0].agent_id == "host-test-01"

        # Delete
        deleted = await repo.delete("host-test-01")
        assert deleted is True
        assert await repo.get_by_id("host-test-01") is None

        await db_mgr.disconnect()

    asyncio.run(_test())


# --- ALERT REPOSITORY TESTS ---

def test_mongo_alert_crud_and_filtering():
    async def _test():
        db_mgr = await _get_connected_mgr()
        repo = MongoAlertRepository(db_manager=db_mgr)
        now = time.time()

        a1 = AlertResponse(
            alert_id="alt-001",
            endpoint_id="host-1",
            prediction="Ransomware",
            confidence=96.5,
            risk_score=92,
            severity="CRITICAL",
            status="ACTIVE",
            created_at=now - 5,
            updated_at=now - 5,
        )
        a2 = AlertResponse(
            alert_id="alt-002",
            endpoint_id="host-2",
            prediction="Goodware",
            confidence=80.0,
            risk_score=25,
            severity="LOW",
            status="ACKNOWLEDGED",
            created_at=now,
            updated_at=now,
        )

        await repo.create(a1)
        await repo.create(a2)

        # Get by ID
        f1 = await repo.get_by_id("alt-001")
        assert f1 is not None
        assert f1.severity == "CRITICAL"
        assert f1.risk_score == 92

        # Filter by severity
        crit_alerts = await repo.list(severity="CRITICAL")
        assert len(crit_alerts) == 1
        assert crit_alerts[0].alert_id == "alt-001"

        # Filter by endpoint
        h2_alerts = await repo.list(endpoint_id="host-2")
        assert len(h2_alerts) == 1
        assert h2_alerts[0].alert_id == "alt-002"

        # Filter by status
        ack_alerts = await repo.list(status="ACKNOWLEDGED")
        assert len(ack_alerts) == 1
        assert ack_alerts[0].alert_id == "alt-002"

        # Update status to RESOLVED
        res = await repo.update("alt-001", {"status": "RESOLVED"})
        assert res is not None
        assert res.status == "RESOLVED"

        await db_mgr.disconnect()

    asyncio.run(_test())


# --- INCIDENT REPOSITORY TESTS ---

def test_mongo_incident_crud_and_filtering():
    async def _test():
        db_mgr = await _get_connected_mgr()
        repo = MongoIncidentRepository(db_manager=db_mgr)
        now = time.time()

        inc = IncidentResponse(
            incident_id="inc-soc-001",
            endpoint_id="host-win11",
            severity="HIGH",
            status="OPEN",
            alert_ids=["alt-001"],
            detection_count=1,
            first_detection=now,
            last_detection=now,
            primary_prediction="Ransomware",
            highest_risk_score=88,
            top_indicators=[{"feature_name": "File_Delete_archived", "weight": 95}],
            created_at=now,
            updated_at=now,
        )

        await repo.create(inc)

        fetched = await repo.get_by_id("inc-soc-001")
        assert fetched is not None
        assert fetched.endpoint_id == "host-win11"
        assert len(fetched.alert_ids) == 1

        # Update
        updated = await repo.update("inc-soc-001", {"status": "ACKNOWLEDGED", "detection_count": 2})
        assert updated is not None
        assert updated.status == "ACKNOWLEDGED"
        assert updated.detection_count == 2

        await db_mgr.disconnect()

    asyncio.run(_test())


# --- DETECTION REPOSITORY TESTS ---

def test_mongo_detection_crud_and_filtering():
    async def _test():
        db_mgr = await _get_connected_mgr()
        repo = MongoDetectionRepository(db_manager=db_mgr)
        now = time.time()

        d1 = DetectionResponse(
            detection_id="det-001",
            endpoint_id="host-win11",
            timestamp=now - 2,
            window_seconds=10,
            prediction="Ransomware",
            confidence=95.0,
            risk_score=94,
            probabilities={"Goodware": 0.05, "Ransomware": 0.95},
            features={"file_name_entropy": 4.5, "File_Delete_archived": 3.0},
            indicators=[{"feature_name": "suspicious_path", "weight": 90}],
        )
        d2 = DetectionResponse(
            detection_id="det-002",
            endpoint_id="host-win11",
            timestamp=now,
            window_seconds=10,
            prediction="Goodware",
            confidence=99.0,
            risk_score=1,
            probabilities={"Goodware": 0.99, "Ransomware": 0.01},
            features={"file_name_entropy": 2.1},
        )

        await repo.create(d1)
        await repo.create(d2)

        # Fetch
        f1 = await repo.get_by_id("det-001")
        assert f1 is not None
        assert f1.risk_score == 94
        assert f1.features["file_name_entropy"] == 4.5

        # Filter prediction
        ransom_dets = await repo.list(prediction="Ransomware")
        assert len(ransom_dets) == 1
        assert ransom_dets[0].detection_id == "det-001"

        # Sorting test: newest timestamp first
        all_dets = await repo.list()
        assert len(all_dets) == 2
        assert all_dets[0].detection_id == "det-002"  # newer
        assert all_dets[1].detection_id == "det-001"

        await db_mgr.disconnect()

    asyncio.run(_test())


# --- INDEX VERIFICATION ---

def test_mongo_index_creation():
    async def _test():
        db_mgr = await _get_connected_mgr()

        agent_indexes = await db_mgr.agents_collection.index_information()
        assert "idx_agents_agent_id" in agent_indexes
        assert agent_indexes["idx_agents_agent_id"].get("unique") is True
        assert "idx_agents_last_seen" in agent_indexes

        alert_indexes = await db_mgr.alerts_collection.index_information()
        assert "idx_alerts_alert_id" in alert_indexes
        assert alert_indexes["idx_alerts_alert_id"].get("unique") is True
        assert "idx_alerts_endpoint_created" in alert_indexes

        incident_indexes = await db_mgr.incidents_collection.index_information()
        assert "idx_incidents_incident_id" in incident_indexes
        assert incident_indexes["idx_incidents_incident_id"].get("unique") is True
        assert "idx_incidents_endpoint_created" in incident_indexes

        detection_indexes = await db_mgr.detections_collection.index_information()
        assert "idx_detections_detection_id" in detection_indexes
        assert detection_indexes["idx_detections_detection_id"].get("unique") is True
        assert "idx_detections_endpoint_timestamp" in detection_indexes

        await db_mgr.disconnect()

    asyncio.run(_test())
