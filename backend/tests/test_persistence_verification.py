"""
RansomShield AI — Real MongoDB Persistence Verification Tests
Phase 3B: MongoDB Persistence Layer

Proves genuine cross-session database persistence:
1. Start backend connected to MongoDB.
2. Ingest agent and live detection via API.
3. Seed alert and incident into MongoDB collections.
4. Stop backend completely (destroying in-memory state).
5. Start fresh backend instance with new TestClient.
6. Retrieve identical records from MongoDB via API and verify data integrity.
"""

import time
import asyncio
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.config.settings import Settings
from backend.database.mongodb import MongoDBManager


def test_cross_session_persistence_lifecycle():
    db_name = "ransomshield_persistence_verify_db"
    test_settings = Settings(
        app_name="RansomShield Persistence Test",
        mongodb_uri="mongodb://localhost:27017",
        mongodb_database=db_name,
        database_backend="mongodb",
        mongodb_server_selection_timeout_ms=1500,
    )

    unique_agent_id = "agent-persist-win11"
    unique_alt_id = "alt-persist-99"
    unique_inc_id = "inc-persist-100"

    # Clean the test database before starting
    async def _clean_db():
        cleaner_mgr = MongoDBManager(settings=test_settings)
        await cleaner_mgr.connect()
        await cleaner_mgr.agents_collection.delete_many({})
        await cleaner_mgr.alerts_collection.delete_many({})
        await cleaner_mgr.incidents_collection.delete_many({})
        await cleaner_mgr.detections_collection.delete_many({})
        await cleaner_mgr.disconnect()

    asyncio.run(_clean_db())

    # ==========================================
    # SESSION 1: Start Backend, Write Records
    # ==========================================
    app_1 = create_app(settings=test_settings)
    with TestClient(app_1) as client_1:
        # Verify readiness shows connected
        ready_resp = client_1.get("/api/v1/health/ready")
        assert ready_resp.status_code == 200
        assert ready_resp.json()["data"]["dependencies"]["database"]["status"] == "connected"

        # 1. Create Agent via API
        agent_payload = {
            "agent_id": unique_agent_id,
            "hostname": "PERSIST-HOST-01",
            "os_name": "Windows",
            "os_version": "11 Pro 23H2",
            "agent_version": "0.2.0",
            "ip_address": "10.0.1.25",
            "monitored_directories": ["C:\\Users\\Analyst\\Documents"],
        }
        r_agent = client_1.post("/api/v1/agents/register", json=agent_payload)
        assert r_agent.status_code == 201
        assert r_agent.json()["data"]["agent_id"] == unique_agent_id

        # 2. Ingest Live Detection via API
        det_payload = {
            "endpoint_id": unique_agent_id,
            "timestamp": time.time(),
            "window_seconds": 10,
            "prediction": "Ransomware",
            "confidence": 97.5,
            "risk_score": 93,
            "probabilities": {"Goodware": 0.025, "Ransomware": 0.975},
            "features": {"File_Delete_archived": 6.0, "file_name_entropy": 4.95},
            "indicators": [{"feature_name": "File_Delete_archived", "weight": 98}],
            "explanation": "Critical archive deletion rate detected.",
            "event_count": 120,
            "duration_ms": 310.2,
        }
        r_det = client_1.post("/api/v1/detections", json=det_payload)
        assert r_det.status_code == 201
        unique_det_id = r_det.json()["data"]["detection_id"]

    # Seed alert and incident into MongoDB
    async def _seed_alert_and_incident():
        mgr = MongoDBManager(settings=test_settings)
        await mgr.connect()
        now = time.time()
        await mgr.alerts_collection.replace_one(
            {"_id": unique_alt_id},
            {
                "_id": unique_alt_id,
                "alert_id": unique_alt_id,
                "endpoint_id": unique_agent_id,
                "prediction": "Ransomware",
                "confidence": 97.5,
                "risk_score": 93,
                "severity": "CRITICAL",
                "status": "ACTIVE",
                "stage": 3,
                "reason": "Archive destruction",
                "indicators": [{"feature_name": "File_Delete_archived", "weight": 98}],
                "created_at": now,
                "updated_at": now,
            },
            upsert=True,
        )
        await mgr.incidents_collection.replace_one(
            {"_id": unique_inc_id},
            {
                "_id": unique_inc_id,
                "incident_id": unique_inc_id,
                "endpoint_id": unique_agent_id,
                "severity": "CRITICAL",
                "status": "OPEN",
                "alert_ids": [unique_alt_id],
                "detection_count": 1,
                "first_detection": now,
                "last_detection": now,
                "primary_prediction": "Ransomware",
                "highest_risk_score": 93,
                "top_indicators": [{"feature_name": "File_Delete_archived", "weight": 98}],
                "summary": "Ransomware outbreak on PERSIST-HOST-01",
                "created_at": now,
                "updated_at": now,
            },
            upsert=True,
        )
        await mgr.disconnect()

    asyncio.run(_seed_alert_and_incident())

    # Session 1 is completely closed and shut down here.
    # In-memory structures from Session 1 are terminated.

    # ==========================================
    # SESSION 2: Start NEW Backend, Query Records
    # ==========================================
    app_2 = create_app(settings=test_settings)
    with TestClient(app_2) as client_2:
        # 1. Query Agent
        r_agent_2 = client_2.get(f"/api/v1/agents/{unique_agent_id}")
        assert r_agent_2.status_code == 200
        agent_data = r_agent_2.json()["data"]
        assert agent_data["agent_id"] == unique_agent_id
        assert agent_data["hostname"] == "PERSIST-HOST-01"
        assert agent_data["ip_address"] == "10.0.1.25"

        # 2. Query Detection
        r_det_2 = client_2.get(f"/api/v1/detections/{unique_det_id}")
        assert r_det_2.status_code == 200
        det_data = r_det_2.json()["data"]
        assert det_data["detection_id"] == unique_det_id
        assert det_data["risk_score"] == 93
        assert det_data["features"]["File_Delete_archived"] == 6.0
        assert det_data["features"]["file_name_entropy"] == 4.95

        # 3. Query Alert
        r_alt_2 = client_2.get(f"/api/v1/alerts/{unique_alt_id}")
        assert r_alt_2.status_code == 200
        alt_data = r_alt_2.json()["data"]
        assert alt_data["alert_id"] == unique_alt_id
        assert alt_data["severity"] == "CRITICAL"
        assert alt_data["status"] == "ACTIVE"

        # 4. Query Incident
        r_inc_2 = client_2.get(f"/api/v1/incidents/{unique_inc_id}")
        assert r_inc_2.status_code == 200
        inc_data = r_inc_2.json()["data"]
        assert inc_data["incident_id"] == unique_inc_id
        assert inc_data["severity"] == "CRITICAL"
        assert inc_data["status"] == "OPEN"
        assert inc_data["summary"] == "Ransomware outbreak on PERSIST-HOST-01"

    # Clean up test database
    asyncio.run(_clean_db())
