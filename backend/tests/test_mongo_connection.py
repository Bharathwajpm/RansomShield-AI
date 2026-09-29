"""
RansomShield AI — MongoDB Connection & Health Probe Tests
Phase 3B: MongoDB Persistence Layer
"""

import asyncio
from backend.database.mongodb import MongoDBManager, sanitize_uri
from backend.config.settings import Settings


def test_sanitize_uri():
    assert sanitize_uri(None) == "None"
    assert sanitize_uri("mongodb://localhost:27017") == "mongodb://localhost:27017"
    masked = sanitize_uri("mongodb://admin:SuperSecretPassword123@cluster0.net:27017/db")
    assert "SuperSecretPassword123" not in masked
    assert "admin:****@" in masked


def test_mongo_not_configured():
    async def _test():
        settings = Settings(mongodb_uri=None)
        mgr = MongoDBManager(settings=settings)
        assert mgr.is_configured is False
        assert mgr.is_connected is False

        status = await mgr.check_connection()
        assert status["status"] == "not_configured"
        assert "not set" in status["message"]

    asyncio.run(_test())


def test_mongo_connected_live():
    async def _test():
        settings = Settings(
            mongodb_uri="mongodb://localhost:27017",
            mongodb_database="ransomshield_test_db",
            mongodb_server_selection_timeout_ms=1500,
        )
        mgr = MongoDBManager(settings=settings)
        assert mgr.is_configured is True

        connected = await mgr.connect()
        assert connected is True
        assert mgr.is_connected is True

        status = await mgr.check_connection()
        assert status["status"] == "connected"

        # Verify collection accessors
        assert mgr.agents_collection is not None
        assert mgr.alerts_collection is not None
        assert mgr.incidents_collection is not None
        assert mgr.detections_collection is not None

        # Disconnect cleanly
        await mgr.disconnect()
        assert mgr.is_connected is False

    asyncio.run(_test())


def test_mongo_unreachable_graceful():
    async def _test():
        # Use invalid port to test timeout & unreachable status
        settings = Settings(
            mongodb_uri="mongodb://127.0.0.1:27099",  # Unused port
            mongodb_database="ransomshield_unreachable_test",
            mongodb_server_selection_timeout_ms=500,
            mongodb_connect_timeout_ms=500,
        )
        mgr = MongoDBManager(settings=settings)
        assert mgr.is_configured is True

        # Attempting to connect should NOT raise an unhandled exception or crash
        connected = await mgr.connect()
        assert connected is False
        assert mgr.is_connected is False

        status = await mgr.check_connection()
        assert status["status"] == "disconnected"
        assert "unreachable" in status["message"]

    asyncio.run(_test())
