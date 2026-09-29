"""
RansomShield AI — MongoDB Connection & Lifecycle Manager
Phase 3B: MongoDB Persistence Layer

Manages asynchronous MongoDB connection lifecycle, health probes, collection accessors,
and automatic index initialization.
"""

import logging
import re
from typing import Dict, Any, Optional
from pymongo import ASCENDING, DESCENDING, IndexModel

from backend.config.settings import Settings, get_settings

logger = logging.getLogger("RansomShieldBackend.Database")


def sanitize_uri(uri: Optional[str]) -> str:
    """Masks credentials in MongoDB URI for safe logging."""
    if not uri:
        return "None"
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", uri)


class MongoDBManager:
    """
    Asynchronous MongoDB client connection and lifecycle manager.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.client: Optional[Any] = None
        self.db: Optional[Any] = None
        self._is_connected: bool = False
        self._indexes_initialized: bool = False

    @property
    def is_configured(self) -> bool:
        """Returns True if a MongoDB URI is configured in settings."""
        return bool(self.settings.mongodb_uri)

    @property
    def is_connected(self) -> bool:
        """Returns True if active connection is established and verified."""
        return self._is_connected and self.db is not None

    @property
    def agents_collection(self):
        """Returns the agents collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["agents"]

    @property
    def alerts_collection(self):
        """Returns the alerts collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["alerts"]

    @property
    def incidents_collection(self):
        """Returns the incidents collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["incidents"]

    @property
    def detections_collection(self):
        """Returns the detections collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["detections"]

    @property
    def users_collection(self):
        """Returns the users collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["users"]

    @property
    def response_actions_collection(self):
        """Returns the response actions collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["response_actions"]

    @property
    def response_audit_collection(self):
        """Returns the response audit collection."""
        if self.db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.db["response_audit"]

    async def connect(self) -> bool:
        """
        Establishes connection to MongoDB if URI is configured.
        Returns True if connection succeeded, False otherwise.
        """
        if not self.is_configured:
            logger.info("[DB_INIT] MongoDB URI not configured. Operating in in-memory mode.")
            self._is_connected = False
            return False

        safe_uri = sanitize_uri(self.settings.mongodb_uri)
        try:
            import motor.motor_asyncio
            logger.info(f"[DB_CONNECTING] Connecting to MongoDB at {safe_uri}...")
            
            self.client = motor.motor_asyncio.AsyncIOMotorClient(
                self.settings.mongodb_uri,
                serverSelectionTimeoutMS=self.settings.mongodb_server_selection_timeout_ms,
                connectTimeoutMS=self.settings.mongodb_connect_timeout_ms,
            )
            self.db = self.client[self.settings.mongodb_database]
            
            # Ping database to verify live connectivity
            await self.client.admin.command("ping")
            self._is_connected = True
            logger.info(
                f"[DB_CONNECTED] Successfully connected to MongoDB database '{self.settings.mongodb_database}'."
            )
            
            # Initialize query optimization indexes
            await self.init_indexes()
            return True

        except ImportError:
            logger.warning("[DB_WARNING] 'motor' package not installed. Operating in in-memory mode.")
            self._is_connected = False
            return False
        except Exception as e:
            logger.error(f"[DB_ERROR] Failed to connect to MongoDB ({safe_uri}): {e}")
            self._is_connected = False
            if self.client:
                self.client.close()
                self.client = None
                self.db = None
            return False

    async def disconnect(self) -> None:
        """Closes MongoDB connection cleanly during shutdown."""
        if self.client:
            try:
                self.client.close()
                logger.info("[DB_DISCONNECTED] MongoDB connection closed cleanly.")
            except Exception as e:
                logger.error(f"[DB_ERROR] Error closing MongoDB connection: {e}")
            finally:
                self.client = None
                self.db = None
                self._is_connected = False
                self._indexes_initialized = False

    async def check_connection(self) -> Dict[str, Any]:
        """Returns a diagnostic status report of the database connection."""
        if not self.is_configured:
            return {
                "status": "not_configured",
                "database": self.settings.mongodb_database,
                "message": "MongoDB URI not set. In-memory repository active.",
            }

        if not self._is_connected or not self.client:
            return {
                "status": "disconnected",
                "database": self.settings.mongodb_database,
                "message": "MongoDB is configured but currently unreachable.",
            }

        try:
            await self.client.admin.command("ping")
            return {
                "status": "connected",
                "database": self.settings.mongodb_database,
                "message": "Active connection verified.",
            }
        except Exception as e:
            return {
                "status": "error",
                "database": self.settings.mongodb_database,
                "error": str(e),
            }

    async def init_indexes(self) -> None:
        """
        Creates query optimization indexes for all collections based on query patterns.
        """
        if not self.is_connected or self.db is None:
            return

        try:
            # 1. Agents Collection Indexes
            await self.agents_collection.create_indexes([
                IndexModel([("agent_id", ASCENDING)], unique=True, name="idx_agents_agent_id"),
                IndexModel([("last_seen", DESCENDING)], name="idx_agents_last_seen"),
                IndexModel([("status", ASCENDING)], name="idx_agents_status"),
            ])

            # 2. Alerts Collection Indexes
            await self.alerts_collection.create_indexes([
                IndexModel([("alert_id", ASCENDING)], unique=True, name="idx_alerts_alert_id"),
                IndexModel([("endpoint_id", ASCENDING)], name="idx_alerts_endpoint_id"),
                IndexModel([("severity", ASCENDING)], name="idx_alerts_severity"),
                IndexModel([("status", ASCENDING)], name="idx_alerts_status"),
                IndexModel([("created_at", DESCENDING)], name="idx_alerts_created_at"),
                IndexModel([("endpoint_id", ASCENDING), ("created_at", DESCENDING)], name="idx_alerts_endpoint_created"),
            ])

            # 3. Incidents Collection Indexes
            await self.incidents_collection.create_indexes([
                IndexModel([("incident_id", ASCENDING)], unique=True, name="idx_incidents_incident_id"),
                IndexModel([("endpoint_id", ASCENDING)], name="idx_incidents_endpoint_id"),
                IndexModel([("severity", ASCENDING)], name="idx_incidents_severity"),
                IndexModel([("status", ASCENDING)], name="idx_incidents_status"),
                IndexModel([("created_at", DESCENDING)], name="idx_incidents_created_at"),
                IndexModel([("endpoint_id", ASCENDING), ("created_at", DESCENDING)], name="idx_incidents_endpoint_created"),
            ])

            # 4. Detections Collection Indexes
            await self.detections_collection.create_indexes([
                IndexModel([("detection_id", ASCENDING)], unique=True, name="idx_detections_detection_id"),
                IndexModel([("endpoint_id", ASCENDING)], name="idx_detections_endpoint_id"),
                IndexModel([("timestamp", DESCENDING)], name="idx_detections_timestamp"),
                IndexModel([("prediction", ASCENDING)], name="idx_detections_prediction"),
                IndexModel([("endpoint_id", ASCENDING), ("timestamp", DESCENDING)], name="idx_detections_endpoint_timestamp"),
            ])

            # 5. Users Collection Indexes
            await self.users_collection.create_indexes([
                IndexModel([("username", ASCENDING)], unique=True, name="idx_users_username"),
                IndexModel([("user_id", ASCENDING)], unique=True, name="idx_users_user_id"),
            ])

            # 6. Response Actions Collection Indexes
            await self.response_actions_collection.create_indexes([
                IndexModel([("action_id", ASCENDING)], unique=True, name="idx_response_action_id"),
                IndexModel([("agent_id", ASCENDING)], name="idx_response_agent_id"),
                IndexModel([("status", ASCENDING)], name="idx_response_status"),
                IndexModel([("action_type", ASCENDING)], name="idx_response_action_type"),
                IndexModel([("created_at", DESCENDING)], name="idx_response_created_at"),
            ])

            # 7. Response Audit Collection Indexes
            await self.response_audit_collection.create_indexes([
                IndexModel([("log_id", ASCENDING)], unique=True, name="idx_response_audit_log_id"),
                IndexModel([("action_id", ASCENDING)], name="idx_response_audit_action_id"),
                IndexModel([("agent_id", ASCENDING)], name="idx_response_audit_agent_id"),
                IndexModel([("timestamp", DESCENDING)], name="idx_response_audit_timestamp"),
            ])

            self._indexes_initialized = True
            logger.info("[DB_INDEXES] MongoDB collections and indexes initialized successfully.")
        except Exception as e:
            logger.error(f"[DB_ERROR] Failed to create database indexes: {e}")


# Singleton database manager instance
db_manager = MongoDBManager()


def get_db_manager(settings: Optional[Settings] = None) -> MongoDBManager:
    """Returns database manager instance, updating settings if custom settings are provided."""
    global db_manager
    if settings is not None:
        db_manager.settings = settings
    return db_manager
