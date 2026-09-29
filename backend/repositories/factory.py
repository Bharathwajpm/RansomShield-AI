"""
RansomShield AI — Repository Provider & Selection Factory
Phase 3B: MongoDB Persistence Layer

Provides clean, decoupled dependency selection between persistent MongoDB
repositories and in-memory repositories based on environment configuration and
connection health.
"""

from typing import Optional, Dict, Any

from backend.repositories.base import BaseRepository
from backend.repositories.agent_repository import AgentRepository, agent_repository as in_memory_agent_repo
from backend.repositories.alert_repository import AlertRepository, alert_repository as in_memory_alert_repo
from backend.repositories.incident_repository import IncidentRepository, incident_repository as in_memory_incident_repo
from backend.repositories.detection_repository import DetectionRepository, detection_repository as in_memory_detection_repo
from backend.repositories.user_repository import UserRepository, user_repository as in_memory_user_repo
from backend.repositories.response_repository import (
    ResponseRepository,
    response_repository as in_memory_response_repo,
    ResponseAuditRepository,
    response_audit_repository as in_memory_response_audit_repo,
)

from backend.repositories.mongo_agent_repository import MongoAgentRepository
from backend.repositories.mongo_alert_repository import MongoAlertRepository
from backend.repositories.mongo_incident_repository import MongoIncidentRepository
from backend.repositories.mongo_detection_repository import MongoDetectionRepository
from backend.repositories.mongo_user_repository import MongoUserRepository
from backend.repositories.mongo_response_repository import (
    MongoResponseRepository,
    MongoResponseAuditRepository,
)

from backend.database.mongodb import get_db_manager
from backend.config.settings import get_settings
from backend.schemas.agent import AgentResponse
from backend.schemas.alert import AlertResponse
from backend.schemas.incident import IncidentResponse
from backend.schemas.detection import DetectionResponse
from backend.schemas.user import UserInDB
from backend.schemas.response import ResponseActionResponse, ResponseAuditLog

# Singleton Mongo Repositories
mongo_agent_repo = MongoAgentRepository()
mongo_alert_repo = MongoAlertRepository()
mongo_incident_repo = MongoIncidentRepository()
mongo_detection_repo = MongoDetectionRepository()
mongo_user_repo = MongoUserRepository()
mongo_response_repo = MongoResponseRepository()
mongo_response_audit_repo = MongoResponseAuditRepository()

# Optional overrides for test suites
_overrides: Dict[str, Any] = {}


def set_repository_override(entity: str, repo: Optional[Any]) -> None:
    """Sets or clears a repository override for testing."""
    if repo is None:
        _overrides.pop(entity, None)
    else:
        _overrides[entity] = repo


def get_agent_repository() -> BaseRepository[AgentResponse]:
    """Returns active Agent repository (MongoDB if connected/configured, else In-Memory)."""
    if "agent" in _overrides:
        return _overrides["agent"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_agent_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_agent_repo

    return in_memory_agent_repo


def get_alert_repository() -> BaseRepository[AlertResponse]:
    """Returns active Alert repository (MongoDB if connected/configured, else In-Memory)."""
    if "alert" in _overrides:
        return _overrides["alert"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_alert_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_alert_repo

    return in_memory_alert_repo


def get_incident_repository() -> BaseRepository[IncidentResponse]:
    """Returns active Incident repository (MongoDB if connected/configured, else In-Memory)."""
    if "incident" in _overrides:
        return _overrides["incident"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_incident_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_incident_repo

    return in_memory_incident_repo


def get_detection_repository() -> BaseRepository[DetectionResponse]:
    """Returns active Detection repository (MongoDB if connected/configured, else In-Memory)."""
    if "detection" in _overrides:
        return _overrides["detection"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_detection_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_detection_repo

    return in_memory_detection_repo


def get_user_repository() -> BaseRepository[UserInDB]:
    """Returns active User repository (MongoDB if connected/configured, else In-Memory)."""
    if "user" in _overrides:
        return _overrides["user"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_user_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_user_repo

    return in_memory_user_repo


def get_response_repository() -> BaseRepository[ResponseActionResponse]:
    """Returns active Response Action repository (MongoDB if connected/configured, else In-Memory)."""
    if "response" in _overrides:
        return _overrides["response"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_response_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_response_repo

    return in_memory_response_repo


def get_response_audit_repository() -> Any:
    """Returns active Response Audit repository (MongoDB if connected/configured, else In-Memory)."""
    if "response_audit" in _overrides:
        return _overrides["response_audit"]

    settings = get_settings()
    if settings.database_backend == "memory":
        return in_memory_response_audit_repo

    db_mgr = get_db_manager()
    if db_mgr.is_connected and settings.database_backend in ("auto", "mongodb"):
        return mongo_response_audit_repo

    return in_memory_response_audit_repo
