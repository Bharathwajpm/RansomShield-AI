"""
RansomShield AI — Backend Repositories Module
Phase 3B: MongoDB Persistence Layer
"""

from backend.repositories.base import BaseRepository
from backend.repositories.agent_repository import AgentRepository, agent_repository as in_memory_agent_repository
from backend.repositories.alert_repository import AlertRepository, alert_repository as in_memory_alert_repository
from backend.repositories.incident_repository import IncidentRepository, incident_repository as in_memory_incident_repository
from backend.repositories.detection_repository import DetectionRepository, detection_repository as in_memory_detection_repository

from backend.repositories.mongo_agent_repository import MongoAgentRepository
from backend.repositories.mongo_alert_repository import MongoAlertRepository
from backend.repositories.mongo_incident_repository import MongoIncidentRepository
from backend.repositories.mongo_detection_repository import MongoDetectionRepository

from backend.repositories.factory import (
    get_agent_repository,
    get_alert_repository,
    get_incident_repository,
    get_detection_repository,
    set_repository_override,
    mongo_agent_repo,
    mongo_alert_repo,
    mongo_incident_repo,
    mongo_detection_repo,
)

# For backward compatibility with existing tests that directly imported singleton references:
agent_repository = in_memory_agent_repository
alert_repository = in_memory_alert_repository
incident_repository = in_memory_incident_repository
detection_repository = in_memory_detection_repository

__all__ = [
    "BaseRepository",
    "AgentRepository",
    "AlertRepository",
    "IncidentRepository",
    "DetectionRepository",
    "MongoAgentRepository",
    "MongoAlertRepository",
    "MongoIncidentRepository",
    "MongoDetectionRepository",
    "get_agent_repository",
    "get_alert_repository",
    "get_incident_repository",
    "get_detection_repository",
    "set_repository_override",
    "agent_repository",
    "alert_repository",
    "incident_repository",
    "detection_repository",
    "mongo_agent_repo",
    "mongo_alert_repo",
    "mongo_incident_repo",
    "mongo_detection_repo",
]
