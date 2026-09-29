"""
RansomShield AI — Agent API Schemas
Phase 3A: Backend Foundation

Defines Pydantic schemas for endpoint agent registration, status, and reporting.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time


class AgentRegisterRequest(BaseModel):
    """Payload sent by an endpoint agent to register with the backend."""
    agent_id: str = Field(..., description="Unique identifier of the endpoint agent")
    hostname: str = Field(..., description="Computer hostname")
    os_name: str = Field("Windows", description="Operating system name")
    os_version: str = Field("", description="Operating system build/version")
    agent_version: str = Field("0.1.0", description="Installed agent software version")
    ip_address: Optional[str] = Field(None, description="Primary network IP address")
    monitored_directories: List[str] = Field(default_factory=list, description="Directories actively monitored")


class AgentResponse(BaseModel):
    """Representation of a registered endpoint agent."""
    agent_id: str
    hostname: str
    os_name: str
    os_version: str
    agent_version: str
    status: str = Field("online", description="Agent state: online, offline, degraded")
    last_seen: float
    ip_address: Optional[str] = None
    monitored_directories: List[str] = Field(default_factory=list)
    registered_at: float


class AgentStatusResponse(BaseModel):
    """Real-time diagnostic health and metric status of an agent."""
    agent_id: str
    status: str
    is_online: bool
    last_seen: float
    uptime_seconds: float = 0.0
    metrics: Dict[str, Any] = Field(default_factory=dict)
    buffer_stats: Optional[Dict[str, Any]] = None
    alerts: Dict[str, Any] = Field(default_factory=dict)
    incidents: Dict[str, Any] = Field(default_factory=dict)
