"""
RansomShield AI — Agent HTTP Network Client
Phase 3C: Agent ↔ Backend Real-Time Communication

Manages synchronous HTTP requests from the endpoint agent to the FastAPI backend
using httpx. Enforces timeouts, validates envelopes, and gracefully handles network errors.
"""

import logging
from typing import Dict, Any, Optional, Tuple, Union
import httpx

logger = logging.getLogger("RansomShieldNetworkClient")


class AgentNetworkClient:
    """
    HTTP client for Windows endpoint agent communication with the FastAPI backend.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 5.0,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key
        headers = {"X-Agent-Key": self.api_key} if self.api_key else {}
        self._client = client or httpx.Client(timeout=self.timeout, headers=headers)
        self._custom_client = client is not None

    def close(self) -> None:
        """Closes the underlying HTTP client session."""
        if not self._custom_client and self._client:
            try:
                self._client.close()
            except Exception:
                pass

    def _url(self, path: str) -> str:
        clean_path = path.lstrip("/")
        return f"{self.base_url}/{clean_path}"

    def _headers(self) -> Dict[str, str]:
        return {"X-Agent-Key": self.api_key} if self.api_key else {}

    def register(self, payload: Dict[str, Any]) -> Tuple[bool, int, Union[Dict[str, Any], str]]:
        """
        Registers an endpoint agent with the backend.
        POST /api/v1/agents/register
        """
        url = self._url("/api/v1/agents/register")
        try:
            resp = self._client.post(url, json=payload, timeout=self.timeout, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                return True, resp.status_code, data.get("data", data)
            return False, resp.status_code, resp.text
        except httpx.TimeoutException as e:
            return False, 408, f"Request timeout to {url}: {e}"
        except httpx.RequestError as e:
            return False, 503, f"Network request error to {url}: {e}"
        except Exception as e:
            return False, 500, f"Unexpected error communicating with {url}: {e}"

    def send_heartbeat(self, agent_id: str) -> Tuple[bool, int, Union[Dict[str, Any], str]]:
        """
        Sends an explicit heartbeat update for the registered agent.
        POST /api/v1/agents/{agent_id}/heartbeat
        """
        url = self._url(f"/api/v1/agents/{agent_id}/heartbeat")
        try:
            resp = self._client.post(url, timeout=self.timeout, headers=self._headers())
            if resp.status_code == 200:
                data = resp.json()
                return True, resp.status_code, data.get("data", data)
            return False, resp.status_code, resp.text
        except httpx.TimeoutException as e:
            return False, 408, f"Heartbeat timeout: {e}"
        except httpx.RequestError as e:
            return False, 503, f"Heartbeat network error: {e}"
        except Exception as e:
            return False, 500, f"Heartbeat error: {e}"

    def send_detection(self, payload: Dict[str, Any]) -> Tuple[bool, int, Union[Dict[str, Any], str]]:
        """
        Transmits a Model V2 DetectionResult ingestion payload to backend.
        POST /api/v1/detections
        """
        url = self._url("/api/v1/detections")
        try:
            resp = self._client.post(url, json=payload, timeout=self.timeout, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                return True, resp.status_code, data.get("data", data)
            return False, resp.status_code, resp.text
        except httpx.TimeoutException as e:
            return False, 408, f"Detection transmission timeout: {e}"
        except httpx.RequestError as e:
            return False, 503, f"Detection network error: {e}"
        except Exception as e:
            return False, 500, f"Detection transmission error: {e}"

    def send_alert(self, payload: Dict[str, Any]) -> Tuple[bool, int, Union[Dict[str, Any], str]]:
        """
        Transmits a DetectionAlert payload to backend.
        POST /api/v1/alerts
        """
        url = self._url("/api/v1/alerts")
        try:
            resp = self._client.post(url, json=payload, timeout=self.timeout, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                return True, resp.status_code, data.get("data", data)
            return False, resp.status_code, resp.text
        except httpx.TimeoutException as e:
            return False, 408, f"Alert transmission timeout: {e}"
        except httpx.RequestError as e:
            return False, 503, f"Alert network error: {e}"
        except Exception as e:
            return False, 500, f"Alert transmission error: {e}"

    def send_incident(self, payload: Dict[str, Any]) -> Tuple[bool, int, Union[Dict[str, Any], str]]:
        """
        Transmits an Incident payload to backend.
        POST /api/v1/incidents
        """
        url = self._url("/api/v1/incidents")
        try:
            resp = self._client.post(url, json=payload, timeout=self.timeout, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                return True, resp.status_code, data.get("data", data)
            return False, resp.status_code, resp.text
        except httpx.TimeoutException as e:
            return False, 408, f"Incident transmission timeout: {e}"
        except httpx.RequestError as e:
            return False, 503, f"Incident network error: {e}"
        except Exception as e:
            return False, 500, f"Incident transmission error: {e}"

    def check_health(self) -> bool:
        """Checks if the backend is reachable via GET /api/v1/health."""
        url = self._url("/api/v1/health")
        try:
            resp = self._client.get(url, timeout=min(2.0, self.timeout))
            return resp.status_code == 200
        except Exception:
            return False
