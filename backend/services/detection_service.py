"""
RansomShield AI — Detection Service
Phase 3A: Backend Foundation

Encapsulates business logic for streaming and retrieving live Model V2 DetectionResult records.
"""

import time
import uuid
from typing import List, Optional, Dict, Any

from backend.schemas.detection import DetectionIngestRequest, DetectionResponse
from backend.repositories.base import BaseRepository
from backend.repositories import get_detection_repository


class DetectionService:
    """
    Business service layer for raw live ML detection results.
    """

    def __init__(self, repository: Optional[BaseRepository[DetectionResponse]] = None):
        self._repository = repository

    @property
    def repository(self) -> BaseRepository[DetectionResponse]:
        if self._repository is not None:
            return self._repository
        return get_detection_repository()

    async def ingest_detection(self, req: DetectionIngestRequest) -> DetectionResponse:
        """Stores a streamed live DetectionResult from an agent."""
        now = time.time()
        detection_id = req.detection_id or f"det-{uuid.uuid4().hex[:12]}"

        detection = DetectionResponse(
            detection_id=detection_id,
            endpoint_id=req.endpoint_id,
            timestamp=req.timestamp,
            window_seconds=req.window_seconds,
            prediction=req.prediction,
            confidence=req.confidence,
            risk_score=req.risk_score,
            probabilities=req.probabilities,
            model_version=req.model_version,
            stage=req.stage,
            features=req.features,
            indicators=req.indicators,
            explanation=req.explanation,
            event_count=req.event_count,
            duration_ms=req.duration_ms,
            created_at=now,
        )
        return await self.repository.create(detection)

    async def get_detection(self, detection_id: str) -> Optional[DetectionResponse]:
        """Retrieves a detection record by ID."""
        return await self.repository.get_by_id(detection_id)

    async def list_detections(
        self,
        limit: int = 50,
        offset: int = 0,
        endpoint_id: Optional[str] = None,
        prediction: Optional[str] = None,
    ) -> List[DetectionResponse]:
        """Lists detection records matching optional filters."""
        return await self.repository.list(
            limit=limit,
            offset=offset,
            endpoint_id=endpoint_id,
            prediction=prediction,
        )


# Singleton service instance
detection_service = DetectionService()


def get_detection_service() -> DetectionService:
    return detection_service
