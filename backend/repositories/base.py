"""
RansomShield AI — Repository Base Interfaces
Phase 3A: Backend Foundation

Defines abstract base repository interfaces for pluggable storage implementations
(In-Memory for Phase 3A, MongoDB for Phase 3B).
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional, List, Dict, Any


T = TypeVar("T")


class BaseRepository(Generic[T], ABC):
    """
    Abstract generic base repository interface.
    """

    @abstractmethod
    async def create(self, item: T) -> T:
        """Saves a new entity."""
        pass

    @abstractmethod
    async def get_by_id(self, item_id: str) -> Optional[T]:
        """Retrieves an entity by unique ID."""
        pass

    @abstractmethod
    async def list(self, limit: int = 50, offset: int = 0, **filters: Any) -> List[T]:
        """Lists entities with optional filtering and pagination."""
        pass

    @abstractmethod
    async def update(self, item_id: str, updates: Dict[str, Any]) -> Optional[T]:
        """Updates an existing entity."""
        pass

    @abstractmethod
    async def delete(self, item_id: str) -> bool:
        """Deletes an entity."""
        pass
