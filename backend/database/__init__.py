"""
RansomShield AI — Database Module
"""

from backend.database.mongodb import MongoDBManager, get_db_manager, db_manager

__all__ = ["MongoDBManager", "get_db_manager", "db_manager"]
