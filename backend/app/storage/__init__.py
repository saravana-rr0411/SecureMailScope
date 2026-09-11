"""
SecureMailScope Storage Layer
Handles persistent storage and retrieval of forensic PCAP analysis results using Supabase PostgreSQL.
"""

from app.storage.supabase_client import get_supabase_client, is_supabase_configured
from app.storage.repository import (
    save_analysis_result,
    get_analysis_results,
    get_analysis_result,
    delete_analysis_result,
)

__all__ = [
    "get_supabase_client",
    "is_supabase_configured",
    "save_analysis_result",
    "get_analysis_results",
    "get_analysis_result",
    "delete_analysis_result",
]
