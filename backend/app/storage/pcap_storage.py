"""
Supabase Storage integration for persistent raw PCAP binary files.
Operates strictly server-side using the private 'pcaps' bucket.
"""

import os
import re
import uuid
import logging
from typing import Optional
from app.storage.supabase_client import get_supabase_client, is_supabase_configured

logger = logging.getLogger("securemailscope.pcap_storage")

PCAPS_BUCKET = "pcaps"
PCAP_MIME_TYPE = "application/vnd.tcpdump.pcap"


def sanitize_storage_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent directory traversal and invalid characters.
    Preserves alphanumeric, dashes, underscores, and dots.
    """
    base = os.path.basename(filename or "capture.pcap").strip()
    safe = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
    if not safe:
        safe = "capture.pcap"
    return safe


def generate_safe_pcap_storage_path(filename: str, capture_id: Optional[str] = None) -> str:
    """
    Generates a collision-safe, path-traversal-resistant storage path
    for storing a PCAP file in the private 'pcaps' Supabase bucket.

    Format: <prefix>_<uuid_token>.pcap
    """
    safe_name = sanitize_storage_filename(filename)
    stem, ext = os.path.splitext(safe_name)
    if ext.lower() not in (".pcap", ".pcapng"):
        ext = ".pcap"

    # Use capture_id prefix if available, otherwise filename stem
    prefix = capture_id if capture_id else stem
    safe_prefix = sanitize_storage_filename(prefix)
    if safe_prefix.endswith((".pcap", ".pcapng")):
        safe_prefix = os.path.splitext(safe_prefix)[0]

    # Append random collision-safe UUID token
    unique_suffix = uuid.uuid4().hex[:12]
    return f"{safe_prefix}_{unique_suffix}{ext}"


def upload_pcap_to_storage(storage_path: str, pcap_bytes: bytes) -> str:
    """
    Uploads raw PCAP bytes to the private 'pcaps' Supabase Storage bucket.
    Returns the storage path upon success.
    Raises RuntimeError on failure or if Supabase is unconfigured.
    """
    if not is_supabase_configured():
        raise RuntimeError("Supabase credentials not configured in environment.")

    clean_path = sanitize_storage_filename(storage_path)
    client = get_supabase_client()
    try:
        client.storage.from_(PCAPS_BUCKET).upload(
            clean_path,
            pcap_bytes,
            file_options={"content-type": PCAP_MIME_TYPE, "upsert": "true"},
        )
        logger.info(f"Successfully uploaded PCAP ({len(pcap_bytes)} bytes) to bucket '{PCAPS_BUCKET}' at '{clean_path}'")
        return clean_path
    except Exception as e:
        logger.error(f"Supabase Storage upload failure for '{clean_path}': {e}", exc_info=True)
        raise RuntimeError(f"Supabase Storage upload failure: {str(e)}") from e


def download_pcap_from_storage(storage_path: str) -> Optional[bytes]:
    """
    Downloads raw PCAP binary bytes from the private 'pcaps' Supabase Storage bucket.
    Returns bytes if found, None if file does not exist (404),
    or raises RuntimeError on connectivity/storage error.
    """
    if not is_supabase_configured():
        return None

    clean_path = sanitize_storage_filename(storage_path)
    client = get_supabase_client()
    try:
        data = client.storage.from_(PCAPS_BUCKET).download(clean_path)
        return data
    except Exception as e:
        err_str = str(e).lower()
        if "not_found" in err_str or "404" in err_str or "not found" in err_str:
            logger.info(f"PCAP '{clean_path}' not found in bucket '{PCAPS_BUCKET}'.")
            return None
        logger.error(f"Supabase Storage download failure for '{clean_path}': {e}", exc_info=True)
        raise RuntimeError(f"Supabase Storage download failure: {str(e)}") from e


def pcap_exists_in_storage(storage_path: str) -> bool:
    """
    Checks if a PCAP file exists in the private 'pcaps' bucket.
    """
    if not is_supabase_configured():
        return False

    clean_path = sanitize_storage_filename(storage_path)
    client = get_supabase_client()
    try:
        return bool(client.storage.from_(PCAPS_BUCKET).exists(clean_path))
    except Exception as e:
        logger.debug(f"Exists check note for '{clean_path}': {e}")
        return False


def delete_pcap_from_storage(storage_path: str) -> bool:
    """
    Deletes a PCAP file from the private 'pcaps' bucket.
    Returns True if successfully deleted or not found, False on error.
    """
    if not is_supabase_configured():
        return False

    clean_path = sanitize_storage_filename(storage_path)
    client = get_supabase_client()
    try:
        client.storage.from_(PCAPS_BUCKET).remove([clean_path])
        logger.info(f"Deleted PCAP '{clean_path}' from bucket '{PCAPS_BUCKET}'")
        return True
    except Exception as e:
        logger.warning(f"Failed to delete PCAP '{clean_path}' from bucket '{PCAPS_BUCKET}': {e}")
        return False
