import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from scapy.all import wrpcap, Ether, IP, TCP, Raw

from app.main import app, _recent_pcaps
from app.storage.pcap_storage import (
    sanitize_storage_filename,
    generate_safe_pcap_storage_path,
    upload_pcap_to_storage,
    download_pcap_from_storage,
    pcap_exists_in_storage,
    delete_pcap_from_storage,
    PCAPS_BUCKET,
)

client = TestClient(app)


def test_sanitize_storage_filename():
    """Verifies filename sanitization strips directory traversal and special chars."""
    assert sanitize_storage_filename("../../test.pcap") == "test.pcap"
    assert sanitize_storage_filename("/etc/passwd") == "passwd"
    assert sanitize_storage_filename("my capture file #1.pcap") == "my_capture_file__1.pcap"
    assert sanitize_storage_filename("") == "capture.pcap"


def test_generate_safe_pcap_storage_path():
    """Verifies collision-safe path generation."""
    path1 = generate_safe_pcap_storage_path("traffic.pcap")
    path2 = generate_safe_pcap_storage_path("traffic.pcap")
    assert path1 != path2
    assert path1.endswith(".pcap")
    assert ".." not in path1
    assert "/" not in path1

    # With capture_id prefix
    path_custom = generate_safe_pcap_storage_path("test.pcap", capture_id="pcap_session_123")
    assert path_custom.startswith("pcap_session_123_")
    assert path_custom.endswith(".pcap")


def test_upload_pcap_to_storage_success():
    """Verifies upload_pcap_to_storage calls Supabase client with proper bucket and headers."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_client.storage.from_.return_value = mock_bucket

    pcap_bytes = b"SAMPLE_PCAP_BYTES"
    storage_path = "pcap_test_12345.pcap"

    with patch("app.storage.pcap_storage.is_supabase_configured", return_value=True), \
         patch("app.storage.pcap_storage.get_supabase_client", return_value=mock_client):
        result_path = upload_pcap_to_storage(storage_path, pcap_bytes)

    assert result_path == storage_path
    mock_client.storage.from_.assert_called_once_with(PCAPS_BUCKET)
    mock_bucket.upload.assert_called_once_with(
        storage_path,
        pcap_bytes,
        file_options={"content-type": "application/vnd.tcpdump.pcap", "upsert": "true"}
    )


def test_upload_pcap_to_storage_failure():
    """Verifies upload_pcap_to_storage raises RuntimeError on upload error."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.upload.side_effect = Exception("Storage quota exceeded")
    mock_client.storage.from_.return_value = mock_bucket

    with patch("app.storage.pcap_storage.is_supabase_configured", return_value=True), \
         patch("app.storage.pcap_storage.get_supabase_client", return_value=mock_client):
        with pytest.raises(RuntimeError) as exc_info:
            upload_pcap_to_storage("error.pcap", b"data")

    assert "Supabase Storage upload failure" in str(exc_info.value)


def test_download_pcap_from_storage_success():
    """Verifies download_pcap_from_storage returns raw bytes from private bucket."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.download.return_value = b"DOWNLOADED_PCAP_BYTES"
    mock_client.storage.from_.return_value = mock_bucket

    with patch("app.storage.pcap_storage.is_supabase_configured", return_value=True), \
         patch("app.storage.pcap_storage.get_supabase_client", return_value=mock_client):
        data = download_pcap_from_storage("capture_valid.pcap")

    assert data == b"DOWNLOADED_PCAP_BYTES"
    mock_client.storage.from_.assert_called_once_with(PCAPS_BUCKET)
    mock_bucket.download.assert_called_once_with("capture_valid.pcap")


def test_download_pcap_from_storage_not_found():
    """Verifies download_pcap_from_storage returns None when file does not exist (404)."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.download.side_effect = Exception("StorageApiError: Object not found (404)")
    mock_client.storage.from_.return_value = mock_bucket

    with patch("app.storage.pcap_storage.is_supabase_configured", return_value=True), \
         patch("app.storage.pcap_storage.get_supabase_client", return_value=mock_client):
        data = download_pcap_from_storage("missing.pcap")

    assert data is None


def test_download_pcap_from_storage_service_error():
    """Verifies download_pcap_from_storage raises RuntimeError on connectivity failure."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.download.side_effect = ConnectionError("Supabase connection timed out")
    mock_client.storage.from_.return_value = mock_bucket

    with patch("app.storage.pcap_storage.is_supabase_configured", return_value=True), \
         patch("app.storage.pcap_storage.get_supabase_client", return_value=mock_client):
        with pytest.raises(RuntimeError) as exc_info:
            download_pcap_from_storage("file.pcap")

    assert "Supabase Storage download failure" in str(exc_info.value)


def test_pcap_exists_and_delete():
    """Verifies exists and delete helper functions."""
    mock_client = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.exists.return_value = True
    mock_bucket.remove.return_value = [{"name": "test.pcap"}]
    mock_client.storage.from_.return_value = mock_bucket

    with patch("app.storage.pcap_storage.is_supabase_configured", return_value=True), \
         patch("app.storage.pcap_storage.get_supabase_client", return_value=mock_client):
        assert pcap_exists_in_storage("test.pcap") is True
        assert delete_pcap_from_storage("test.pcap") is True

    mock_bucket.remove.assert_called_once_with(["test.pcap"])


def test_api_pcap_analyze_stores_pcap(tmp_path):
    """Verifies /api/pcap/analyze uploads to Supabase Storage and returns storage metadata."""
    pcap_file = tmp_path / "smtp_test.pcap"
    pkt = Ether()/IP(src="192.168.1.5", dst="192.168.1.25")/TCP(sport=2525, dport=25)/Raw(load=b"220 mail.test ESMTP\r\n")
    wrpcap(str(pcap_file), [pkt])

    mock_upload = MagicMock(return_value="smtp_test_uuid1234.pcap")

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.upload_pcap_to_storage", mock_upload), \
         patch("app.main.save_analysis_result") as mock_save:
        mock_save.return_value = {"id": 1, "capture_id": "pcap_smtp_test.pcap"}

        with open(pcap_file, "rb") as f:
            response = client.post(
                "/api/pcap/analyze",
                files={"file": ("smtp_test.pcap", f, "application/vnd.tcpdump.pcap")}
            )

    assert response.status_code == 200
    data = response.json()
    assert "pcap_storage_path" in data
    assert data["pcap_storage_path"].endswith(".pcap")
    assert data["pcap_download_url"] == f"/api/capture/download/{data['capture_id']}"
    assert data["pcap_filename"] == "smtp_test.pcap"
    assert data["pcap_size_bytes"] > 0
    mock_upload.assert_called_once()


def test_api_pcap_analyze_storage_failure(tmp_path):
    """Verifies /api/pcap/analyze returns 502 if Supabase storage upload fails."""
    pcap_file = tmp_path / "smtp_fail.pcap"
    pkt = Ether()/IP(src="192.168.1.5", dst="192.168.1.25")/TCP(sport=2525, dport=25)/Raw(load=b"220 mail.test ESMTP\r\n")
    wrpcap(str(pcap_file), [pkt])

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.upload_pcap_to_storage", side_effect=RuntimeError("Supabase Storage upload failure: Bucket full")):
        with open(pcap_file, "rb") as f:
            response = client.post(
                "/api/pcap/analyze",
                files={"file": ("smtp_fail.pcap", f, "application/vnd.tcpdump.pcap")}
            )

    assert response.status_code == 502
    assert "Supabase Storage upload failure" in response.json()["detail"]


def test_download_capture_from_supabase_storage():
    """Verifies /api/capture/download/{capture_id} retrieves and streams PCAP from Supabase Storage."""
    _recent_pcaps.clear()

    mock_meta = {
        "id": 10,
        "capture_id": "pcap_stored_sample.pcap",
        "filename": "stored_sample.pcap",
        "pcap_storage_path": "stored_sample_abc123.pcap",
        "pcap_filename": "stored_sample.pcap",
    }
    sample_bytes = b"BINARY_PCAP_STREAM_FROM_SUPABASE"

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.get_analysis_result", return_value=mock_meta), \
         patch("app.main.download_pcap_from_storage", return_value=sample_bytes) as mock_dl:
        response = client.get("/api/capture/download/pcap_stored_sample.pcap")

    assert response.status_code == 200
    assert response.content == sample_bytes
    assert response.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert 'attachment; filename="stored_sample.pcap"' in response.headers["content-disposition"]
    mock_dl.assert_called_once_with("stored_sample_abc123.pcap")


def test_download_capture_with_storage_path_param():
    """Verifies download using explicit ?storage_path= query parameter."""
    _recent_pcaps.clear()
    sample_bytes = b"BINARY_EXPLICIT_PATH"

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.download_pcap_from_storage", return_value=sample_bytes) as mock_dl:
        response = client.get("/api/capture/download/pcap_any?storage_path=direct_file_123.pcap")

    assert response.status_code == 200
    assert response.content == sample_bytes
    mock_dl.assert_called_once_with("direct_file_123.pcap")


def test_download_capture_missing_returns_404():
    """Verifies missing PCAP returns 404."""
    _recent_pcaps.clear()

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.get_analysis_result", return_value=None), \
         patch("app.main.download_pcap_from_storage", return_value=None):
        response = client.get("/api/capture/download/nonexistent_capture_xyz")

    assert response.status_code == 404
    assert "PCAP file not found or expired" in response.json()["detail"]


def test_download_capture_storage_failure_returns_502():
    """Verifies storage service error during download returns 502."""
    _recent_pcaps.clear()
    mock_meta = {
        "capture_id": "pcap_error.pcap",
        "pcap_storage_path": "error_file.pcap",
    }

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.get_analysis_result", return_value=mock_meta), \
         patch("app.main.download_pcap_from_storage", side_effect=RuntimeError("Supabase Storage download failure: 500")):
        response = client.get("/api/capture/download/pcap_error.pcap")

    assert response.status_code == 502
    assert "Supabase Storage download failure" in response.json()["detail"]


def test_download_capture_traversal_rejection():
    """Verifies directory traversal attacks are rejected with 400 or 404."""
    response = client.get("/api/capture/download/..%2F..%2Fetc%2Fpasswd")
    assert response.status_code in (400, 404)

    # In-route traversal pattern
    response_dot = client.get("/api/capture/download/test..traversal")
    assert response_dot.status_code == 400
    assert "Invalid capture identifier" in response_dot.json()["detail"]

    response2 = client.get("/api/capture/download/valid_id?storage_path=..%2Fsecret")
    assert response2.status_code == 400
    assert "Invalid storage path identifier" in response2.json()["detail"]
