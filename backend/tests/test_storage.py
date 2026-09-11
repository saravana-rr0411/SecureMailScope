import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.storage.supabase_client import get_supabase_client, is_supabase_configured
from app.storage.repository import (
    extract_storage_row,
    format_db_row_to_capture,
    save_analysis_result,
    get_analysis_results,
    get_analysis_result,
    delete_analysis_result,
    TABLE_NAME,
)

client = TestClient(app)


def test_extract_storage_row_comprehensive():
    """Verifies that all required Supabase columns are accurately extracted from analysis result."""
    mock_result = {
        "filename": "sample_tls.pcap",
        "capture_id": "pcap_sample_tls.pcap",
        "analyzed_at": "2026-09-11T12:00:00Z",
        "protocols": [{"protocol": "SMTP"}],
        "ai_risk": {
            "score": 15.5,
            "operational_risk_tier": "LOW",
            "label": "LOW"
        },
        "posture": {
            "score": 100,
            "security_posture": "SECURE"
        },
        "sessions": [
            {
                "session_id": "TCP-001",
                "protocol": "SMTP",
                "tls": {
                    "detected": True,
                    "version": "TLSv1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    "certificate": {
                        "expiration_status": "VALID",
                        "self_signed": False
                    }
                },
                "assessment": {
                    "findings": [
                        {"finding_id": "SEC-001", "title": "Test Finding", "severity": "LOW"}
                    ]
                },
                "ai_analysis": {
                    "anomaly_detected": False,
                    "prediction": "NORMAL"
                }
            }
        ]
    }

    row = extract_storage_row(mock_result)

    assert row["capture_id"] == "pcap_sample_tls.pcap"
    assert row["filename"] == "sample_tls.pcap"
    assert row["protocol"] == "SMTP"
    assert row["analyzed_at"] == "2026-09-11T12:00:00Z"
    assert row["ai_risk_score"] == 15.5
    assert row["ai_risk_tier"] == "LOW"
    assert row["posture_status"] == "SECURE"
    assert row["security_posture"] in (100, "SECURE")
    assert row["anomaly_status"] == "NORMAL"
    assert row["tls_version"] == "TLSv1.3"
    assert row["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert row["certificate_status"] == "VALID"
    assert isinstance(row["findings"], list)
    assert len(row["findings"]) == 1
    assert row["findings"][0]["finding_id"] == "SEC-001"


def test_format_db_row_to_capture():
    """Verifies that database rows are formatted into frontend-compatible capture structures."""
    db_row = {
        "id": 42,
        "capture_id": "pcap_test.pcap",
        "filename": "test.pcap",
        "protocol": "IMAP",
        "analyzed_at": "2026-09-11T12:00:00Z",
        "ai_risk_score": 72.0,
        "ai_risk_tier": "HIGH",
        "security_posture": 30,
        "posture_status": "AT_RISK",
        "anomaly_status": "ANOMALOUS",
        "tls_version": "TLSv1.0",
        "cipher": "TLS_RSA_WITH_RC4_128_MD5",
        "certificate_status": "EXPIRED",
        "findings": [
            {"finding_id": "SEC-002", "title": "Expired Certificate", "severity": "HIGH"}
        ]
    }

    capture = format_db_row_to_capture(db_row)

    assert capture["capture_id"] == "pcap_test.pcap"
    assert capture["filename"] == "test.pcap"
    assert capture["ai_risk"]["score"] == 72.0
    assert capture["ai_risk"]["operational_risk_tier"] == "HIGH"
    assert capture["posture"]["score"] == 30
    assert capture["posture"]["security_posture"] == "AT_RISK"
    assert len(capture["sessions"]) == 1
    assert capture["sessions"][0]["tls"]["version"] == "TLSv1.0"
    assert capture["sessions"][0]["tls"]["cipher_suite"] == "TLS_RSA_WITH_RC4_128_MD5"
    assert capture["sessions"][0]["tls"]["certificate"]["expiration_status"] == "EXPIRED"
    assert len(capture["findings"]) == 1


def test_supabase_client_missing_env_vars(monkeypatch):
    """Verifies that missing SUPABASE_URL or SUPABASE_KEY raises a clear RuntimeError."""
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_KEY", raising=False)

    from app.storage.supabase_client import reset_supabase_client
    reset_supabase_client()

    with pytest.raises(RuntimeError) as exc_info:
        get_supabase_client()

    assert "Missing required Supabase environment variable(s)" in str(exc_info.value)
    assert "SUPABASE_URL" in str(exc_info.value)
    assert "SUPABASE_KEY" in str(exc_info.value)


def test_repository_save_insert_when_new():
    """Verifies save_analysis_result calls insert when capture_id does not exist."""
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table

    # Existing query returns empty data
    select_query = MagicMock()
    select_query.eq.return_value.execute.return_value.data = []
    mock_table.select.return_value = select_query

    # Insert returns inserted row
    mock_table.insert.return_value.execute.return_value.data = [{
        "id": 1,
        "capture_id": "pcap_new.pcap",
        "analyzed_at": "2026-09-11T12:00:00Z"
    }]

    sample_result = {
        "filename": "new.pcap",
        "capture_id": "pcap_new.pcap",
        "protocols": [{"protocol": "SMTP"}],
    }

    with patch("app.storage.repository.get_supabase_client", return_value=mock_client):
        saved = save_analysis_result(sample_result)

    assert saved["id"] == 1
    assert sample_result["id"] == 1
    mock_table.insert.assert_called_once()
    mock_table.update.assert_not_called()


def test_repository_save_update_when_existing():
    """Verifies TASK 5 duplicate replacement behavior: calls update when capture_id exists."""
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table

    # Existing query returns an existing row with id=99
    select_query = MagicMock()
    select_query.eq.return_value.execute.return_value.data = [{"id": 99, "capture_id": "pcap_existing.pcap"}]
    mock_table.select.return_value = select_query

    # Update returns updated row
    mock_table.update.return_value.eq.return_value.execute.return_value.data = [{
        "id": 99,
        "capture_id": "pcap_existing.pcap",
        "analyzed_at": "2026-09-11T13:00:00Z"
    }]

    sample_result = {
        "filename": "existing.pcap",
        "capture_id": "pcap_existing.pcap",
        "protocols": [{"protocol": "SMTP"}],
    }

    with patch("app.storage.repository.get_supabase_client", return_value=mock_client):
        saved = save_analysis_result(sample_result)

    assert saved["id"] == 99
    assert sample_result["id"] == 99
    mock_table.update.assert_called_once()
    mock_table.insert.assert_not_called()


def test_api_captures_unconfigured():
    """Verifies GET /api/captures returns empty list when Supabase is unconfigured."""
    with patch("app.main.is_supabase_configured", return_value=False):
        response = client.get("/api/captures")
        assert response.status_code == 200
        assert response.json() == []


def test_api_captures_configured():
    """Verifies GET /api/captures returns capture history when configured."""
    mock_captures = [
        format_db_row_to_capture({
            "id": 1,
            "capture_id": "pcap_alpha.pcap",
            "filename": "alpha.pcap",
            "protocol": "SMTP",
            "analyzed_at": "2026-09-11T12:00:00Z",
            "ai_risk_score": 10.0,
            "ai_risk_tier": "LOW",
            "security_posture": 100,
            "posture_status": "SECURE",
            "anomaly_status": "NORMAL",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_status": "VALID",
            "findings": []
        })
    ]

    with patch("app.main.is_supabase_configured", return_value=True), \
         patch("app.main.get_analysis_results", return_value=mock_captures):
        response = client.get("/api/captures")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["capture_id"] == "pcap_alpha.pcap"
        assert data[0]["filename"] == "alpha.pcap"
        assert data[0]["ai_risk"]["score"] == 10.0
