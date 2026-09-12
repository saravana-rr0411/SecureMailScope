import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_dashboard_periods_endpoint():
    response = client.get("/api/dashboard/periods")
    assert response.status_code == 200
    data = response.json()
    assert "dates" in data
    assert "months" in data
    assert isinstance(data["dates"], list)
    assert isinstance(data["months"], list)

    if len(data["dates"]) > 0:
        first_date = data["dates"][0]
        assert "value" in first_date
        assert "label" in first_date
        # Check ISO format YYYY-MM-DD
        assert len(first_date["value"]) == 10

    if len(data["months"]) > 0:
        first_month = data["months"][0]
        assert "value" in first_month
        assert "label" in first_month
        # Check ISO format YYYY-MM
        assert len(first_month["value"]) == 7


def test_dashboard_trends_daily_endpoint():
    # Test with explicit daily period
    response = client.get("/api/dashboard/trends?period=daily")
    assert response.status_code == 200
    data = response.json()
    assert data["period"] == "daily"
    assert "points" in data
    assert "summary" in data
    assert isinstance(data["points"], list)

    summary = data["summary"]
    assert "total" in summary
    assert "secure" in summary
    assert "insecure" in summary

    # If points exist, verify point fields required by ExecutiveDashboard graphs
    if len(data["points"]) > 0:
        pt = data["points"][0]
        assert "key" in pt
        assert "label" in pt
        assert "secureReports" in pt
        assert "insecureReports" in pt
        assert "avgRisk" in pt
        assert "riskLevel" in pt


def test_dashboard_trends_monthly_endpoint():
    response = client.get("/api/dashboard/trends?period=monthly")
    assert response.status_code == 200
    data = response.json()
    assert data["period"] == "monthly"
    assert "points" in data
    assert "summary" in data


def test_dashboard_trends_invalid_period():
    response = client.get("/api/dashboard/trends?period=yearly")
    assert response.status_code == 400
    assert "Invalid period type" in response.json()["detail"]


def test_dashboard_trends_invalid_date_format():
    response = client.get("/api/dashboard/trends?period=daily&date=invalid-date")
    assert response.status_code == 400


def test_dashboard_trends_invalid_month_format():
    response = client.get("/api/dashboard/trends?period=monthly&month=invalid-month")
    assert response.status_code == 400
