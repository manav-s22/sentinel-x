
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


@pytest.fixture
def client():
    # Give every test its own temporary in-memory database.
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )

    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def test_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "Sentinel X API"
    assert data["analysis_method"] == "heuristic"


def test_https_url_analysis(client):
    response = client.post(
        "/api/analyze-url",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["hostname"] == "example.com"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "Low"
    assert data["analysis_method"] == "heuristic"
    assert data["scan_id"] is not None
    assert data["created_at"] is not None
    assert isinstance(data["signals"], list)
    assert "not a calibrated probability" in data["disclaimer"]


def test_suspicious_signals_are_reported(client):
    response = client.post(
        "/api/analyze-url",
        json={"url": "http://192.0.2.1/login"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["hostname"] == "192.0.2.1"
    assert data["risk_score"] == 43
    assert data["risk_level"] == "Medium"

    signal_names = [item["signal"] for item in data["signals"]]
    assert "No HTTPS" in signal_names
    assert "IP address hostname" in signal_names
    assert "Sensitive-action keywords" in signal_names


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "https://",
        "https://example.com:99999",
        "",
        "   ",
        "https://example.com/" + ("a" * 2048),
    ],
)
def test_invalid_urls_are_rejected(client, url):
    response = client.post(
        "/api/analyze-url",
        json={"url": url},
    )

    assert response.status_code == 422


def test_missing_url_is_rejected(client):
    response = client.post("/api/analyze-url", json={})

    assert response.status_code == 422


def test_scan_is_saved_to_history(client):
    analysis = client.post(
        "/api/analyze-url",
        json={"url": "https://example.com"},
    )
    assert analysis.status_code == 200

    scan_id = analysis.json()["scan_id"]

    history = client.get("/api/history")
    assert history.status_code == 200

    records = history.json()
    assert len(records) == 1
    assert records[0]["scan_id"] == scan_id
    assert records[0]["hostname"] == "example.com"


def test_history_is_newest_first(client):
    first = client.post(
        "/api/analyze-url",
        json={"url": "https://example.com"},
    )
    second = client.post(
        "/api/analyze-url",
        json={"url": "https://example.org"},
    )

    assert first.status_code == 200
    assert second.status_code == 200

    history = client.get("/api/history")
    assert history.status_code == 200

    records = history.json()
    assert len(records) == 2
    assert records[0]["scan_id"] == second.json()["scan_id"]
    assert records[1]["scan_id"] == first.json()["scan_id"]


def test_history_limit_is_validated(client):
    assert client.get("/api/history?limit=1").status_code == 200
    assert client.get("/api/history?limit=0").status_code == 422
    assert client.get("/api/history?limit=501").status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "https://bad..example.com",
        "https://-bad.example.com",
        "https://bad-.example.com",
        "https://exa mple.com",
    ],
)
def test_invalid_hostnames_are_rejected(client, url):
    response = client.post(
        "/api/analyze-url",
        json={"url": url},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"url": None},
        {"url": ["https://example.com"]},
        {"url": 12345},
    ],
)
def test_non_string_urls_are_rejected(client, payload):
    response = client.post("/api/analyze-url", json=payload)

    assert response.status_code == 422


def test_url_normalization(client):
    response = client.post(
        "/api/analyze-url",
        json={"url": "  HTTPS://Example.COM/path  "},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["hostname"] == "example.com"
    assert data["normalized_url"] == "https://example.com/path"


@pytest.mark.parametrize(
    "url, expected_score, expected_level",
    [
        ("https://example.com", 0, "Low"),
        ("http://192.0.2.1/login", 43, "Medium"),
        (
            "http://192.0.2.1@bit.ly/login?next=https://evil.test",
            66,
            "High",
        ),
    ],
)
def test_risk_scores_and_levels_are_consistent(
    client, url, expected_score, expected_level
):
    response = client.post(
        "/api/analyze-url",
        json={"url": url},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] == expected_score
    assert data["risk_level"] == expected_level

    # These examples have scores below 100, so no score capping applies.
    points_total = sum(
        signal["points"]
        for signal in data["signals"]
        if signal["points"] > 0
    )
    assert points_total == data["risk_score"]


def test_url_at_maximum_length_is_accepted(client):
    prefix = "https://example.com/"
    url = prefix + ("a" * (2048 - len(prefix)))

    response = client.post(
        "/api/analyze-url",
        json={"url": url},
    )

    assert response.status_code == 200
    assert len(response.json()["submitted_url"]) == 2048


def test_rejected_url_is_not_saved_to_history(client):
    response = client.post(
        "/api/analyze-url",
        json={"url": "ftp://example.com"},
    )

    assert response.status_code == 422

    history = client.get("/api/history")
    assert history.status_code == 200
    assert history.json() == []


def test_ipv6_url_is_accepted(client):
    response = client.post(
        "/api/analyze-url",
        json={"url": "https://[2001:db8::1]/"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["hostname"] == "2001:db8::1"
    assert data["analysis_method"] == "heuristic"


def test_signal_count_matches_positive_signals(client):
    response = client.post(
        "/api/analyze-url",
        json={"url": "http://192.0.2.1/login"},
    )

    assert response.status_code == 200
    data = response.json()

    positive_signals = [
        signal for signal in data["signals"]
        if signal["points"] > 0
    ]

    assert data["signal_count"] == len(positive_signals)


def test_history_limit_returns_requested_number(client):
    for url in [
        "https://example.com",
        "https://example.org",
        "https://example.net",
    ]:
        response = client.post(
            "/api/analyze-url",
            json={"url": url},
        )
        assert response.status_code == 200

    response = client.get("/api/history?limit=2")

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_cors_allows_frontend_origin(client):
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin")
        == "http://localhost:5173"
    )


def test_cors_does_not_authorize_unknown_origin(client):
    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert (
        response.headers.get("access-control-allow-origin")
        != "https://untrusted.example"
    )


def test_normalization_preserves_userinfo_case(client):
    response = client.post(
        "/api/analyze-url",
        json={
            "url": "https://UserName:PassWord@example.com/login"
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["normalized_url"] == (
        "https://UserName:PassWord@example.com/login"
    )
    assert data["hostname"] == "example.com"

    signal_names = [item["signal"] for item in data["signals"]]
    assert "URL contains @" in signal_names
