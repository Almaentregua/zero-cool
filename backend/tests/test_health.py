"""Tests for the health endpoint and app configuration."""

import pytest
from fastapi.testclient import TestClient

from zero_cool_api.main import app, get_cors_origins


def test_health_returns_ok() -> None:
    response = TestClient(app).get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_cors_origins_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    assert get_cors_origins() == ["http://localhost:5173"]


def test_cors_origins_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "http://a.test, http://b.test,")
    assert get_cors_origins() == ["http://a.test", "http://b.test"]
