"""readiness includes the database; liveness deliberately does not

both k8s probes pointed at /health, which skips the db — so a pod with a
dead database reported Ready and stayed in the load balancer serving errors.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_ready_when_database_answers(super_admin_client):
    response = super_admin_client.get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True and body["database"] == "ok"


def test_not_ready_when_database_is_unreachable(super_admin_client, monkeypatch):
    import app.api.routes as routes

    def broken_connect():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(routes, "connect", broken_connect)
    response = super_admin_client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["ok"] is False


def test_liveness_stays_database_free(super_admin_client, monkeypatch):
    """a db outage must not make the orchestrator kill and churn pods"""
    import app.api.routes as routes

    def broken_connect():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(routes, "connect", broken_connect)
    assert super_admin_client.get("/health").status_code == 200
