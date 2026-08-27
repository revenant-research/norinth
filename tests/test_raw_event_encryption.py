"""raw event bodies encrypted at rest while governance columns stay queryable"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _event(content: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": "t1",
        "span_id": "s1",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": "success",
        "attributes": {
            "provider": "openai",
            "model": "gpt-4o",
            "metadata": {"application_name": "Claims"},
            "prompt": {"content": content},
        },
    }


def test_raw_event_is_ciphertext_but_columns_are_queryable(client, monkeypatch):
    monkeypatch.setenv("NORINTH_ENCRYPT_RAW_EVENTS", "1")
    from app.storage.raw_events import connect, insert_events, list_events

    secret_text = "PATIENT-SSN-123-45-6789"
    assert len(insert_events([_event(secret_text)])) == 1

    # on disk the raw_event is ciphertext; the plaintext never appears
    with connect() as connection:
        row = connection.execute("SELECT raw_event, application_name, provider FROM sdk_events").fetchone()
    assert secret_text not in row["raw_event"]
    assert row["raw_event"].startswith("enc:v2:")  # aes-gcm ciphertext, not json
    # extracted governance columns stay in plaintext for querying
    assert row["application_name"] == "Claims"
    assert row["provider"] == "openai"

    # reads decrypt transparently
    events = list_events(tenant_id=None, project="p1", environment="prod")
    assert events[0]["attributes"]["prompt"]["content"] == secret_text


def test_raw_events_are_encrypted_by_default_when_a_key_is_configured(client, monkeypatch):
    """no flag set, key present -> ciphertext

    the flag used to default off, so an install that configured a key and captured
    content still wrote prompts and responses to disk in the clear until someone
    found the variable. protection now follows the key
    """
    monkeypatch.delenv("NORINTH_ENCRYPT_RAW_EVENTS", raising=False)
    from app.storage.db import connect
    from app.storage.raw_events import insert_events, list_events

    secret_text = "patient Jane Q. Patient, MRN-4417233"
    assert len(insert_events([_event(secret_text)])) == 1
    with connect() as connection:
        row = connection.execute("SELECT raw_event FROM sdk_events").fetchone()
    assert secret_text not in row["raw_event"]
    assert row["raw_event"].startswith("enc:v2:")

    events = list_events(tenant_id=None, project="p1", environment="prod")
    assert events[0]["attributes"]["prompt"]["content"] == secret_text


def test_an_operator_can_still_opt_out_explicitly(client, monkeypatch):
    """some operators need the column queryable; the opt-out has to be a deliberate act"""
    monkeypatch.setenv("NORINTH_ENCRYPT_RAW_EVENTS", "0")
    from app.storage.db import connect
    from app.storage.raw_events import insert_events

    assert len(insert_events([_event("hello world")])) == 1
    with connect() as connection:
        row = connection.execute("SELECT raw_event FROM sdk_events").fetchone()
    assert "hello world" in row["raw_event"]


def test_a_keyless_install_stores_plaintext_rather_than_failing(client, monkeypatch):
    """secret_store.encrypt fails closed, so defaulting on must not break keyless dev"""
    monkeypatch.delenv("NORINTH_ENCRYPT_RAW_EVENTS", raising=False)
    monkeypatch.delenv("NORINTH_SECRET_KEY", raising=False)
    monkeypatch.delenv("NORINTH_SECRET_KEYS", raising=False)
    from app.storage.raw_events import insert_events, list_events

    assert len(insert_events([_event("hello world")])) == 1
    events = list_events(tenant_id=None, project="p1", environment="prod")
    assert events[0]["attributes"]["prompt"]["content"] == "hello world"
