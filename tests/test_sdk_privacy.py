"""sdk privacy hardening: keyed hashing, error summarization, context inference"""

from __future__ import annotations

import pathlib
import sys

SDK_DIR = pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"
sys.path.insert(0, str(SDK_DIR))


def test_hash_is_keyed_and_not_plain_sha256():
    import hashlib
    import hmac

    from norinth_logger.privacy import stable_hash

    plain = stable_hash("reset my password")
    keyed = stable_hash("reset my password", hash_key="tenant-secret")
    # keyed digest differs from plain sha256, so short low-entropy inputs
    # aren't dictionary-reversible or cross-tenant linkable
    assert keyed != plain
    expected = "sha256:" + hmac.new(b"tenant-secret", b"reset my password", hashlib.sha256).hexdigest()
    assert keyed == expected


def test_hash_is_canonical_for_structured_values():
    from norinth_logger.privacy import stable_hash

    # dict key order must not change the fingerprint
    assert stable_hash({"a": 1, "b": 2}) == stable_hash({"b": 2, "a": 1})


def test_exception_message_is_hidden_by_default():
    from norinth_logger.privacy import summarize_error

    exc = ValueError("invalid SSN 123-45-6789 for patient jane@hospital.org")
    summary = summarize_error(exc, capture_content=False, hash_key="k")
    assert summary["type"] == "ValueError"
    assert "message" not in summary  # raw pii/phi never emitted by default
    assert summary["message_hash"].startswith("sha256:")
    assert summary["message_size"] > 0

    # with capture enabled the message is included but still redacted:
    # exception type preserved while ssns/emails are masked
    revealed = summarize_error(exc, capture_content=True, hash_key="k")
    assert "123-45-6789" not in revealed["message"]
    assert "jane@hospital.org" not in revealed["message"]
    assert "[redacted-ssn]" in revealed["message"]


def test_inferred_context_caps_length_and_skips_nested():
    from norinth_logger.privacy import infer_governance_context

    long_use_case = "x" * 5000
    payload = {
        "tenant_id": "acme",
        "user_id": "u@acme.test",
        "use_case": long_use_case,
        # nested structure under a governance field must not be stringified
        "model_purpose": {"secret": "do not stringify me"},
    }
    context = infer_governance_context((payload,), {})
    # platform routing tenant is never inferred from app data; the app's
    # own tenant is recorded under subject_tenant instead
    assert "tenant_id" not in context
    assert context["subject_tenant"] == "acme"
    assert len(context["use_case"]) <= 256
    assert "model_purpose" not in context  # nested value skipped


def test_summarize_value_never_emits_content_without_optin():
    from norinth_logger.privacy import summarize_value

    summary = summarize_value("patient note: confidential", capture_content=False, hash_key="k")
    assert "content" not in summary
    assert summary["hash"].startswith("sha256:")
