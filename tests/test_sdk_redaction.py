"""content capture redacts secrets and never repr's arbitrary objects"""

from __future__ import annotations

import pathlib
import sys
from dataclasses import dataclass

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from norinth_logger.privacy import redact_text, summarize_error, summarize_value  # noqa: E402


def test_redact_masks_common_secrets_and_identifiers():
    text = "email a@b.com ssn 123-45-6789 card 4111 1111 1111 1111 key sk-ABCDEF0123456789ABCD"
    out = redact_text(text)
    assert "a@b.com" not in out and "[redacted-email]" in out
    assert "123-45-6789" not in out and "[redacted-ssn]" in out
    assert "4111 1111 1111 1111" not in out and "[redacted-card]" in out
    assert "sk-ABCDEF0123456789ABCD" not in out and "[redacted-key]" in out


def test_captured_string_content_is_redacted():
    summary = summarize_value("contact me at jane@example.com", capture_content=True)
    assert summary["content"] == "contact me at [redacted-email]"


def test_captured_error_message_is_redacted():
    exc = ValueError("bad token sk-ABCDEF0123456789ABCDEF for user x@y.com")
    result = summarize_error(exc, capture_content=True)
    assert "sk-ABCDEF0123456789ABCDEF" not in result["message"]
    assert "x@y.com" not in result["message"]


@dataclass
class _Config:
    api_key: str = "sk-super-secret-key-value-1234567890"


def test_arbitrary_object_is_never_repr_captured():
    # even with capture on, a config object must not be repr'd into content
    summary = summarize_value(_Config(), capture_content=True)
    assert "content" not in summary
    assert "sk-super-secret" not in str(summary)
    # still summarized by type + hash for correlation
    assert summary["type"] == "_Config"
    assert summary["hash"].startswith("sha256:")


def test_nested_content_is_redacted_recursively():
    payload = {"messages": [{"role": "user", "content": "my card is 4111111111111111"}]}
    summary = summarize_value(payload, capture_content=True)
    assert "4111111111111111" not in str(summary["content"])
