"""smoke tests for the sdk"""

from __future__ import annotations

import pathlib
import sys

SDK_DIR = pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"
sys.path.insert(0, str(SDK_DIR))


def test_sdk_imports():
    import norinth_logger

    assert hasattr(norinth_logger, "init")


def test_privacy_summary_is_metadata_only_by_default():
    from norinth_logger.privacy import summarize_value

    summary = summarize_value("a secret prompt", capture_content=False)
    # without capture_content, the raw value must not be present
    assert "content" not in summary
    assert summary["hash"].startswith("sha256:")
    assert summary["type"] == "str"


def test_privacy_summary_includes_content_when_opted_in():
    from norinth_logger.privacy import summarize_value

    summary = summarize_value("visible", capture_content=True)
    assert summary["content"] == "visible"
