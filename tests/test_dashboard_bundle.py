"""The dashboard bundle is a build artifact (not committed). The platform must
serve it when present and fail loudly -- not fall back to an alternative UI --
when it is absent."""

from __future__ import annotations

import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

STATIC_DIR = pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform" / "app" / "dashboard" / "static"
BUNDLE_PRESENT = (STATIC_DIR / "index.html").exists()


@pytest.mark.skipif(BUNDLE_PRESENT, reason="bundle is built in this checkout")
def test_root_is_503_when_dashboard_not_built(client):
    response = client.get("/")
    assert response.status_code == 503
    assert "dashboard has not been built" in response.text
    assert "make build-frontend" in response.text
    # API stays fully available regardless of the bundle.
    assert client.get("/health").status_code == 200


@pytest.mark.skipif(not BUNDLE_PRESENT, reason="bundle not built in this checkout")
def test_root_serves_built_index_and_assets(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache, no-store, must-revalidate"
    scripts = re.findall(r'src="(/assets/[^"]+\.js)"', response.text)
    styles = re.findall(r'href="(/assets/[^"]+\.css)"', response.text)
    assert scripts and styles, response.text[:400]
    for asset in scripts + styles:
        asset_response = client.get(asset)
        assert asset_response.status_code == 200, asset
        assert len(asset_response.content) > 1000, asset
