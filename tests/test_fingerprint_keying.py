"""content fingerprints must be keyed on a default install

an unkeyed digest of low-entropy content is a lookup table: an MRN was
brute-forced from its plain SHA-256 in four guesses during the F500 buyer
evaluation. the threat model promises a keyed HMAC fingerprint, so the default
config has to deliver one — the key is derived from the api key (a secret every
install already holds) unless an explicit signing_secret pins it.
"""

from __future__ import annotations

import hashlib
import hmac
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "packages" / "python-sdk"))

from norinth_logger.client import NorinthClient  # noqa: E402
from norinth_logger.config import NorinthConfig  # noqa: E402

MRN = "MRN-00847213"


def _capturing_client(**config: object) -> tuple[NorinthClient, list[dict]]:
    client = NorinthClient(NorinthConfig(async_transport=False, **config))
    captured: list[dict] = []
    client.transport.send_batch = captured.extend  # type: ignore[method-assign]
    return client, captured


def _prompt_digest(captured: list[dict]) -> str:
    events = [event for event in captured if event["type"] == "model.call"]
    return events[-1]["attributes"]["prompt"]["hash"]


def test_default_install_never_emits_the_unkeyed_digest():
    """the exact attack: hash a candidate list, compare against the stored digest"""
    client, captured = _capturing_client(api_key="nrk_live_key")
    client.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)

    stored = _prompt_digest(captured)
    unkeyed = "sha256:" + hashlib.sha256(MRN.encode("utf-8")).hexdigest()
    assert stored != unkeyed, "default install emitted a brute-forceable unkeyed digest"

    # a dictionary attack over the plausible MRN space finds nothing
    for candidate in (f"MRN-{n:08d}" for n in range(847200, 847230)):
        assert "sha256:" + hashlib.sha256(candidate.encode()).hexdigest() != stored


def test_fingerprints_do_not_link_across_api_keys():
    a, captured_a = _capturing_client(api_key="nrk_tenant_a")
    b, captured_b = _capturing_client(api_key="nrk_tenant_b")
    a.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)
    b.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)

    assert _prompt_digest(captured_a) != _prompt_digest(captured_b)


def test_same_key_stays_deterministic():
    """fingerprints exist to link identical content; the key must not be per-process"""
    a, captured_a = _capturing_client(api_key="nrk_same")
    b, captured_b = _capturing_client(api_key="nrk_same")
    a.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)
    b.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)

    assert _prompt_digest(captured_a) == _prompt_digest(captured_b)


def test_explicit_signing_secret_pins_the_key_across_api_keys():
    """an org that needs continuity across services/rotation pins signing_secret"""
    a, captured_a = _capturing_client(api_key="nrk_one", signing_secret="org-secret")
    b, captured_b = _capturing_client(api_key="nrk_two", signing_secret="org-secret")
    a.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)
    b.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)

    expected = "sha256:" + hmac.new(b"org-secret", MRN.encode("utf-8"), hashlib.sha256).hexdigest()
    assert _prompt_digest(captured_a) == expected
    assert _prompt_digest(captured_b) == expected


def test_derived_key_is_not_the_api_key_itself():
    """the api key authenticates the transport; it must not appear as the hmac key"""
    config = NorinthConfig(api_key="nrk_live_key")
    assert config.fingerprint_key != "nrk_live_key"
    direct = "sha256:" + hmac.new(b"nrk_live_key", MRN.encode("utf-8"), hashlib.sha256).hexdigest()
    client, captured = _capturing_client(api_key="nrk_live_key")
    client.model_call(provider="openai", model="gpt-4o", operation="chat", prompt=MRN)
    assert _prompt_digest(captured) != direct
