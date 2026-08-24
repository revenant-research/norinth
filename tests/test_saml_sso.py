"""saml 2.0 sso against a fake idp issuing signed assertions"""

from __future__ import annotations

import base64
import datetime as dt
import pathlib
import sys
import zlib
from urllib import parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

IDP_ENTITY = "https://idp.example.test/saml"
IDP_SSO = "https://idp.example.test/sso"
BASE = "http://testserver"  # TestClient base URL -> SP entity id / ACS derive from it
SP_ENTITY = f"{BASE}/api/auth/saml/metadata"
ACS = f"{BASE}/api/auth/saml/acs"


class FakeSamlIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.test")])
        now = dt.datetime.now(dt.UTC)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .sign(self.key, hashes.SHA256())
        )

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    def response(
        self,
        in_response_to: str,
        *,
        email="jane@acme.test",
        issuer=IDP_ENTITY,
        audience=SP_ENTITY,
        recipient=ACS,
        expired=False,
        sign=True,
        signer_key=None,
    ) -> str:
        now = dt.datetime.now(dt.UTC)
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        nb = (now - dt.timedelta(minutes=1)).strftime(fmt)
        na = (now + (dt.timedelta(minutes=-30) if expired else dt.timedelta(minutes=5))).strftime(fmt)
        xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_resp1" Version="2.0" IssueInstant="{now.strftime(fmt)}" Destination="{recipient}" InResponseTo="{in_response_to}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="{now.strftime(fmt)}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{in_response_to}" Recipient="{recipient}" NotOnOrAfter="{na}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">
      <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="displayName"><saml:AttributeValue>Jane Doe</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
        root = etree.fromstring(xml.encode())
        if sign:
            key = signer_key or self.key_pem
            assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
            signed_assertion = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256").sign(
                assertion, key=key, cert=self.cert_pem
            )
            root.replace(assertion, signed_assertion)
        return base64.b64encode(etree.tostring(root)).decode()


@pytest.fixture
def idp():
    return FakeSamlIdP()


def _org(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "acme", "admin_email": "oa@acme.test", "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    return org


def _configure(org, idp, **overrides):
    payload = {"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_certificate": idp.cert_pem, **overrides}
    resp = org.put("/api/org/saml", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _start(browser) -> str:
    """kick off login and return the authnrequest id the idp must echo back"""
    start = browser.get("/api/auth/saml/acme/start", follow_redirects=False)
    assert start.status_code == 302
    query = dict(parse.parse_qsl(parse.urlsplit(start.headers["location"]).query))
    inflated = zlib.decompress(base64.b64decode(query["SAMLRequest"]), -15)
    authn = etree.fromstring(inflated)
    assert authn.get("AssertionConsumerServiceURL") == ACS
    return authn.get("ID")


_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


def _strip(payload: str, xpath: str) -> str:
    root = etree.fromstring(base64.b64decode(payload))
    for node in root.findall(xpath, {"saml": _SAML_NS}):
        node.getparent().remove(node)
    return base64.b64encode(etree.tostring(root)).decode()


def test_response_level_inresponseto_rewrite_is_rejected(super_admin_client, idp):
    """wrapping attack: assertion signed alone, wrapped in a response whose root inresponseto is
    swapped to another pending request; signed subjectconfirmationdata still names the original"""
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org(super_admin_client)
    _configure(org, idp)
    with TestClient(app) as browser:
        victim_req = _start(browser)
        attacker_req = _start(browser)  # a second, distinct pending request
        payload = idp.response(victim_req)  # assertion bound to victim_req
        root = etree.fromstring(base64.b64decode(payload))
        root.set("InResponseTo", attacker_req)  # rewrite only the unsigned root
        mangled = base64.b64encode(etree.tostring(root)).decode()
        resp = browser.post("/api/auth/saml/acs", data={"SAMLResponse": mangled}, follow_redirects=False)
        assert resp.status_code == 401, resp.text
    org.close()


@pytest.mark.parametrize(
    "xpath",
    [
        "saml:Assertion/saml:Subject/saml:SubjectConfirmation",
        "saml:Assertion/saml:Conditions/saml:AudienceRestriction",
    ],
)
def test_missing_mandatory_bindings_are_rejected(super_admin_client, idp, xpath):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org(super_admin_client)
    _configure(org, idp)
    with TestClient(app) as browser:
        req = _start(browser)
        # strip a mandatory element from an otherwise-valid signed response; the
        # assertion signature covers its subtree, so removing subjectconfirmation
        # or audiencerestriction also breaks the signature; either way fail closed
        payload = _strip(idp.response(req), xpath)
        resp = browser.post("/api/auth/saml/acs", data={"SAMLResponse": payload}, follow_redirects=False)
        assert resp.status_code == 401, resp.text
    org.close()


def test_full_saml_login_with_jit(super_admin_client, idp):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org(super_admin_client)
    cfg = _configure(org, idp)
    assert cfg["saml"]["idp_entity_id"] == IDP_ENTITY

    with TestClient(app) as browser:
        request_id = _start(browser)
        acs = browser.post("/api/auth/saml/acs", data={"SAMLResponse": idp.response(request_id), "RelayState": "acme"}, follow_redirects=False)
        assert acs.status_code == 303, acs.text
        me = browser.get("/api/auth/me").json()["user"]
        assert me["email"] == "jane@acme.test"
        assert me["tenant_id"] == "acme"
        assert me["display_name"] == "Jane Doe"
        # least-privilege jit default (viewer): no decision or admin rights until
        # an org admin deliberately elevates the user
        assert "review.decide" not in me["permissions"]
        assert "role.assign" not in me["permissions"]
    org.close()


def test_sp_metadata_is_served(client):
    resp = client.get("/api/auth/saml/metadata")
    assert resp.status_code == 200
    assert "application/samlmetadata+xml" in resp.headers["content-type"]
    assert ACS in resp.text and SP_ENTITY in resp.text


@pytest.mark.parametrize(
    "case",
    ["tampered", "wrong_cert", "unsigned", "expired", "wrong_audience", "wrong_issuer", "replay", "unsolicited"],
)
def test_invalid_responses_are_rejected(super_admin_client, idp, case):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org(super_admin_client)
    _configure(org, idp)
    with TestClient(app) as browser:
        request_id = _start(browser)
        if case == "tampered":
            signed = base64.b64decode(idp.response(request_id))
            tampered = signed.replace(b"jane@acme.test", b"mallory@acme.test")  # alter signed content
            payload = base64.b64encode(tampered).decode()
        elif case == "wrong_cert":
            other = FakeSamlIdP()  # signed by a key the org never configured
            payload = other.response(request_id)
        elif case == "unsigned":
            payload = idp.response(request_id, sign=False)
        elif case == "expired":
            payload = idp.response(request_id, expired=True)
        elif case == "wrong_audience":
            payload = idp.response(request_id, audience="https://someone-else.example")
        elif case == "wrong_issuer":
            payload = idp.response(request_id, issuer="https://evil.example/saml")
        elif case == "replay":
            payload = idp.response(request_id)
            assert browser.post("/api/auth/saml/acs", data={"SAMLResponse": payload}, follow_redirects=False).status_code == 303
            # second submission of the same valid response must fail: inresponseto consumed
        else:  # unsolicited
            payload = idp.response("_never-issued")

        resp = browser.post("/api/auth/saml/acs", data={"SAMLResponse": payload}, follow_redirects=False)
        assert resp.status_code == 401, f"{case}: {resp.text}"
    org.close()


def test_saml_config_requires_pem_and_org_admin(super_admin_client, idp):
    org = _org(super_admin_client)
    bad = org.put("/api/org/saml", json={"idp_entity_id": "x", "idp_sso_url": "https://x", "idp_certificate": "not-a-cert"})
    assert bad.status_code == 400
    assert super_admin_client.put("/api/org/saml", json={"idp_entity_id": "x", "idp_sso_url": "https://x", "idp_certificate": idp.cert_pem}).status_code == 403
    org.close()
