"""saml 2.0 service provider: sp-initiated web browser sso (http-redirect
AuthnRequest, http-post Response) with jit provisioning

security model:
* the Response is parsed with a hardened xml parser (no dtd / external entities)
  and its signature verified with signxml against the configured idp certificate,
  never against a cert embedded in the message; defeats signature-wrapping and
  cert-substitution
* only the signed subtree is trusted: the assertion is read from there, not the
  raw document
* claims validated: Issuer == configured idp entity id, Audience == our sp
  entity id, InResponseTo matches a request we issued (single use), NotBefore /
  NotOnOrAfter with a small clock skew, StatusCode success, and a bearer
  SubjectConfirmation whose Recipient is our acs url
* user provisioned like oidc jit: tenant-bound, default non-admin role, no
  password
"""

from __future__ import annotations

import base64
import zlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib import parse

from lxml import etree
from signxml import XMLVerifier

from app.services.sso import _provision_user  # shared jit provisioning
from app.storage.saml import consume_saml_request, create_saml_request, load_saml_configuration

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
CLOCK_SKEW = timedelta(minutes=3)

_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, remove_comments=True, huge_tree=False)


class SamlError(Exception):
    pass


def sp_entity_id(base_url: str) -> str:
    return base_url.rstrip("/") + "/api/auth/saml/metadata"


def acs_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/api/auth/saml/acs"


# --- AuthnRequest -----------------------------------------------------------------


def build_authn_redirect(tenant_id: str, base_url: str) -> tuple[str, str]:
    config = load_saml_configuration(tenant_id)
    if config is None or not config.get("enabled"):
        raise SamlError("SAML SSO is not configured for this organization")
    request_id = create_saml_request(tenant_id)
    issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{config["idp_sso_url"]}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'AssertionConsumerServiceURL="{acs_url(base_url)}">'
        f"<saml:Issuer>{sp_entity_id(base_url)}</saml:Issuer>"
        f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>'
        f"</samlp:AuthnRequest>"
    )
    # http-redirect binding: raw deflate + base64 + url-encode
    deflated = zlib.compress(xml.encode("utf-8"))[2:-4]
    saml_request = base64.b64encode(deflated).decode("ascii")
    separator = "&" if "?" in config["idp_sso_url"] else "?"
    return f"{config['idp_sso_url']}{separator}{parse.urlencode({'SAMLRequest': saml_request, 'RelayState': tenant_id})}", request_id


# --- Response ---------------------------------------------------------------------


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _verify_signed(root: etree._Element, certificate_pem: str) -> etree._Element:
    """verify the xml signature against the configured cert and return the signed
    element; signxml rejects any cert the message supplies unless it matches ours"""
    try:
        verified = XMLVerifier().verify(root, x509_cert=certificate_pem, expect_references=1)
    except Exception as error:
        raise SamlError(f"SAML signature verification failed: {error}") from error
    return verified.signed_xml


def process_response(saml_response_b64: str, base_url: str, expected_request_id: str | None = None) -> dict[str, Any]:
    """verify a saml Response (http-post binding) and return the provisioned user

    ``expected_request_id`` is the AuthnRequest id this browser was issued at
    /start (from a cookie); when set, the response's InResponseTo must match it,
    binding the login to the browser that began it"""
    try:
        raw = base64.b64decode(saml_response_b64)
        root = etree.fromstring(raw, parser=_PARSER)
    except Exception as error:
        raise SamlError("SAMLResponse is not valid base64 XML") from error

    # locate our request id first so we know which tenant's cert to use
    in_response_to = root.get("InResponseTo")
    if not in_response_to:
        raise SamlError("SAML Response lacks InResponseTo; unsolicited responses are not accepted")
    if expected_request_id is not None and in_response_to != expected_request_id:
        raise SamlError("SAML Response does not match the login request from this browser")
    request = consume_saml_request(in_response_to)
    if request is None:
        raise SamlError("SAML Response does not match a pending login request (unknown, expired, or replayed)")
    tenant_id = request["tenant_id"]
    config = load_saml_configuration(tenant_id)
    if config is None or not config.get("enabled"):
        raise SamlError("SAML SSO is not configured for this organization")

    # status must be success before we verify anything
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != SUCCESS:
        raise SamlError("identity provider returned a non-success status")

    # the Response or the Assertion may be signed; verify whichever carries the
    # signature and only trust the verified subtree
    signed = _verify_signed(root, config["idp_certificate"])
    if etree.QName(signed).localname == "Response":
        assertion = signed.find("saml:Assertion", NS)
    elif etree.QName(signed).localname == "Assertion":
        assertion = signed
    else:
        raise SamlError("signed element is neither a Response nor an Assertion")
    if assertion is None:
        raise SamlError("no Assertion inside the signed Response")

    issuer = (assertion.findtext("saml:Issuer", namespaces=NS) or "").strip()
    if issuer != config["idp_entity_id"]:
        raise SamlError("assertion Issuer does not match the configured identity provider")

    now = datetime.now(UTC)
    # Conditions (validity window + audience) required, not fail-open on absence:
    # an assertion with no AudienceRestriction or no expiry must be rejected
    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise SamlError("assertion lacks Conditions")
    not_before = _parse_time(conditions.get("NotBefore"))
    not_after = _parse_time(conditions.get("NotOnOrAfter"))
    if not_after is None:
        raise SamlError("assertion Conditions lack NotOnOrAfter")
    if not_before and now + CLOCK_SKEW < not_before:
        raise SamlError("assertion is not yet valid")
    if now - CLOCK_SKEW >= not_after:
        raise SamlError("assertion has expired")
    audiences = [a.text.strip() for a in conditions.findall("saml:AudienceRestriction/saml:Audience", NS) if a.text]
    if not audiences:
        raise SamlError("assertion lacks an AudienceRestriction")
    if sp_entity_id(base_url) not in audiences:
        raise SamlError("assertion audience does not include this service provider")

    # the bearer SubjectConfirmationData binds the signed assertion to this
    # request and acs; every field is mandatory. an assertion signed alone (entra
    # default) could otherwise be wrapped in a Response with a forged
    # InResponseTo, and an absent Recipient/NotOnOrAfter would fail open to replay
    confirmation = assertion.find("saml:Subject/saml:SubjectConfirmation", NS)
    if confirmation is None or confirmation.get("Method") != BEARER:
        raise SamlError("assertion lacks a bearer SubjectConfirmation")
    data = confirmation.find("saml:SubjectConfirmationData", NS)
    if data is None:
        raise SamlError("assertion lacks SubjectConfirmationData")
    if data.get("InResponseTo") != in_response_to:
        raise SamlError("SubjectConfirmationData InResponseTo does not match the login request")
    if data.get("Recipient") != acs_url(base_url):
        raise SamlError("SubjectConfirmationData Recipient is not this ACS URL")
    scd_not_after = _parse_time(data.get("NotOnOrAfter"))
    if scd_not_after is None:
        raise SamlError("SubjectConfirmationData lacks NotOnOrAfter")
    if now - CLOCK_SKEW >= scd_not_after:
        raise SamlError("subject confirmation has expired")

    name_id = (assertion.findtext("saml:Subject/saml:NameID", namespaces=NS) or "").strip()
    attributes: dict[str, str] = {}
    for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        values = [v.text.strip() for v in attr.findall("saml:AttributeValue", NS) if v.text]
        if values:
            attributes[attr.get("Name", "")] = values[0]
    email = (
        attributes.get("email")
        or attributes.get("mail")
        or attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
        or (name_id if "@" in name_id else "")
    ).strip().lower()
    if not email:
        raise SamlError("identity provider did not supply an email (NameID or email attribute)")
    domain = config.get("allowed_email_domain")
    if domain and not email.endswith("@" + domain.lower()):
        raise SamlError("email domain is not permitted for this organization")

    claims = {
        "email": email,
        "name": attributes.get("displayName")
        or attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
        or attributes.get("name"),
    }
    return _provision_user(tenant_id, email, claims, {"default_role": config.get("default_role")})
