"""rfc 6238 time-based one-time passwords, stdlib only

sha-1/6-digit/30-second is what every authenticator app provisions by
default; the hotp truncation is rfc 4226. no external dependency: the whole
algorithm is an hmac and a modulo, and a crypto dependency would be a bigger
liability than these thirty lines
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
# accept one neighbouring step each way so phone/server clock skew doesn't
# lock people out; the customary window
DRIFT_STEPS = 1


def generate_secret() -> str:
    """160-bit secret, base32 for authenticator-app entry"""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _hotp(key: bytes, counter: int) -> str:
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**DIGITS)
    return f"{code:0{DIGITS}d}"


def current_counter(now: float | None = None) -> int:
    return int((time.time() if now is None else now) / STEP_SECONDS)


def verify_code(
    secret_b32: str,
    code: str,
    *,
    last_counter: int | None,
    now: float | None = None,
) -> int | None:
    """the matched time-step counter when the code is valid, else None

    a code only matches a counter NEWER than last_counter, which makes every
    code single-use: replaying a shoulder-surfed code inside its 30-second
    window fails. the caller persists the returned counter
    """
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    try:
        key = base64.b32decode(secret_b32, casefold=True)
    except Exception:
        return None
    counter = current_counter(now)
    floor = last_counter if last_counter is not None else -1
    for candidate in range(counter - DRIFT_STEPS, counter + DRIFT_STEPS + 1):
        if candidate <= floor:
            continue
        if hmac.compare_digest(_hotp(key, candidate), code):
            return candidate
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Norinth") -> str:
    """otpauth:// uri an authenticator app can consume (pasted or via qr)"""
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    return (
        f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
