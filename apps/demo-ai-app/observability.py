"""Norinth observability bootstrap.

This is the single integration point between the Helpdesk service and Norinth.
No other module in this service references the SDK. The pattern mirrors how a
real team adds Norinth to an existing repository:

  1. Install the package (``pip install norinth-logger``).
  2. Set the application identity once, at startup.
  3. Let auto-instrumentation capture provider calls and request traces.

Connection settings (endpoint, project, environment, API key) are read from the
standard ``NORINTH_*`` environment variables. Remove the ``install()`` call in
``main.py`` and the service behaves identically, just without telemetry.
"""

from __future__ import annotations

import os

import norinth_logger as norinth


def install(
    app,
    *,
    application_name: str = "Helpdesk Assistant",
    use_case: str = "Customer support automation",
) -> None:
    norinth.init(
        application_name=application_name,
        use_case=use_case,
        service=os.getenv("NORINTH_SERVICE", "helpdesk-assistant"),
    )
    # Transparently records every OpenAI / Anthropic call made by the app.
    norinth.autoinstrument()
    # Records a request trace per endpoint and derives tenant/user context from
    # the request payload without the application passing anything explicitly.
    norinth.instrument_fastapi(app)
