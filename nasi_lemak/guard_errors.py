"""Fail-closed guard exceptions shared by every guard transport.

These classes live in their own module so that the failure vocabulary can be
imported by modules that must not import a transport (the shared Qwen3Guard
contract, the bounded inference pool) without creating an import cycle with
:mod:`nasi_lemak.guards`.  :mod:`nasi_lemak.guards` re-exports both names, so
``from nasi_lemak.guards import GuardError`` keeps working unchanged.

Neither message carries request text, a path, a token or a raw exception.
"""

from __future__ import annotations


class GuardError(RuntimeError):
    """Fail-closed guard failure carrying no request text, path or token data."""


class GuardInputLimit(GuardError):
    """Known oversize input rejected before any provider request.

    The gateway maps this to the stable ``INPUT_LIMIT`` error instead of a
    generic unavailable-guard ``503``; callers must not include raw input,
    provider data or paths in its message.
    """
