"""
api/auth.py

Static per-deployment API key auth for api/app.py — closes the item
tracked in PHASES.md Phase 6 ("API authentication — design decided
(static per-deployment key), not implemented") and Phase 3.5.5's open
item. This is the documented hard blocker for Phase 4's native-app
track, so it goes in before any dashboard code is written.

Why a static key, not real auth (OAuth/JWT/user accounts):
------------------------------------------------------------
Sentinel is a single-operator, single-deployment tool — there's no
multi-user story to build session/identity management for. A shared
secret is the right amount of auth for "keep randoms on the LAN from
hitting my incidents API," which is the actual threat model here.
If Sentinel ever grows a real multi-user angle, this is the file that
gets replaced — every route already goes through one dependency
(`require_api_key`), so swapping the mechanism later only means
rewriting this one function, not touching every route in app.py.

Why the key lives in .env, never config.yaml:
------------------------------------------------------------
Dev rule, unconditional: "All credentials go in .env, never in code
or config files." The stale `dashboard.api_key` field in config.yaml
violated this (a secret sitting in a committed YAML file) — flagged
in that file's own comments before this pass, now actually removed
rather than just noted. The key is read here from the
SENTINEL_API_KEY environment variable ONLY.

Why /health is exempt:
------------------------------------------------------------
Load balancers, systemd health checks, and a dashboard's own "is the
API even up" probe all need to hit /health before they have any
reason to know the key — and liveness alone ("the process is up")
isn't sensitive. Every route that returns actual incident data or
performs an action requires the key.

Behaviour when auth is misconfigured vs. simply not provided:
------------------------------------------------------------
These are deliberately different failure modes:
  - SENTINEL_API_KEY unset entirely -> 500. This is a deployment
    mistake, not a client error - fail loudly instead of silently
    running the API wide open (the FastAPI equivalent of the old
    config.yaml bug where a missing section silently fell back to
    permissive defaults instead of erroring).
  - Key set, but request omits/mismatches it -> 401. Ordinary auth
    failure, the client's problem to fix.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

_API_KEY_ENV_VAR = "SENTINEL_API_KEY"

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided_key: str | None = Security(_api_key_header)) -> None:
    """
    FastAPI dependency - raise on missing/invalid key, otherwise
    return None (routes don't need the key value, just the gate).

    Uses hmac.compare_digest rather than `==` for the comparison -
    a plain string comparison short-circuits on the first mismatched
    character, which leaks (via response timing) how many leading
    characters of a guess were correct. Overkill for a LAN tool
    against a casual threat model, but it's a one-line fix with no
    downside, so there's no reason not to do it correctly.
    """
    configured_key = os.environ.get(_API_KEY_ENV_VAR)

    if not configured_key:
        # Deployment misconfiguration, not a client error - see
        # module docstring's "misconfigured vs not provided" section.
        raise HTTPException(
            status_code=500,
            detail=(
                f"Server misconfiguration: {_API_KEY_ENV_VAR} is not set. "
                "Set it in .env before starting the API."
            ),
        )

    if not provided_key or not hmac.compare_digest(provided_key, configured_key):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API key. Provide it via the X-API-Key header.",
        )


# Convenience export for app.py: `dependencies=[require_auth_dependency]`
# on the router/routes that need protecting.
require_auth_dependency = Depends(require_api_key)
