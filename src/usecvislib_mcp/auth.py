#
# VULNEX -Universal Security Visualization Library-
#
# File: auth.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""API key authentication for HTTP transports."""

import hashlib
import secrets

from mcp.server.auth.provider import AccessToken, TokenVerifier


class ApiKeyVerifier(TokenVerifier):
    """Verify bearer tokens against a pre-shared API key using constant-time comparison."""

    def __init__(self, api_key: str) -> None:
        if not api_key:
            raise ValueError("API key must not be empty")
        self._key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    async def verify_token(self, token: str) -> AccessToken | None:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if secrets.compare_digest(self._key_hash, token_hash):
            return AccessToken(
                token=token,
                client_id="api-key-user",
                scopes=["usecvislib"],
            )
        return None
