#
# VULNEX -Universal Security Visualization Library-
#
# File: server.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP server for USecVisLib security visualization library."""

import os

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import (
    configure_logging,
    ensure_directories,
    get_api_key,
    get_host,
    get_port,
    get_transport,
    warn_if_unrestricted_http,
)

# Configure logging to stderr before anything else
logger = configure_logging()


def _build_server() -> FastMCP:
    """Build the FastMCP instance with transport-aware configuration."""
    transport = get_transport()

    kwargs: dict = {
        "name": "usecvislib",
        "instructions": (
            "Security visualization server providing attack trees, attack graphs, "
            "threat models, mermaid diagrams, binary analysis, cloud diagrams, "
            "privilege gradient graphs, custom diagrams, component diagrams, "
            "dependency graphs, and utility tools via the USecVisLib library."
        ),
    }

    # HTTP transport settings
    if transport in ("sse", "streamable-http"):
        kwargs["host"] = get_host()
        kwargs["port"] = get_port()
        kwargs["stateless_http"] = True

        # API key auth — required for HTTP unless explicitly opted out
        api_key = get_api_key()
        if api_key:
            from mcp.server.auth.settings import AuthSettings

            from .auth import ApiKeyVerifier

            kwargs["token_verifier"] = ApiKeyVerifier(api_key)
            kwargs["auth"] = AuthSettings(
                issuer_url="https://localhost",
                resource_server_url=None,
                required_scopes=["usecvislib"],
            )
        else:
            allow_no_auth = os.environ.get("USECVISLIB_MCP_ALLOW_NO_AUTH", "").lower() in (
                "true",
                "1",
                "yes",
            )
            if not allow_no_auth:
                raise RuntimeError(
                    "HTTP transport requires authentication. "
                    "Set USECVISLIB_MCP_API_KEY to enable API key auth, "
                    "or set USECVISLIB_MCP_ALLOW_NO_AUTH=true to explicitly "
                    "run without authentication (NOT recommended for production)."
                )
            logger.warning(
                "HTTP transport (%s) starting WITHOUT authentication. "
                "Set USECVISLIB_MCP_API_KEY to enable API key auth.",
                transport,
            )

    server = FastMCP(**kwargs)

    # Health endpoint (does not require auth)
    @server.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    return server


# Create the FastMCP instance — tool modules import this
mcp = _build_server()

# Import prompt modules — they register via @mcp.prompt()
from .prompts import guidance  # noqa: F401

# Import resource modules — they register via @mcp.resource()
from .resources import (
    schemas,  # noqa: F401
    styles,  # noqa: F401
    templates,  # noqa: F401
)

# Import tool modules — they register via @mcp.tool()
from .tools import (
    analysis,  # noqa: F401
    architecture,  # noqa: F401
    attack_graphs,  # noqa: F401
    attack_trees,  # noqa: F401
    batch,  # noqa: F401
    binary_analysis,  # noqa: F401
    cloud_diagrams,  # noqa: F401
    custom_diagrams,  # noqa: F401
    export,  # noqa: F401
    mermaid,  # noqa: F401
    privilege_gradient,  # noqa: F401
    threat_models,  # noqa: F401
    utilities,  # noqa: F401
)


def main():
    """Entry point for the MCP server."""
    ensure_directories()
    warn_if_unrestricted_http()
    logger.info("Starting usecvislib MCP server (transport=%s)", get_transport())
    mcp.run(transport=get_transport())


if __name__ == "__main__":
    main()
