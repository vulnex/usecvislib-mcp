#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/cloud_diagrams.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for cloud architecture diagram generation."""

import asyncio
import json

from usecvislib import CloudDiagrams, USecVisLibError

from ..helpers import analyze_pattern_b, format_error
from ..output import OutputHandler
from ..server import mcp


@mcp.tool()
async def generate_cloud_diagram(
    config: dict,
    format: str = "png",
):
    """Generate a cloud architecture diagram from a configuration dictionary.

    The config should define nodes (with cloud provider icons), edges,
    and optional clusters for grouping. Requires the 'diagrams' Python
    package and Graphviz.

    Args:
        config: Cloud diagram configuration with nodes, edges, clusters.
        format: Output format — png, pdf, svg, or dot.
    """
    try:
        handler = OutputHandler()
        output_path = handler.make_output_path("cloud_diagram", format)

        def _sync_render():
            from pathlib import Path

            output_base = str(Path(output_path).with_suffix(""))
            cd = CloudDiagrams()
            cd.load_from_string(json.dumps(config), "json")
            cd.render(output=output_base, format=format)
            return output_path

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _sync_render)
        return handler.format_result(output_path, format)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def validate_cloud_diagram(config: dict) -> str:
    """Validate a cloud diagram configuration and return any errors.

    Checks icon paths, edge references, and direction validity.

    Args:
        config: Cloud diagram configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await analyze_pattern_b(CloudDiagrams, config, "validate")
        errors = json.loads(result)
        return json.dumps(
            {"valid": len(errors) == 0, "errors": errors}, indent=2, default=str
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def get_cloud_diagram_stats(config: dict) -> str:
    """Get statistics about a cloud diagram — node counts, providers used, etc.

    Args:
        config: Cloud diagram configuration to analyze.
    """
    try:
        return await analyze_pattern_b(CloudDiagrams, config, "get_stats")
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def search_cloud_icons(
    query: str,
    limit: int = 20,
) -> str:
    """Search for cloud provider icons by name.

    Searches across all supported cloud providers (AWS, GCP, Azure, etc.)
    to find matching icon names for use in cloud diagrams.

    Args:
        query: Search query (case-insensitive).
        limit: Maximum number of results to return.
    """
    try:

        def _sync_search():
            return CloudDiagrams.search_icons(query, limit)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_search)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def list_cloud_providers() -> str:
    """List available cloud providers for diagram generation.

    Returns provider IDs and display names for use with
    generate_cloud_diagram and list_cloud_icons.

    Returns:
        JSON list of provider dictionaries with 'id' and 'name'.
    """
    try:

        def _sync_list():
            return CloudDiagrams.list_providers()

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_list)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def list_cloud_icons(
    provider: str,
    category: str = "",
) -> str:
    """List available icons for a specific cloud provider.

    Returns icon definitions that can be used in cloud diagram node
    configurations. Optionally filter by icon category.

    Args:
        provider: Cloud provider ID (e.g. 'aws', 'gcp', 'azure').
        category: Filter by icon category (empty for all categories).

    Returns:
        JSON list of icon dictionaries with id, path, name, category.
    """
    try:

        def _sync_list():
            return CloudDiagrams.list_icons(provider, category or None)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_list)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)
