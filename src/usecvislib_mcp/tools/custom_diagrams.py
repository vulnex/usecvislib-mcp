#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/custom_diagrams.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for custom diagram generation."""

import json

from usecvislib import CustomDiagrams, USecVisLibError

from ..helpers import analyze_pattern_b, build_pattern_b, format_error
from ..server import mcp


@mcp.tool()
async def generate_custom_diagram(
    config: dict,
    format: str = "png",
    style: str = "cd_default",
):
    """Generate a custom diagram from a configuration dictionary.

    Creates flexible, schema-driven diagrams using Graphviz. The config
    should define nodes, edges, and optional settings for layout and styling.

    Args:
        config: Custom diagram configuration with nodes, edges, settings.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. cd_default).
    """
    try:
        return await build_pattern_b(
            CustomDiagrams,
            config,
            "custom_diagram",
            fmt=format,
            build_method="BuildCustomDiagram",
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def validate_custom_diagram(config: dict) -> str:
    """Validate a custom diagram configuration and return any errors.

    Checks schema definition, data conformance, node/edge references.

    Args:
        config: Custom diagram configuration to validate.

    Returns:
        JSON with validation report including errors and warnings.
    """
    try:
        return await analyze_pattern_b(CustomDiagrams, config, "validate",
                                       raise_on_error=False)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def get_custom_diagram_stats(config: dict) -> str:
    """Get statistics about a custom diagram — node counts, edge counts, etc.

    Args:
        config: Custom diagram configuration to analyze.
    """
    try:
        return await analyze_pattern_b(CustomDiagrams, config, "get_stats")
    except (USecVisLibError, Exception) as e:
        return format_error(e)
