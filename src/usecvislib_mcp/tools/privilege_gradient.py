#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/privilege_gradient.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for privilege gradient visualization and analysis."""

import json

from usecvislib import PrivilegeGradient

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_privilege_gradient(
    config: dict,
    format: str = "png",
    style: str = "pg_default",
    shine: bool = False,
):
    """Generate a privilege gradient graph from a configuration dictionary.

    Visualizes trust zones, components, and influence relationships with
    automatic privilege inversion detection. The config should contain
    'gradient', 'zones', 'components', and 'influences' sections.

    Args:
        config: Privilege gradient configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. pg_default).
        shine: Post-process Graphviz SVG output with the shine pack (fonts, shadows,
               hover). Requires format='svg' and render_engine='graphviz'.
    """
    try:
        return await build_visualization(
            PrivilegeGradient, config, "privilege_gradient", fmt=format, styleid=style, shine=shine
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_privilege_gradient(config: dict) -> str:
    """Validate a privilege gradient configuration and return any errors.

    Args:
        config: Privilege gradient configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(PrivilegeGradient, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_privilege_gradient_stats(config: dict) -> str:
    """Get statistics about a privilege gradient — zone counts, component counts, etc.

    Args:
        config: Privilege gradient configuration to analyze.
    """
    try:
        return await build_and_analyze(PrivilegeGradient, config, "get_stats")
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def detect_privilege_inversions(config: dict) -> str:
    """Detect privilege inversions in a privilege gradient configuration.

    Identifies cases where lower-privilege zones have influence over
    higher-privilege zones, which may indicate security issues.

    Args:
        config: Privilege gradient configuration to analyze.
    """
    try:
        return await build_and_analyze(PrivilegeGradient, config, "detect_inversions")
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_zone_influence(config: dict) -> str:
    """Analyze the influence matrix between trust zones.

    Returns a matrix showing influence counts between each pair of zones,
    useful for understanding trust relationships and potential attack paths.

    Args:
        config: Privilege gradient configuration to analyze.
    """
    try:
        return await build_and_analyze(PrivilegeGradient, config, "get_zone_influence_matrix")
    except Exception as e:
        return format_error(e)
