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

from ..helpers import (
    build_and_analyze,
    build_visualization,
    format_error,
    grouping_options,
    log_tool_call,
)
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_privilege_gradient(
    config: dict,
    format: str = "png",
    style: str = "pg_default",
    render_engine: str = "graphviz",
    shine: bool = False,
    group_by: str = "",
    collapse: str | list[str] | bool | None = None,
    max_nodes: int | None = None,
    keep: str = "",
    keep_ids: list[str] | None = None,
):
    """Generate a privilege gradient graph from a configuration dictionary.

    Visualizes trust zones, components, and influence relationships with
    automatic privilege inversion detection. The config should contain
    'gradient', 'zones', 'components', and 'influences' sections. Components
    can be grouped within their zone (groups never span zones), and groups
    collapsed into one summary component each; inversions on merged edges stay exact.

    Args:
        config: Privilege gradient configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. pg_default; sv_* with render_engine='svg').
        render_engine: graphviz (default) or svg (the stdlib SVG engine: zones as
               clusters ordered by trust level, influence styles by type,
               self-contained SVG; png/pdf via cairosvg; sv_* style presets).
        shine: Post-process Graphviz SVG output with the shine pack (fonts, shadows,
               hover). Requires format='svg' and render_engine='graphviz'.
        group_by: Group components within their zone by this component field
               (e.g. 'role'); a component's own 'group' wins. Group ids are
               '<zone>/<value>'. Overrides gradient.group_by.
        collapse: 'all' (or true), 'auto' (with max_nodes), 'none', or a list of
               group ids. Overrides gradient.collapse.
        max_nodes: Component target for collapse='auto' (default 300).
        keep: 'inversions' keeps every component taking part in an inversion
               drawn individually next to its collapsed group's card.
        keep_ids: Component ids kept drawn the same way.
    """
    try:
        return await build_visualization(
            PrivilegeGradient,
            config,
            "privilege_gradient",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            shine=shine,
            **grouping_options(group_by, collapse, max_nodes, keep, keep_ids),
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
async def get_privilege_gradient_stats(config: dict, group_by: str = "") -> str:
    """Get statistics about a privilege gradient — zone counts, component counts, etc.

    Args:
        config: Privilege gradient configuration to analyze.
        group_by: Component field to group by; adds per-group counts under
               'groups' (also used when the config sets gradient.group_by or
               components have a 'group').
    """
    try:
        return await build_and_analyze(
            PrivilegeGradient,
            config,
            "get_stats",
            viz_options=grouping_options(group_by),
        )
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
