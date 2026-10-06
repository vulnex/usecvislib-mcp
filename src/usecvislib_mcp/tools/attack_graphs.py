#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/attack_graphs.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for attack graph visualization and analysis."""

import json

from usecvislib import AttackGraphs

from ..helpers import (
    build_and_analyze,
    build_visualization,
    format_error,
    log_tool_call,
    validate_int_range,
)
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_attack_graph(
    config: dict,
    format: str = "png",
    style: str = "ag_default",
    render_engine: str = "graphviz",
    shine: bool = False,
):
    """Generate an attack graph visualization from a configuration dictionary.

    The config should contain 'graph', 'hosts', 'vulnerabilities', 'privileges',
    'services', 'exploits', and 'network_edges' sections.

    Args:
        config: Attack graph configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. ag_default).
        render_engine: graphviz (default) or svg (the stdlib SVG engine: interactive,
               self-contained SVG; png/pdf via cairosvg; sv_* style presets).
        shine: Post-process Graphviz SVG output with the shine pack (fonts, shadows,
               hover). Requires format='svg' and render_engine='graphviz'.
    """
    try:
        return await build_visualization(
            AttackGraphs,
            config,
            "attack_graph",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            shine=shine,
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_attack_graph(config: dict) -> str:
    """Validate an attack graph configuration and return any errors.

    Args:
        config: Attack graph configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(AttackGraphs, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_attack_graph_stats(config: dict) -> str:
    """Get statistics about an attack graph — node counts, edge counts, etc.

    Args:
        config: Attack graph configuration to analyze.
    """
    try:
        return await build_and_analyze(AttackGraphs, config, "get_stats")
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def find_attack_paths(
    config: dict,
    source: str,
    target: str,
    max_paths: int = 10,
    max_depth: int = 20,
) -> str:
    """Find attack paths between two nodes in an attack graph.

    Discovers all possible paths an attacker could take from a source node
    to a target node, up to the specified limits.

    Args:
        config: Attack graph configuration.
        source: Source node ID (attacker entry point).
        target: Target node ID (goal).
        max_paths: Maximum number of paths to return.
        max_depth: Maximum path depth to search.
    """
    try:
        validate_int_range(max_paths, "max_paths", 1, 100)
        validate_int_range(max_depth, "max_depth", 1, 100)
        return await build_and_analyze(
            AttackGraphs,
            config,
            "find_attack_paths",
            source=source,
            target=target,
            max_paths=max_paths,
            max_depth=max_depth,
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_critical_nodes(
    config: dict,
    top_n: int = 10,
) -> str:
    """Identify the most critical nodes in an attack graph.

    Uses centrality analysis to find nodes that are most important
    for attack propagation. Useful for prioritizing defenses.

    Args:
        config: Attack graph configuration.
        top_n: Number of top critical nodes to return.
    """
    try:
        validate_int_range(top_n, "top_n", 1, 1000)
        return await build_and_analyze(
            AttackGraphs,
            config,
            "analyze_critical_nodes",
            top_n=top_n,
        )
    except Exception as e:
        return format_error(e)
