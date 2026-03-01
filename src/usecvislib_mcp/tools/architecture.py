#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/architecture.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for architecture visualization — component diagrams and dependency graphs."""

import json

from usecvislib import ComponentDiagram, DependencyGraph, USecVisLibError

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp


# ── Component Diagram Tools ─────────────────────────────────────────


@mcp.tool()
@log_tool_call
async def generate_component_diagram(
    config: dict,
    format: str = "png",
    style: str = "comp_default",
):
    """Generate a component diagram from a configuration dictionary.

    Creates layered architecture diagrams showing components, layers,
    and their connections using Graphviz. The config should contain
    'diagram', 'layers', 'components', and 'connections' sections.

    Args:
        config: Component diagram configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. comp_default).
    """
    try:
        return await build_visualization(
            ComponentDiagram, config, "component_diagram", fmt=format, styleid=style
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_component_diagram(config: dict) -> str:
    """Validate a component diagram configuration and return any errors.

    Args:
        config: Component diagram configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(ComponentDiagram, config, "validate")
        errors = json.loads(result)
        return json.dumps(
            {"valid": len(errors) == 0, "errors": errors}, indent=2, default=str
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_component_diagram_stats(config: dict) -> str:
    """Get statistics about a component diagram — layer counts, component counts, etc.

    Args:
        config: Component diagram configuration to analyze.
    """
    try:
        return await build_and_analyze(ComponentDiagram, config, "get_stats")
    except (USecVisLibError, Exception) as e:
        return format_error(e)


# ── Dependency Graph Tools ───────────────────────────────────────────


@mcp.tool()
@log_tool_call
async def generate_dependency_graph(
    config: dict,
    format: str = "png",
    style: str = "dep_default",
):
    """Generate a dependency graph from a configuration dictionary.

    Creates module dependency visualizations with force-directed layout,
    SLOC-based node sizing, and circular dependency highlighting. The
    config should contain 'graph', 'modules', and 'dependencies' sections.

    Args:
        config: Dependency graph configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. dep_default).
    """
    try:
        return await build_visualization(
            DependencyGraph, config, "dependency_graph", fmt=format, styleid=style
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_dependency_graph(config: dict) -> str:
    """Validate a dependency graph configuration and return any errors.

    Args:
        config: Dependency graph configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(DependencyGraph, config, "validate")
        errors = json.loads(result)
        return json.dumps(
            {"valid": len(errors) == 0, "errors": errors}, indent=2, default=str
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_dependency_graph_stats(config: dict) -> str:
    """Get statistics about a dependency graph — module counts, dependency counts, etc.

    Args:
        config: Dependency graph configuration to analyze.
    """
    try:
        return await build_and_analyze(DependencyGraph, config, "get_stats")
    except (USecVisLibError, Exception) as e:
        return format_error(e)
