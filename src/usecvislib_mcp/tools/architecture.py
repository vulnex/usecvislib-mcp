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

from usecvislib import ComponentDiagram, DependencyGraph

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp

# ── Component Diagram Tools ─────────────────────────────────────────


@mcp.tool()
@log_tool_call
async def generate_component_diagram(
    config: dict,
    format: str = "png",
    style: str = "cd_default",
    render_engine: str = "graphviz",
    shine: bool = False,
):
    """Generate a component diagram from a configuration dictionary.

    Creates layered architecture diagrams showing components, layers,
    and their connections using Graphviz. The config should contain
    'diagram', 'layers', 'components', and 'connections' sections.

    Args:
        config: Component diagram configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (cd_default, cd_dark, cd_blueprint, cd_minimal;
               sv_* presets with the SVG engine).
        render_engine: graphviz (default) or svg (the stdlib SVG engine: interactive,
               self-contained SVG; png/pdf via cairosvg; sv_* style presets).
        shine: Post-process Graphviz SVG output with the shine pack (fonts, shadows,
               hover). Requires format='svg' and render_engine='graphviz'.
    """
    try:
        return await build_visualization(
            ComponentDiagram,
            config,
            "component_diagram",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            shine=shine,
        )
    except Exception as e:
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
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
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
    except Exception as e:
        return format_error(e)


# ── Dependency Graph Tools ───────────────────────────────────────────


@mcp.tool()
@log_tool_call
async def generate_dependency_graph(
    config: dict,
    format: str = "png",
    style: str = "dg_default",
    render_engine: str = "graphviz",
    shine: bool = False,
):
    """Generate a dependency graph from a configuration dictionary.

    Creates module dependency visualizations with force-directed layout,
    SLOC-based node sizing, and circular dependency highlighting. The
    config should contain 'graph', 'modules', and 'dependencies' sections.

    Args:
        config: Dependency graph configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (dg_default, dg_dark, dg_minimal, dg_coupling;
               sv_* presets with the SVG engine).
        render_engine: graphviz (default) or svg (the stdlib SVG engine: interactive,
               self-contained SVG; png/pdf via cairosvg; sv_* style presets).
        shine: Post-process Graphviz SVG output with the shine pack (fonts, shadows,
               hover). Requires format='svg' and render_engine='graphviz'.
    """
    try:
        return await build_visualization(
            DependencyGraph,
            config,
            "dependency_graph",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            shine=shine,
        )
    except Exception as e:
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
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
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
    except Exception as e:
        return format_error(e)
