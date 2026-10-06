#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/maestro.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for MAESTRO agentic-AI threat models."""

import json

from usecvislib import MaestroThreatModel

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp

MAESTRO_VIEWS = ("layered", "graph", "heatmap")

# export target -> MaestroThreatModel method
MAESTRO_EXPORTS = {
    "stride": "to_stride",
    "attack_graph": "to_attack_graph",
    "privilege_gradient": "to_privilege_gradient",
}


@mcp.tool()
@log_tool_call
async def generate_maestro_threat_model(
    config: dict,
    format: str = "png",
    style: str = "ma_default",
    view: str = "layered",
    render_engine: str = "graphviz",
    shine: bool = False,
):
    """Generate a MAESTRO threat model for an agentic AI system.

    MAESTRO (CSA) maps agents and assets onto 7 layers (foundation models,
    data operations, agent frameworks, deployment, observability, security,
    agent ecosystem); the built-in catalog auto-populates layer and
    cross-layer threats with ATT&CK, OWASP and NIST AI RMF tags. The config
    should contain 'meta' (name, owner), 'architecture' (patterns),
    'agents' (id, name, type, autonomy, layers, tools), 'assets' (id, name,
    layer, sensitivity), optional 'threats' overrides (id, target, severity,
    status, mitigations), 'mitigations' and 'catalog' (mode = auto).

    Args:
        config: MAESTRO threat model configuration dict.
        format: Output format — png, pdf, svg, or dot (dot: Graphviz views only).
        style: Style preset ID (ma_default, ma_dark, ma_blueprint, ma_severity,
               ma_compact; sv_* presets with the SVG engine).
        view: layered (default, the 7-layer stack), graph (agent-centric
              graph with cross-layer attack chains), or heatmap (layer x
              severity matrix, Matplotlib).
        render_engine: graphviz (default) or svg. The SVG engine supports
               the graph view only.
        shine: Post-process Graphviz SVG output with the shine pack (fonts, shadows,
               hover). Requires format='svg' and render_engine='graphviz'.
    """
    try:
        if view not in MAESTRO_VIEWS:
            raise ValueError(f"Invalid view '{view}'. Allowed: {', '.join(MAESTRO_VIEWS)}")
        if render_engine == "svg" and view != "graph":
            raise ValueError("render_engine='svg' supports view='graph' only")
        if view == "heatmap" and (format == "dot" or shine):
            raise ValueError(
                "The heatmap view is a Matplotlib chart: use png, pdf or svg without shine"
            )
        return await build_visualization(
            MaestroThreatModel,
            config,
            "maestro",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            shine=shine,
            view=view,
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_maestro_threat_model(config: dict) -> str:
    """Validate a MAESTRO threat model configuration and return any errors.

    Args:
        config: MAESTRO configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(MaestroThreatModel, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_maestro_stats(config: dict) -> str:
    """Get MAESTRO statistics — agents, assets, threats (total, unmitigated,
    by severity and layer), cross-layer threats, mitigations and detected
    architecture patterns.

    Args:
        config: MAESTRO configuration to analyze.
    """
    try:
        return await build_and_analyze(MaestroThreatModel, config, "get_stats")
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def export_maestro(config: dict, target: str = "stride") -> str:
    """Convert a MAESTRO threat model into another USecVisLib configuration.

    The result is a config dict you can pass straight to the matching
    generate tool.

    Args:
        config: MAESTRO configuration to convert.
        target: stride (threat model DFD for generate_threat_model),
                attack_graph (for generate_attack_graph), or
                privilege_gradient (for generate_privilege_gradient).
    """
    try:
        method = MAESTRO_EXPORTS.get(target)
        if method is None:
            raise ValueError(f"Invalid target '{target}'. Allowed: {', '.join(MAESTRO_EXPORTS)}")
        return await build_and_analyze(MaestroThreatModel, config, method)
    except Exception as e:
        return format_error(e)
