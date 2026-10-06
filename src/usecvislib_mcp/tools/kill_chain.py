#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/kill_chain.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for kill chain / MITRE ATT&CK visualization and coverage analysis."""

import json

from usecvislib import KillChain

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_kill_chain(
    config: dict,
    format: str = "png",
    style: str = "kc_default",
    render_engine: str = "graphviz",
):
    """Generate a kill chain / MITRE ATT&CK visualization from a configuration dictionary.

    Lays techniques out in phase columns (Lockheed Martin Cyber Kill Chain,
    MITRE ATT&CK tactics, or a custom phase axis), colors them by detection
    and mitigation coverage, and draws incident paths across phases. The config
    should contain a 'killchain' section (name, framework = kill_chain | attack
    | custom, phases for custom), 'techniques' keyed by ID (name, phase,
    severity, detected, mitigated) and optional 'incidents' (id, name,
    techniques in order).

    Args:
        config: Kill chain configuration dict.
        format: Output format — png, pdf, svg, or dot (dot is Graphviz only).
        style: Style preset ID (kc_default, kc_light, kc_coverage; sv_default,
               sv_dark, sv_neon, sv_corporate, sv_minimal with the SVG engine).
        render_engine: graphviz (default) or svg (the stdlib SVG engine: interactive,
               self-contained SVG; png/pdf via cairosvg; sv_* style presets).
    """
    try:
        return await build_visualization(
            KillChain, config, "kill_chain", fmt=format, styleid=style, render_engine=render_engine
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_kill_chain(config: dict) -> str:
    """Validate a kill chain configuration and return any errors.

    Args:
        config: Kill chain configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(KillChain, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_kill_chain_stats(config: dict) -> str:
    """Get kill chain statistics — technique counts, detection and mitigation
    coverage, active phases, incidents.

    Args:
        config: Kill chain configuration to analyze.
    """
    try:
        return await build_and_analyze(KillChain, config, "get_stats")
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_kill_chain_coverage(config: dict) -> str:
    """List detection and mitigation gaps: undetected techniques, unmitigated
    techniques, and critical gaps (high/critical severity with neither).

    Args:
        config: Kill chain configuration to analyze.
    """
    try:
        return await build_and_analyze(KillChain, config, "analyze_coverage_gaps")
    except Exception as e:
        return format_error(e)
