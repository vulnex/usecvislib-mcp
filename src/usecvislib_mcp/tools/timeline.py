#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/timeline.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for incident timeline visualization and response metrics."""

import json

from usecvislib import IncidentTimeline
from usecvislib.timeline import SUPPORTED_MODES

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_incident_timeline(
    config: dict,
    format: str = "png",
    style: str = "tl_default",
    mode: str = "swimlane",
    render_engine: str = "graphviz",
):
    """Generate an incident timeline from a configuration dictionary.

    Plots the chronology of a security incident with severity markers, lanes,
    durations, ATT&CK technique tags and response-phase bands. The config
    should contain an 'incident' section (name, id, analyst), 'events' (id,
    timestamp ISO-8601, title, severity critical|high|medium|low|info, lane,
    optional duration, technique, source) and optional 'phases' (name,
    start, end, color).

    Args:
        config: Incident timeline configuration dict.
        format: Output format — png, pdf, or svg (charts have no dot output).
        style: Style preset ID (tl_default, tl_light, tl_dark, tl_print,
               tl_minimal, tl_corporate; sv_default, sv_dark, sv_print,
               sv_corporate, sv_minimal with the SVG engine).
        mode: Layout — swimlane (default), gantt, vertical, or compact.
        render_engine: graphviz (default; the timeline is drawn with Matplotlib)
               or svg (the stdlib SVG engine: interactive, self-contained SVG).
    """
    try:
        if mode not in SUPPORTED_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Allowed: {', '.join(SUPPORTED_MODES)}")
        if format == "dot":
            raise ValueError("Format 'dot' is not available for timelines. Use png, pdf or svg.")
        return await build_visualization(
            IncidentTimeline,
            config,
            "incident_timeline",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            mode=mode,
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_incident_timeline(config: dict) -> str:
    """Validate an incident timeline configuration and return any errors.

    Args:
        config: Incident timeline configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(IncidentTimeline, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_incident_timeline_stats(config: dict) -> str:
    """Get incident timeline statistics — event and phase counts, lanes, time
    span, severity distribution, response metrics (time to detect, contain
    and recover from the phase bands) and ATT&CK-tagged events.

    Args:
        config: Incident timeline configuration to analyze.
    """
    try:
        return await build_and_analyze(IncidentTimeline, config, "get_stats")
    except Exception as e:
        return format_error(e)
