#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/utilities.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP utility tools — Mermaid export, CVSS scoring, config detection."""

import json

from usecvislib import (
    CustomDiagrams,
    calculate_cvss_from_vector_unified,
    detect_cvss_version,
    parse_cvss_vector_unified,
    serialize_to_mermaid,
)
from usecvislib.mermaid import detect_visualization_type

from ..helpers import check_rate_limit, format_error, log_tool_call, run_with_timeout
from ..server import mcp

# usecvislib.mermaid.detect_visualization_type() names -> MCP visualization types
_LIBRARY_TYPES = {
    "attack_tree": "attack_tree",
    "attack_graph": "attack_graph",
    "threat_model": "threat_model",
    "privilege_gradient": "privilege_gradient",
    "component_diagram": "component_diagram",
    "dependency_graph": "dependency_graph",
    "killchain": "kill_chain",
    "timeline": "incident_timeline",
    "vuln_tree": "vuln_tree",
    "maestro": "maestro",
    "access_graph": "access_graph",
    "mermaid_source": "mermaid",
}


def _detect(config: dict) -> tuple[str, str]:
    """(MCP visualization type, confidence) for a config dict."""
    library_type = detect_visualization_type(config)
    if library_type in _LIBRARY_TYPES:
        return _LIBRARY_TYPES[library_type], "high"
    nodes = config.get("nodes")
    if isinstance(nodes, list) and any(isinstance(n, dict) and "icon" in n for n in nodes):
        return "cloud_diagram", "high" if "diagram" in config else "medium"
    if library_type == "node_graph" or "schema" in config:
        return "custom_diagram", "high" if "schema" in config else "medium"
    if "nodes" in config or "edges" in config:
        return "custom_diagram", "low"
    return "unknown", "low"


@mcp.tool()
@log_tool_call
async def convert_to_mermaid(
    config: dict,
    viz_type: str = "",
) -> str:
    """Convert a visualization configuration to Mermaid diagram syntax.

    Supports attack trees, attack graphs, threat models, kill chains,
    incident timelines, vulnerability trees, privilege gradients,
    component diagrams, dependency graphs, MAESTRO models, and
    custom/cloud node-and-edge diagrams. The type is detected from the
    config structure (see detect_config_type).

    Args:
        config: Visualization configuration dict.
        viz_type: Optional expected type (e.g. 'attack_tree', 'kill_chain',
                  'maestro'). If given and the config is detected as a
                  different type, an error is returned instead of a
                  conversion of the wrong kind.

    Returns:
        JSON with 'mermaid_source' containing the Mermaid syntax and the
        detected 'viz_type'.
    """
    try:
        check_rate_limit("convert_to_mermaid")
        detected, _confidence = _detect(config)
        if viz_type and viz_type != detected:
            raise ValueError(f"Config looks like '{detected}', not '{viz_type}'")

        def _sync_convert():
            return serialize_to_mermaid(config)

        result = await run_with_timeout(_sync_convert)
        return json.dumps({"mermaid_source": result, "viz_type": detected}, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def calculate_cvss_score(vector: str) -> str:
    """Calculate a CVSS score from a vector string.

    Supports CVSS 3.0, 3.1, and 4.0 vector formats. Auto-detects
    the version from the vector prefix.

    Args:
        vector: CVSS vector string (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').

    Returns:
        JSON with score, version, severity, and parsed vector components.
    """
    try:
        check_rate_limit("calculate_cvss_score")

        def _sync_calculate():
            version = detect_cvss_version(vector)
            success_parse, parsed, parse_error = parse_cvss_vector_unified(vector)
            success_score, score, score_error = calculate_cvss_from_vector_unified(vector)

            if not success_score:
                return {"error": score_error or parse_error or "Failed to calculate score"}

            # Determine severity rating
            severity = "None"
            if score is not None:
                if score >= 9.0:
                    severity = "Critical"
                elif score >= 7.0:
                    severity = "High"
                elif score >= 4.0:
                    severity = "Medium"
                elif score > 0.0:
                    severity = "Low"

            result = {
                "vector": vector,
                "version": version,
                "score": score,
                "severity": severity,
            }
            if parsed:
                result["components"] = parsed if isinstance(parsed, dict) else str(parsed)
            return result

        result = await run_with_timeout(_sync_calculate)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def detect_config_type(config: dict) -> str:
    """Detect the visualization type from a configuration dictionary.

    Uses USecVisLib's own config detection. Possible types: attack_tree,
    attack_graph, threat_model, privilege_gradient, component_diagram,
    dependency_graph, kill_chain, incident_timeline, vuln_tree, maestro,
    cloud_diagram, custom_diagram, access_graph, mermaid, or unknown.

    Args:
        config: Configuration dictionary to analyze.

    Returns:
        JSON with 'type' string and 'confidence' level (high, medium, low).
    """
    try:
        check_rate_limit("detect_config_type")
        detected, confidence = _detect(config)
        return json.dumps({"type": detected, "confidence": confidence}, indent=2)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def list_shapes(category: str = "") -> str:
    """List available shapes for custom diagrams.

    Returns shape definitions from the CustomDiagrams shape gallery,
    optionally filtered by category.

    Args:
        category: Filter by shape category (empty for all categories).

    Returns:
        JSON list of shape information dictionaries.
    """
    try:
        check_rate_limit("list_shapes")

        def _sync_list():
            cd = CustomDiagrams()
            return cd.list_shapes(category=category or None)

        result = await run_with_timeout(_sync_list)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return format_error(e)
