"""MCP utility tools — Mermaid export, CVSS scoring, config detection."""

import asyncio
import json

from usecvislib import (
    AttackGraphs,
    AttackTrees,
    CustomDiagrams,
    ThreatModeling,
    USecVisLibError,
    calculate_cvss_from_vector_unified,
    detect_cvss_version,
    parse_cvss_vector_unified,
    serialize_to_mermaid,
)

from ..helpers import format_error, temp_config_file
from ..server import mcp


@mcp.tool()
async def convert_to_mermaid(
    config: dict,
    viz_type: str = "",
) -> str:
    """Convert a visualization configuration to Mermaid diagram syntax.

    Supports attack trees, attack graphs, and threat models. Auto-detects
    the visualization type from the config structure if not specified.

    Args:
        config: Visualization configuration dict.
        viz_type: Visualization type hint — 'attack_tree', 'attack_graph',
                  or 'threat_model'. Auto-detected if empty.

    Returns:
        JSON with 'mermaid_source' containing the Mermaid syntax.
    """
    try:

        def _sync_convert():
            return serialize_to_mermaid(config, diagram_type=viz_type or None)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_convert)
        return json.dumps({"mermaid_source": result}, indent=2)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
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

        def _sync_calculate():
            version = detect_cvss_version(vector)
            success_parse, parsed, parse_error = parse_cvss_vector_unified(vector)
            success_score, score, score_error = calculate_cvss_from_vector_unified(
                vector
            )

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
                result["components"] = (
                    parsed if isinstance(parsed, dict) else str(parsed)
                )
            return result

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_calculate)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def detect_config_type(config: dict) -> str:
    """Detect the visualization type from a configuration dictionary.

    Uses heuristics to identify whether a config is for an attack tree,
    attack graph, threat model, privilege gradient, cloud diagram,
    custom diagram, component diagram, or dependency graph.

    Args:
        config: Configuration dictionary to analyze.

    Returns:
        JSON with 'type' string and 'confidence' level.
    """
    try:
        detected = "unknown"
        confidence = "low"

        # Attack Trees: have 'tree' with 'root'
        if "tree" in config and "root" in config.get("tree", {}):
            detected = "attack_tree"
            confidence = "high"
        # Attack Graphs: have 'graph' and 'hosts'/'vulnerabilities'
        elif "graph" in config and (
            "hosts" in config or "vulnerabilities" in config
        ):
            detected = "attack_graph"
            confidence = "high"
        # Threat Models: have 'model' and 'processes'/'dataflows'
        elif "model" in config and (
            "processes" in config or "dataflows" in config
        ):
            detected = "threat_model"
            confidence = "high"
        # Privilege Gradient: have 'gradient' and 'zones'
        elif "gradient" in config and "zones" in config:
            detected = "privilege_gradient"
            confidence = "high"
        # Component Diagram: have 'diagram' and 'layers'/'components'
        elif "diagram" in config and (
            "layers" in config or "components" in config
        ):
            detected = "component_diagram"
            confidence = "high"
        # Dependency Graph: have 'graph' and 'modules'/'dependencies'
        elif "graph" in config and (
            "modules" in config or "dependencies" in config
        ):
            detected = "dependency_graph"
            confidence = "high"
        # Cloud Diagram: have 'config'/'nodes' with 'icon' fields
        elif "nodes" in config:
            nodes = config["nodes"]
            if isinstance(nodes, list) and any(
                "icon" in n for n in nodes if isinstance(n, dict)
            ):
                detected = "cloud_diagram"
                confidence = "medium"
            else:
                detected = "custom_diagram"
                confidence = "medium"
        # Custom Diagram: have 'settings' or 'edges' without other markers
        elif "settings" in config or "edges" in config:
            detected = "custom_diagram"
            confidence = "low"

        return json.dumps(
            {"type": detected, "confidence": confidence}, indent=2
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
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

        def _sync_list():
            cd = CustomDiagrams()
            return cd.list_shapes(category=category or None)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_list)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)
