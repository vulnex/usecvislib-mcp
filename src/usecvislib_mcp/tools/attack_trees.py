#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/attack_trees.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for attack tree visualization and analysis."""

import asyncio
import json

from usecvislib import AttackTreeBuilder, AttackTrees, USecVisLibError

from ..config import get_rate_limiter
from ..helpers import (
    build_and_analyze,
    build_visualization,
    format_error,
    log_tool_call,
    validate_format,
)
from ..output import OutputHandler
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_attack_tree(
    config: dict,
    format: str = "png",
    style: str = "at_default",
):
    """Generate an attack tree visualization from a configuration dictionary.

    The config should contain 'tree', 'nodes', and 'edges' sections following
    the USecVisLib attack tree schema. Returns the generated image file path
    or base64-encoded image data.

    Args:
        config: Attack tree configuration with tree/nodes/edges sections.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. at_default, at_corporate, at_neon).
    """
    try:
        return await build_visualization(
            AttackTrees, config, "attack_tree", fmt=format, styleid=style
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_attack_tree(config: dict) -> str:
    """Validate an attack tree configuration and return any errors.

    Checks the structure, node references, edge consistency, and other
    validation rules without generating a visualization.

    Args:
        config: Attack tree configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(AttackTrees, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_attack_tree_stats(config: dict) -> str:
    """Get statistics about an attack tree configuration.

    Returns node counts, depth, CVSS score distribution, and other metrics.

    Args:
        config: Attack tree configuration to analyze.
    """
    try:
        return await build_and_analyze(AttackTrees, config, "get_stats")
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def build_attack_tree_from_spec(
    name: str,
    root: str,
    nodes: list[dict],
    edges: list[dict],
    format: str = "png",
    style: str = "at_default",
):
    """Build an attack tree from a structured specification using the builder API.

    Instead of providing a full config dict, specify the tree components directly.

    Args:
        name: Name of the attack tree.
        root: Label of the root node.
        nodes: List of node dicts with keys: id, label (optional), fillcolor (optional),
               shape (optional), cvss (optional), cvss_vector (optional).
        edges: List of edge dicts with keys: from, to, label (optional).
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID.
    """
    try:
        validate_format(format)
        get_rate_limiter().check("build_attack_tree_from_spec")
        handler = OutputHandler()
        output_path = handler.make_output_path("attack_tree", format)

        def _sync_build():
            from pathlib import Path

            output_base = str(Path(output_path).with_suffix(""))
            builder = AttackTreeBuilder(name=name, root=root)

            for node in nodes:
                node = dict(node)  # Copy to avoid mutating caller's data
                node_id = node.pop("id") if "id" in node else node.pop("label", root)
                builder.add_node(node_id, **node)

            for edge in edges:
                edge = dict(edge)  # Copy to avoid mutating caller's data
                from_node = edge.pop("from")
                to_node = edge.pop("to")
                label = edge.pop("label", "")
                builder.add_edge(from_node, to_node, label=label, **edge)

            at = builder.to_attack_tree(outputfile=output_base, format=format, styleid=style)
            at.build()
            return output_path

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _sync_build)
        return handler.format_result(output_path, format)
    except (USecVisLibError, Exception) as e:
        return format_error(e)
