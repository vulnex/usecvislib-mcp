#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/analysis.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for advanced cross-module analysis."""

import base64
import json
from pathlib import Path

from usecvislib import AttackGraphs, compare_files, render_diff

from ..helpers import (
    RENDER_ENGINES,
    build_and_analyze,
    check_rate_limit,
    format_error,
    grouping_options,
    log_tool_call,
    run_with_timeout,
    temp_config_file,
    validate_format,
    validate_int_range,
)
from ..output import OutputHandler
from ..server import mcp

DRIFT_TYPES = frozenset({"attack_graph", "privilege_gradient"})
DRIFT_FORMATS = frozenset({"png", "pdf", "svg"})


@mcp.tool()
@log_tool_call
async def find_chokepoints(
    config: dict,
    top_n: int = 10,
) -> str:
    """Find network chokepoints in an attack graph.

    Identifies nodes that appear on the most attack paths, representing
    critical points for defensive controls.

    Args:
        config: Attack graph configuration dictionary.
        top_n: Number of top chokepoints to return.

    Returns:
        JSON list of chokepoint nodes with scores.
    """
    try:
        validate_int_range(top_n, "top_n", 1, 1000)
        return await build_and_analyze(AttackGraphs, config, "find_chokepoints", top_n=top_n)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_centrality(
    config: dict,
    top_n: int = 10,
) -> str:
    """Compute betweenness centrality for attack graph nodes.

    Identifies nodes that act as bridges between different parts of the
    network, highlighting critical infrastructure components.

    Args:
        config: Attack graph configuration dictionary.
        top_n: Number of top central nodes to return.

    Returns:
        JSON list of nodes with centrality scores.
    """
    try:
        validate_int_range(top_n, "top_n", 1, 1000)
        return await build_and_analyze(AttackGraphs, config, "betweenness_centrality", top_n=top_n)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def compare_visualizations(
    old_config: dict,
    new_config: dict,
    viz_type: str,
) -> str:
    """Compare two visualization configs and return a diff.

    Computes structural differences between an old and new version
    of a visualization configuration.

    Args:
        old_config: Previous version of the configuration.
        new_config: New version of the configuration.
        viz_type: Visualization type — 'attack_tree', 'attack_graph',
                  'threat_model', 'privilege_gradient', 'component_diagram',
                  'dependency_graph', 'kill_chain', 'incident_timeline',
                  'vuln_tree', or 'maestro'.

    Returns:
        JSON with change summary (added/removed/modified counts)
        and detailed list of changes.
    """
    try:
        check_rate_limit("compare_visualizations")

        def _sync_compare():
            with temp_config_file(old_config) as old_path:
                with temp_config_file(new_config) as new_path:
                    result = compare_files(old_path, new_path, viz_type)
                    return result.to_dict()

        result = await run_with_timeout(_sync_compare)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def render_drift(
    old_config: dict,
    new_config: dict,
    viz_type: str = "attack_graph",
    format: str = "png",
    render_engine: str = "graphviz",
    style: str = "",
    show_unchanged: bool = True,
    ignore_paths: list[str] | None = None,
    diff_colors: dict[str, str] | None = None,
    group_by: str = "",
    collapse: str | list[str] | bool | None = None,
    max_nodes: int | None = None,
    keep: str = "",
    keep_ids: list[str] | None = None,
) -> str:
    """Draw the drift between two versions of an attack graph or privilege gradient.

    One picture of the merged graph: added elements in green with '+', removed
    ones faded in red with '−', modified ones in amber with '~'. For privilege
    gradients, tiering violations are compared too: new ones are labelled
    'NEW INVERSION', fixed ones 'FIXED INVERSION', and ones whose severity or
    trust gap changed '~ INVERSION (old → new)'.

    Args:
        old_config: The earlier version.
        new_config: The later version.
        viz_type: 'attack_graph' or 'privilege_gradient'.
        format: png, pdf, or svg.
        render_engine: graphviz (default) or svg.
        style: Style preset of the module ('' for the engine's default).
        show_unchanged: False draws only changed elements and their direct neighbours.
        ignore_paths: Config path prefixes to ignore (e.g. ['graph.description']).
        diff_colors: Override any of 'added', 'removed', 'modified' (hex colors).
        group_by, collapse, max_nodes: Grouping and collapse of the merged graph,
               as in generate_attack_graph / generate_privilege_gradient. A
               collapsed group shows its members' changes (+N −N ~N).
        keep, keep_ids: Privilege gradients: components kept drawn next to their
               collapsed group; keep='inversions' also keeps the endpoints of new,
               fixed and changed inversions.

    Returns:
        JSON with 'summary' (added/removed/modified/total), 'has_changes',
        'changes', for privilege gradients 'inversions' (new/fixed/changed), and
        the picture: 'output_path' and 'size_bytes' (file output mode) or
        'data_base64' (base64 mode).
    """
    try:
        if viz_type not in DRIFT_TYPES:
            raise ValueError(
                f"render_drift supports {', '.join(sorted(DRIFT_TYPES))}, not '{viz_type}'"
            )
        validate_format(format, DRIFT_FORMATS)
        if render_engine not in RENDER_ENGINES:
            raise ValueError(
                f"Invalid render_engine '{render_engine}'. "
                f"Allowed: {', '.join(sorted(RENDER_ENGINES))}"
            )
        options = grouping_options(group_by, collapse, max_nodes, keep, keep_ids)
        if viz_type == "attack_graph" and ("keep" in options or "keep_ids" in options):
            raise ValueError("keep and keep_ids apply to privilege gradients only")
        check_rate_limit("render_drift")
        handler = OutputHandler()
        output_path = handler.make_output_path(f"drift_{viz_type}", format)
        output_base = str(Path(output_path).with_suffix(""))

        def _sync_drift():
            with temp_config_file(old_config) as old_path:
                with temp_config_file(new_config) as new_path:
                    return render_diff(
                        old_path,
                        new_path,
                        visualization_type=viz_type,
                        output=output_base,
                        format=format,
                        render_engine=render_engine,
                        style=style,
                        diff_colors=diff_colors,
                        ignore_paths=ignore_paths,
                        show_unchanged=show_unchanged,
                        **options,
                    )

        diff = await run_with_timeout(_sync_drift)
        result = diff.to_dict()
        result.pop("old_source", None)  # temp file paths
        result.pop("new_source", None)
        result["changes"] = [c for c in result["changes"] if c["type"] != "unchanged"]
        metadata = result.pop("metadata", {}) or {}
        if "inversions" in metadata:
            result["inversions"] = metadata["inversions"]
        result.update(viz_type=viz_type, format=format)
        path = Path(output_path)
        if handler.mode == "file":
            result.update(output_path=str(path), size_bytes=path.stat().st_size)
        else:
            result["data_base64"] = base64.b64encode(path.read_bytes()).decode("ascii")
            path.unlink(missing_ok=True)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return format_error(e)
