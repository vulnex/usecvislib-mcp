"""MCP tools for advanced cross-module analysis."""

import asyncio
import json

from usecvislib import AttackGraphs, USecVisLibError, compare_files

from ..helpers import build_and_analyze, format_error, temp_config_file
from ..server import mcp


@mcp.tool()
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
        return await build_and_analyze(
            AttackGraphs, config, "find_chokepoints", top_n=top_n
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
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
        return await build_and_analyze(
            AttackGraphs, config, "betweenness_centrality", top_n=top_n
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
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
                  or 'threat_model'.

    Returns:
        JSON with change summary (added/removed/modified counts)
        and detailed list of changes.
    """
    try:

        def _sync_compare():
            with temp_config_file(old_config) as old_path:
                with temp_config_file(new_config) as new_path:
                    result = compare_files(old_path, new_path, viz_type)
                    return result.to_dict()

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_compare)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)
