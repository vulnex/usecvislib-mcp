#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_attack_graphs.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for attack graph tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_attack_graph(sample_attack_graph_config):
    """generate_attack_graph produces output."""
    from usecvislib_mcp.tools.attack_graphs import generate_attack_graph

    result = await generate_attack_graph(sample_attack_graph_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_attack_graph(sample_attack_graph_config):
    """validate_attack_graph returns valid status."""
    from usecvislib_mcp.tools.attack_graphs import validate_attack_graph

    result = await validate_attack_graph(sample_attack_graph_config)
    parsed = json.loads(result)
    assert "valid" in parsed
    assert parsed["valid"] is True


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_attack_graph_stats(sample_attack_graph_config):
    """get_attack_graph_stats returns statistics."""
    from usecvislib_mcp.tools.attack_graphs import get_attack_graph_stats

    result = await get_attack_graph_stats(sample_attack_graph_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_find_attack_paths(sample_attack_graph_config):
    """find_attack_paths finds paths between nodes."""
    from usecvislib_mcp.tools.attack_graphs import find_attack_paths

    result = await find_attack_paths(
        sample_attack_graph_config,
        source="attacker",
        target="dbserver",
    )
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))
    if isinstance(parsed, dict):
        assert "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_critical_nodes(sample_attack_graph_config):
    """analyze_critical_nodes identifies critical nodes."""
    from usecvislib_mcp.tools.attack_graphs import analyze_critical_nodes

    result = await analyze_critical_nodes(sample_attack_graph_config, top_n=5)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))
    if isinstance(parsed, dict):
        assert "error" not in parsed


@pytest.mark.asyncio
async def test_validate_invalid_attack_graph():
    """validate_attack_graph reports errors for invalid config."""
    from usecvislib_mcp.tools.attack_graphs import validate_attack_graph

    result = await validate_attack_graph({"invalid": "config"})
    parsed = json.loads(result)
    if "valid" in parsed:
        assert parsed["valid"] is False or len(parsed.get("errors", [])) > 0
    else:
        assert "error" in parsed
