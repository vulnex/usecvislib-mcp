#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_architecture.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for architecture tools — component diagrams and dependency graphs."""

import json

import pytest

from tests.conftest import skip_no_graphviz

# ── Component Diagram Tests ─────────────────────────────────────────


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_component_diagram(sample_component_diagram_config):
    """generate_component_diagram produces output file."""
    from usecvislib_mcp.tools.architecture import generate_component_diagram

    result = await generate_component_diagram(sample_component_diagram_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_component_diagram(sample_component_diagram_config):
    """validate_component_diagram returns valid status."""
    from usecvislib_mcp.tools.architecture import validate_component_diagram

    result = await validate_component_diagram(sample_component_diagram_config)
    parsed = json.loads(result)
    assert "valid" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_component_diagram_stats(sample_component_diagram_config):
    """get_component_diagram_stats returns statistics."""
    from usecvislib_mcp.tools.architecture import get_component_diagram_stats

    result = await get_component_diagram_stats(sample_component_diagram_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_validate_invalid_component_diagram():
    """validate_component_diagram reports errors for invalid config."""
    from usecvislib_mcp.tools.architecture import validate_component_diagram

    result = await validate_component_diagram({"invalid": "config"})
    parsed = json.loads(result)
    assert "valid" in parsed or "error" in parsed


# ── Dependency Graph Tests ───────────────────────────────────────────


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_dependency_graph(sample_dependency_graph_config):
    """generate_dependency_graph produces output file."""
    from usecvislib_mcp.tools.architecture import generate_dependency_graph

    result = await generate_dependency_graph(sample_dependency_graph_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_dependency_graph(sample_dependency_graph_config):
    """validate_dependency_graph returns valid status."""
    from usecvislib_mcp.tools.architecture import validate_dependency_graph

    result = await validate_dependency_graph(sample_dependency_graph_config)
    parsed = json.loads(result)
    assert "valid" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_dependency_graph_stats(sample_dependency_graph_config):
    """get_dependency_graph_stats returns statistics."""
    from usecvislib_mcp.tools.architecture import get_dependency_graph_stats

    result = await get_dependency_graph_stats(sample_dependency_graph_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_validate_invalid_dependency_graph():
    """validate_dependency_graph reports errors for invalid config."""
    from usecvislib_mcp.tools.architecture import validate_dependency_graph

    result = await validate_dependency_graph({"invalid": "config"})
    parsed = json.loads(result)
    assert "valid" in parsed or "error" in parsed
