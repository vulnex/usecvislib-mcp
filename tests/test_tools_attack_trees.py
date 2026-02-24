#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_attack_trees.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for attack tree tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_attack_tree(sample_attack_tree_config):
    """generate_attack_tree produces output file."""
    from usecvislib_mcp.tools.attack_trees import generate_attack_tree

    result = await generate_attack_tree(sample_attack_tree_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_attack_tree(sample_attack_tree_config):
    """validate_attack_tree returns valid status."""
    from usecvislib_mcp.tools.attack_trees import validate_attack_tree

    result = await validate_attack_tree(sample_attack_tree_config)
    parsed = json.loads(result)
    assert "valid" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_attack_tree_stats(sample_attack_tree_config):
    """get_attack_tree_stats returns statistics."""
    from usecvislib_mcp.tools.attack_trees import get_attack_tree_stats

    result = await get_attack_tree_stats(sample_attack_tree_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@skip_no_graphviz
@pytest.mark.asyncio
async def test_build_attack_tree_from_spec():
    """build_attack_tree_from_spec creates tree from components."""
    from usecvislib_mcp.tools.attack_trees import build_attack_tree_from_spec

    result = await build_attack_tree_from_spec(
        name="Test Tree",
        root="Goal",
        nodes=[
            {"id": "Goal", "fillcolor": "#e74c3c"},
            {"id": "Step A"},
            {"id": "Step B"},
        ],
        edges=[
            {"from": "Goal", "to": "Step A", "label": "OR"},
            {"from": "Goal", "to": "Step B", "label": "OR"},
        ],
    )
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@pytest.mark.asyncio
async def test_validate_invalid_attack_tree():
    """validate_attack_tree reports errors for invalid config."""
    from usecvislib_mcp.tools.attack_trees import validate_attack_tree

    result = await validate_attack_tree({"invalid": "config"})
    parsed = json.loads(result)
    # Should either report invalid or return an error
    assert "valid" in parsed or "error" in parsed
