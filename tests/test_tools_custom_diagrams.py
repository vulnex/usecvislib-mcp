#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_custom_diagrams.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for custom diagram tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_custom_diagram(sample_custom_diagram_config):
    """generate_custom_diagram produces output file."""
    from usecvislib_mcp.tools.custom_diagrams import generate_custom_diagram

    result = await generate_custom_diagram(sample_custom_diagram_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_custom_diagram(sample_custom_diagram_config):
    """validate_custom_diagram returns validation report."""
    from usecvislib_mcp.tools.custom_diagrams import validate_custom_diagram

    result = await validate_custom_diagram(sample_custom_diagram_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_custom_diagram_stats(sample_custom_diagram_config):
    """get_custom_diagram_stats returns statistics."""
    from usecvislib_mcp.tools.custom_diagrams import get_custom_diagram_stats

    result = await get_custom_diagram_stats(sample_custom_diagram_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "error" not in parsed


@pytest.mark.asyncio
async def test_validate_custom_diagram_invalid():
    """validate_custom_diagram handles invalid config."""
    from usecvislib_mcp.tools.custom_diagrams import validate_custom_diagram

    result = await validate_custom_diagram({"invalid": "config"})
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "valid" in parsed or "error" in parsed
