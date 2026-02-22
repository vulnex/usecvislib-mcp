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
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_custom_diagram(sample_custom_diagram_config):
    """validate_custom_diagram returns validation report."""
    from usecvislib_mcp.tools.custom_diagrams import validate_custom_diagram

    result = await validate_custom_diagram(sample_custom_diagram_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_custom_diagram_stats(sample_custom_diagram_config):
    """get_custom_diagram_stats returns statistics."""
    from usecvislib_mcp.tools.custom_diagrams import get_custom_diagram_stats

    result = await get_custom_diagram_stats(sample_custom_diagram_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_validate_custom_diagram_invalid():
    """validate_custom_diagram handles invalid config."""
    from usecvislib_mcp.tools.custom_diagrams import validate_custom_diagram

    result = await validate_custom_diagram({"invalid": "config"})
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
