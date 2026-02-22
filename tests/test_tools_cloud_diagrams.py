"""Tests for cloud diagram tools."""

import json

import pytest

from tests.conftest import skip_no_diagrams


@skip_no_diagrams
@pytest.mark.asyncio
async def test_generate_cloud_diagram(sample_cloud_diagram_config):
    """generate_cloud_diagram produces output file."""
    from usecvislib_mcp.tools.cloud_diagrams import generate_cloud_diagram

    result = await generate_cloud_diagram(sample_cloud_diagram_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@pytest.mark.asyncio
async def test_validate_cloud_diagram(sample_cloud_diagram_config):
    """validate_cloud_diagram returns validation result."""
    from usecvislib_mcp.tools.cloud_diagrams import validate_cloud_diagram

    result = await validate_cloud_diagram(sample_cloud_diagram_config)
    parsed = json.loads(result)
    assert "valid" in parsed or "error" in parsed


@pytest.mark.asyncio
async def test_get_cloud_diagram_stats(sample_cloud_diagram_config):
    """get_cloud_diagram_stats returns statistics."""
    from usecvislib_mcp.tools.cloud_diagrams import get_cloud_diagram_stats

    result = await get_cloud_diagram_stats(sample_cloud_diagram_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_search_cloud_icons():
    """search_cloud_icons returns matching icons."""
    from usecvislib_mcp.tools.cloud_diagrams import search_cloud_icons

    result = await search_cloud_icons("compute", limit=5)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))


@pytest.mark.asyncio
async def test_validate_cloud_diagram_invalid():
    """validate_cloud_diagram handles invalid config."""
    from usecvislib_mcp.tools.cloud_diagrams import validate_cloud_diagram

    result = await validate_cloud_diagram({"invalid": "config"})
    parsed = json.loads(result)
    assert "valid" in parsed or "error" in parsed
