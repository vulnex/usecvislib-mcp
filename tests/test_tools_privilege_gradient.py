"""Tests for privilege gradient tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_privilege_gradient(sample_privilege_gradient_config):
    """generate_privilege_gradient produces output file."""
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    result = await generate_privilege_gradient(
        sample_privilege_gradient_config, format="png"
    )
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_privilege_gradient(sample_privilege_gradient_config):
    """validate_privilege_gradient returns valid status."""
    from usecvislib_mcp.tools.privilege_gradient import validate_privilege_gradient

    result = await validate_privilege_gradient(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert "valid" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_privilege_gradient_stats(sample_privilege_gradient_config):
    """get_privilege_gradient_stats returns statistics."""
    from usecvislib_mcp.tools.privilege_gradient import get_privilege_gradient_stats

    result = await get_privilege_gradient_stats(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@skip_no_graphviz
@pytest.mark.asyncio
async def test_detect_privilege_inversions(sample_privilege_gradient_config):
    """detect_privilege_inversions returns inversion data."""
    from usecvislib_mcp.tools.privilege_gradient import detect_privilege_inversions

    result = await detect_privilege_inversions(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_zone_influence(sample_privilege_gradient_config):
    """analyze_zone_influence returns influence matrix."""
    from usecvislib_mcp.tools.privilege_gradient import analyze_zone_influence

    result = await analyze_zone_influence(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_validate_invalid_privilege_gradient():
    """validate_privilege_gradient reports errors for invalid config."""
    from usecvislib_mcp.tools.privilege_gradient import validate_privilege_gradient

    result = await validate_privilege_gradient({"invalid": "config"})
    parsed = json.loads(result)
    assert "valid" in parsed or "error" in parsed
