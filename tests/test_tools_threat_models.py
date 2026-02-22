"""Tests for threat model tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_threat_model(sample_threat_model_config):
    """generate_threat_model produces output."""
    from usecvislib_mcp.tools.threat_models import generate_threat_model

    result = await generate_threat_model(sample_threat_model_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_threat_model(sample_threat_model_config):
    """validate_threat_model returns valid status."""
    from usecvislib_mcp.tools.threat_models import validate_threat_model

    result = await validate_threat_model(sample_threat_model_config)
    parsed = json.loads(result)
    assert "valid" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_threat_model_stats(sample_threat_model_config):
    """get_threat_model_stats returns statistics."""
    from usecvislib_mcp.tools.threat_models import get_threat_model_stats

    result = await get_threat_model_stats(sample_threat_model_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_stride_threats(sample_threat_model_config):
    """analyze_stride_threats performs STRIDE analysis."""
    from usecvislib_mcp.tools.threat_models import analyze_stride_threats

    result = await analyze_stride_threats(sample_threat_model_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_validate_invalid_threat_model():
    """validate_threat_model reports errors for invalid config."""
    from usecvislib_mcp.tools.threat_models import validate_threat_model

    result = await validate_threat_model({"invalid": "config"})
    parsed = json.loads(result)
    assert "valid" in parsed or "error" in parsed
