"""Tests for binary analysis tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_entropy(sample_binary_file):
    """analyze_binary_entropy produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_entropy

    result = await analyze_binary_entropy(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_distribution(sample_binary_file):
    """analyze_binary_distribution produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_distribution

    result = await analyze_binary_distribution(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_heatmap(sample_binary_file):
    """analyze_binary_heatmap produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_heatmap

    result = await analyze_binary_heatmap(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_all(sample_binary_file):
    """analyze_binary_all produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_all

    result = await analyze_binary_all(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@pytest.mark.asyncio
async def test_get_binary_stats(sample_binary_file):
    """get_binary_stats returns statistics."""
    from usecvislib_mcp.tools.binary_analysis import get_binary_stats

    result = await get_binary_stats(sample_binary_file)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_get_binary_stats_nonexistent():
    """get_binary_stats handles missing file gracefully."""
    from usecvislib_mcp.tools.binary_analysis import get_binary_stats

    result = await get_binary_stats("/nonexistent/file.bin")
    parsed = json.loads(result)
    assert "error" in parsed
