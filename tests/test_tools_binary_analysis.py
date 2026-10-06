#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_binary_analysis.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for binary analysis tools."""

import json
import os

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_entropy(sample_binary_file):
    """analyze_binary_entropy produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_entropy

    result = await analyze_binary_entropy(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed
    assert os.path.getsize(parsed["output_path"]) > 0  # the reported path is the file written


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_distribution(sample_binary_file):
    """analyze_binary_distribution produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_distribution

    result = await analyze_binary_distribution(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed
    assert os.path.getsize(parsed["output_path"]) > 0  # the reported path is the file written


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_heatmap(sample_binary_file):
    """analyze_binary_heatmap produces output file."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_heatmap

    result = await analyze_binary_heatmap(sample_binary_file, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed
    assert os.path.getsize(parsed["output_path"]) > 0  # the reported path is the file written


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_all(sample_binary_file):
    """analyze_binary_all produces one file per chart."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_all

    result = await analyze_binary_all(sample_binary_file, format="png")
    charts = json.loads(result)["charts"]
    assert all(os.path.getsize(c["output_path"]) > 0 for c in charts)


@pytest.mark.asyncio
async def test_get_binary_stats(sample_binary_file):
    """get_binary_stats returns statistics."""
    from usecvislib_mcp.tools.binary_analysis import get_binary_stats

    result = await get_binary_stats(sample_binary_file)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "error" not in parsed


@pytest.mark.asyncio
async def test_get_binary_stats_nonexistent():
    """get_binary_stats handles missing file gracefully."""
    from usecvislib_mcp.tools.binary_analysis import get_binary_stats

    result = await get_binary_stats("/nonexistent/file.bin")
    parsed = json.loads(result)
    assert "error" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_digraph(sample_binary_file):
    """The byte-pair digraph renders to the reported path, in every format and a style."""
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_digraph

    for fmt in ("png", "svg", "pdf"):
        parsed = json.loads(
            await analyze_binary_digraph(sample_binary_file, format=fmt, style="bv_dark")
        )
        assert "error" not in parsed, parsed
        assert parsed["output_path"].endswith(f".{fmt}")
        assert os.path.getsize(parsed["output_path"]) > 0


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_binary_all_returns_every_chart(sample_binary_file):
    from usecvislib_mcp.tools.binary_analysis import analyze_binary_all

    parsed = json.loads(await analyze_binary_all(sample_binary_file, style="bv_security"))
    charts = parsed["charts"]
    assert [c["type"] for c in charts] == [
        "entropy",
        "distribution",
        "windrose",
        "heatmap",
        "digraph",
    ]
    for chart in charts:
        assert os.path.getsize(chart["output_path"]) == chart["size_bytes"] > 0


@pytest.mark.asyncio
async def test_analyze_binary_all_base64_mode(sample_binary_file, monkeypatch):
    import base64

    from usecvislib_mcp.tools.binary_analysis import analyze_binary_all

    monkeypatch.setenv("USECVISLIB_MCP_OUTPUT_MODE", "base64")
    charts = json.loads(await analyze_binary_all(sample_binary_file))["charts"]
    assert len(charts) == 5
    assert all(base64.b64decode(c["data_base64"]).startswith(b"\x89PNG") for c in charts)
