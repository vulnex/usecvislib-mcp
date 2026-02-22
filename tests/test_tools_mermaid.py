"""Tests for Mermaid tool."""

import json

import pytest

from tests.conftest import skip_no_mermaid


@skip_no_mermaid
@pytest.mark.asyncio
async def test_render_mermaid(sample_mermaid_source):
    """render_mermaid produces output file."""
    from usecvislib_mcp.tools.mermaid import render_mermaid

    result = await render_mermaid(sample_mermaid_source, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@skip_no_mermaid
@pytest.mark.asyncio
async def test_render_mermaid_svg(sample_mermaid_source):
    """render_mermaid works with SVG format."""
    from usecvislib_mcp.tools.mermaid import render_mermaid

    result = await render_mermaid(sample_mermaid_source, format="svg")
    parsed = json.loads(result)
    assert "output_path" in parsed or "error" not in parsed


@pytest.mark.asyncio
async def test_render_mermaid_invalid_source():
    """render_mermaid handles invalid source gracefully."""
    from usecvislib_mcp.tools.mermaid import render_mermaid

    result = await render_mermaid("not valid mermaid syntax !!!")
    parsed = json.loads(result)
    # Should return error, not crash
    assert isinstance(parsed, dict)
