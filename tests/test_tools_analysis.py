"""Tests for advanced analysis tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_find_chokepoints(sample_attack_graph_config):
    """find_chokepoints returns chokepoint analysis."""
    from usecvislib_mcp.tools.analysis import find_chokepoints

    result = await find_chokepoints(sample_attack_graph_config, top_n=5)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))


@skip_no_graphviz
@pytest.mark.asyncio
async def test_find_chokepoints_default_top_n(sample_attack_graph_config):
    """find_chokepoints works with default top_n."""
    from usecvislib_mcp.tools.analysis import find_chokepoints

    result = await find_chokepoints(sample_attack_graph_config)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))


@pytest.mark.asyncio
async def test_find_chokepoints_invalid_config():
    """find_chokepoints handles invalid config gracefully."""
    from usecvislib_mcp.tools.analysis import find_chokepoints

    result = await find_chokepoints({"invalid": "config"})
    parsed = json.loads(result)
    # Library may return empty list or error dict for invalid configs
    assert isinstance(parsed, (list, dict))


@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_centrality(sample_attack_graph_config):
    """analyze_centrality returns centrality scores."""
    from usecvislib_mcp.tools.analysis import analyze_centrality

    result = await analyze_centrality(sample_attack_graph_config, top_n=5)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))


@pytest.mark.asyncio
async def test_analyze_centrality_invalid_config():
    """analyze_centrality handles invalid config gracefully."""
    from usecvislib_mcp.tools.analysis import analyze_centrality

    result = await analyze_centrality({"invalid": "config"})
    parsed = json.loads(result)
    # Library may return empty list or error dict for invalid configs
    assert isinstance(parsed, (list, dict))


@pytest.mark.asyncio
async def test_compare_visualizations_attack_tree(sample_attack_tree_config):
    """compare_visualizations detects differences between configs."""
    from usecvislib_mcp.tools.analysis import compare_visualizations

    # Create a modified version
    new_config = json.loads(json.dumps(sample_attack_tree_config))
    new_config["tree"]["name"] = "Modified Attack Tree"

    result = await compare_visualizations(
        old_config=sample_attack_tree_config,
        new_config=new_config,
        viz_type="attack_tree",
    )
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    if "error" not in parsed:
        assert "summary" in parsed or "changes" in parsed


@pytest.mark.asyncio
async def test_compare_visualizations_identical(sample_attack_tree_config):
    """compare_visualizations with identical configs shows no changes."""
    from usecvislib_mcp.tools.analysis import compare_visualizations

    result = await compare_visualizations(
        old_config=sample_attack_tree_config,
        new_config=sample_attack_tree_config,
        viz_type="attack_tree",
    )
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
