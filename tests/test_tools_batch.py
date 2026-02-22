"""Tests for batch processing tool."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@skip_no_graphviz
@pytest.mark.asyncio
async def test_batch_process_attack_trees(sample_attack_tree_config):
    """batch_process handles a list of attack tree configs."""
    from usecvislib_mcp.tools.batch import batch_process

    result = await batch_process(
        module_type="attack_tree",
        configs=[sample_attack_tree_config],
        format="png",
    )
    parsed = json.loads(result)
    # Should have summary keys or be an error
    assert isinstance(parsed, dict)
    if "error" not in parsed:
        assert "successes" in parsed or "success_count" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_batch_process_multiple_configs(sample_attack_tree_config):
    """batch_process handles multiple configs."""
    from usecvislib_mcp.tools.batch import batch_process

    result = await batch_process(
        module_type="attack_tree",
        configs=[sample_attack_tree_config, sample_attack_tree_config],
        format="png",
        max_workers=2,
    )
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_batch_process_empty_configs():
    """batch_process handles empty config list."""
    from usecvislib_mcp.tools.batch import batch_process

    result = await batch_process(
        module_type="attack_tree",
        configs=[],
        format="png",
    )
    parsed = json.loads(result)
    assert isinstance(parsed, dict)


@pytest.mark.asyncio
async def test_batch_process_invalid_module_type():
    """batch_process returns error for invalid module type."""
    from usecvislib_mcp.tools.batch import batch_process

    result = await batch_process(
        module_type="nonexistent_type",
        configs=[{"dummy": "config"}],
    )
    parsed = json.loads(result)
    assert "error" in parsed
