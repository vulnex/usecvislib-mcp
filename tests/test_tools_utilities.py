#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_utilities.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for utility tools."""

import json

import pytest


@pytest.mark.asyncio
async def test_convert_to_mermaid(sample_attack_tree_config):
    """convert_to_mermaid produces Mermaid syntax from attack tree config."""
    from usecvislib_mcp.tools.utilities import convert_to_mermaid

    result = await convert_to_mermaid(sample_attack_tree_config)
    parsed = json.loads(result)
    assert "mermaid_source" in parsed or "error" in parsed


@pytest.mark.asyncio
async def test_convert_to_mermaid_with_type(sample_attack_tree_config):
    """convert_to_mermaid works with explicit viz_type."""
    from usecvislib_mcp.tools.utilities import convert_to_mermaid

    result = await convert_to_mermaid(sample_attack_tree_config, viz_type="attack_tree")
    parsed = json.loads(result)
    assert "mermaid_source" in parsed or "error" in parsed


@pytest.mark.asyncio
async def test_calculate_cvss_score_v31():
    """calculate_cvss_score parses CVSS 3.1 vector."""
    from usecvislib_mcp.tools.utilities import calculate_cvss_score

    result = await calculate_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    parsed = json.loads(result)
    assert "score" in parsed or "error" in parsed
    if "score" in parsed:
        assert parsed["score"] >= 9.0
        assert parsed["severity"] == "Critical"
        assert parsed["version"] == "3.1"


@pytest.mark.asyncio
async def test_calculate_cvss_score_invalid():
    """calculate_cvss_score handles invalid vector."""
    from usecvislib_mcp.tools.utilities import calculate_cvss_score

    result = await calculate_cvss_score("not-a-valid-vector")
    parsed = json.loads(result)
    assert "error" in parsed


@pytest.mark.asyncio
async def test_detect_config_type_attack_tree(sample_attack_tree_config):
    """detect_config_type identifies attack tree config."""
    from usecvislib_mcp.tools.utilities import detect_config_type

    result = await detect_config_type(sample_attack_tree_config)
    parsed = json.loads(result)
    assert parsed["type"] == "attack_tree"
    assert parsed["confidence"] == "high"


@pytest.mark.asyncio
async def test_detect_config_type_attack_graph(sample_attack_graph_config):
    """detect_config_type identifies attack graph config."""
    from usecvislib_mcp.tools.utilities import detect_config_type

    result = await detect_config_type(sample_attack_graph_config)
    parsed = json.loads(result)
    assert parsed["type"] == "attack_graph"
    assert parsed["confidence"] == "high"


@pytest.mark.asyncio
async def test_detect_config_type_threat_model(sample_threat_model_config):
    """detect_config_type identifies threat model config."""
    from usecvislib_mcp.tools.utilities import detect_config_type

    result = await detect_config_type(sample_threat_model_config)
    parsed = json.loads(result)
    assert parsed["type"] == "threat_model"
    assert parsed["confidence"] == "high"


@pytest.mark.asyncio
async def test_detect_config_type_unknown():
    """detect_config_type returns unknown for unrecognized config."""
    from usecvislib_mcp.tools.utilities import detect_config_type

    result = await detect_config_type({"random": "data"})
    parsed = json.loads(result)
    assert parsed["type"] == "unknown"
