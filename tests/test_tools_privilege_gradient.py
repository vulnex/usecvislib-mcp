#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_privilege_gradient.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for privilege gradient tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz, skip_no_privilege_gradient


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_privilege_gradient(sample_privilege_gradient_config):
    """generate_privilege_gradient produces output file."""
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    result = await generate_privilege_gradient(sample_privilege_gradient_config, format="png")
    parsed = json.loads(result)
    assert "output_path" in parsed


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_validate_privilege_gradient(sample_privilege_gradient_config):
    """validate_privilege_gradient returns valid status."""
    from usecvislib_mcp.tools.privilege_gradient import validate_privilege_gradient

    result = await validate_privilege_gradient(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert "valid" in parsed
    assert parsed["valid"] is True


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_get_privilege_gradient_stats(sample_privilege_gradient_config):
    """get_privilege_gradient_stats returns statistics."""
    from usecvislib_mcp.tools.privilege_gradient import get_privilege_gradient_stats

    result = await get_privilege_gradient_stats(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "error" not in parsed


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_detect_privilege_inversions(sample_privilege_gradient_config):
    """detect_privilege_inversions returns inversion data."""
    from usecvislib_mcp.tools.privilege_gradient import detect_privilege_inversions

    result = await detect_privilege_inversions(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert isinstance(parsed, (list, dict))
    if isinstance(parsed, dict):
        assert "error" not in parsed


@skip_no_privilege_gradient
@pytest.mark.asyncio
async def test_schema_trust_level_detects_inversions(sample_privilege_gradient_config):
    """Zones written as the schema documents (trust_level) give their real inversions.

    With the field the schema used to document ('level'), every zone had trust 0
    and no inversion was ever found.
    """
    from usecvislib_mcp.resources.schemas import get_privilege_gradient_schema
    from usecvislib_mcp.tools.privilege_gradient import detect_privilege_inversions

    zone_fields = json.loads(get_privilege_gradient_schema())["sections"]["zones"]["value_fields"]
    assert "trust_level" in zone_fields and "level" not in zone_fields
    config = dict(sample_privilege_gradient_config)
    config["influences"] = [{"from": "cdn", "to": "api", "type": "control"}]
    parsed = json.loads(await detect_privilege_inversions(config))
    assert [(i["from"], i["to"], i["severity"]) for i in parsed] == [("cdn", "api", "high")]


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_analyze_zone_influence(sample_privilege_gradient_config):
    """analyze_zone_influence returns influence matrix."""
    from usecvislib_mcp.tools.privilege_gradient import analyze_zone_influence

    result = await analyze_zone_influence(sample_privilege_gradient_config)
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "error" not in parsed


@skip_no_privilege_gradient
@pytest.mark.asyncio
async def test_validate_invalid_privilege_gradient():
    """validate_privilege_gradient reports errors for invalid config."""
    from usecvislib_mcp.tools.privilege_gradient import validate_privilege_gradient

    result = await validate_privilege_gradient({"invalid": "config"})
    parsed = json.loads(result)
    if "valid" in parsed:
        assert parsed["valid"] is False or len(parsed.get("errors", [])) > 0
    else:
        assert "error" in parsed
