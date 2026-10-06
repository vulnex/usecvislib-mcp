#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_maestro.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for MAESTRO agentic-AI threat model tools."""

import json
from pathlib import Path

import pytest

from tests.conftest import skip_no_graphviz, skip_no_maestro

pytestmark = skip_no_maestro


@skip_no_graphviz
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "view,render_engine,fmt",
    [
        ("layered", "graphviz", "png"),
        ("graph", "graphviz", "svg"),
        ("graph", "svg", "svg"),
        ("heatmap", "graphviz", "png"),
    ],
)
async def test_generate_maestro_threat_model(sample_maestro_config, view, render_engine, fmt):
    from usecvislib_mcp.tools.maestro import generate_maestro_threat_model

    parsed = json.loads(
        await generate_maestro_threat_model(
            sample_maestro_config, format=fmt, view=view, render_engine=render_engine
        )
    )
    assert "error" not in parsed, parsed
    assert Path(parsed["output_path"]).stat().st_size > 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"view": "pyramid"},
        {"view": "layered", "render_engine": "svg"},
        {"view": "heatmap", "format": "dot"},
    ],
)
async def test_generate_maestro_rejects_invalid_combinations(sample_maestro_config, kwargs):
    from usecvislib_mcp.tools.maestro import generate_maestro_threat_model

    parsed = json.loads(await generate_maestro_threat_model(sample_maestro_config, **kwargs))
    assert parsed["error"] == "ValueError"


@pytest.mark.asyncio
async def test_validate_maestro_threat_model(sample_maestro_config):
    from usecvislib_mcp.tools.maestro import validate_maestro_threat_model

    parsed = json.loads(await validate_maestro_threat_model(sample_maestro_config))
    assert parsed["valid"] is True, parsed


@pytest.mark.asyncio
async def test_get_maestro_stats_auto_populates_catalog(sample_maestro_config):
    from usecvislib_mcp.tools.maestro import get_maestro_stats

    parsed = json.loads(await get_maestro_stats(sample_maestro_config))
    assert parsed["total_agents"] == 1
    assert parsed["total_threats"] > 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target,key",
    [("stride", "dataflows"), ("attack_graph", "hosts"), ("privilege_gradient", "zones")],
)
async def test_export_maestro(sample_maestro_config, target, key):
    from usecvislib_mcp.tools.maestro import export_maestro

    parsed = json.loads(await export_maestro(sample_maestro_config, target=target))
    assert "error" not in parsed, parsed
    assert key in parsed


@pytest.mark.asyncio
async def test_export_maestro_rejects_unknown_target(sample_maestro_config):
    from usecvislib_mcp.tools.maestro import export_maestro

    parsed = json.loads(await export_maestro(sample_maestro_config, target="excel"))
    assert parsed["error"] == "ValueError"
