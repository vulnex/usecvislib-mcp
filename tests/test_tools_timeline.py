#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_timeline.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for incident timeline tools."""

import json
from pathlib import Path

import pytest

from tests.conftest import skip_no_timeline

pytestmark = skip_no_timeline


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["swimlane", "gantt", "vertical", "compact"])
@pytest.mark.parametrize("render_engine", ["graphviz", "svg"])
async def test_generate_incident_timeline(sample_timeline_config, mode, render_engine):
    from usecvislib_mcp.tools.timeline import generate_incident_timeline

    parsed = json.loads(
        await generate_incident_timeline(
            sample_timeline_config, format="svg", mode=mode, render_engine=render_engine
        )
    )
    assert "error" not in parsed, parsed
    assert Path(parsed["output_path"]).stat().st_size > 0


@pytest.mark.asyncio
async def test_generate_incident_timeline_rejects_bad_mode(sample_timeline_config):
    from usecvislib_mcp.tools.timeline import generate_incident_timeline

    parsed = json.loads(await generate_incident_timeline(sample_timeline_config, mode="spiral"))
    assert parsed["error"] == "ValueError"


@pytest.mark.asyncio
async def test_generate_incident_timeline_rejects_dot(sample_timeline_config):
    from usecvislib_mcp.tools.timeline import generate_incident_timeline

    parsed = json.loads(await generate_incident_timeline(sample_timeline_config, format="dot"))
    assert parsed["error"] == "ValueError"


@pytest.mark.asyncio
async def test_validate_incident_timeline(sample_timeline_config):
    from usecvislib_mcp.tools.timeline import validate_incident_timeline

    parsed = json.loads(await validate_incident_timeline(sample_timeline_config))
    assert parsed["valid"] is True, parsed


@pytest.mark.asyncio
async def test_get_incident_timeline_stats(sample_timeline_config):
    from usecvislib_mcp.tools.timeline import get_incident_timeline_stats

    parsed = json.loads(await get_incident_timeline_stats(sample_timeline_config))
    assert parsed["total_events"] == 3
    assert parsed["response_metrics"]["time_to_detect"] is not None
    assert parsed["response_metrics"]["time_to_contain"] is not None
