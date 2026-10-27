#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_kill_chain.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for kill chain tools."""

import json
from pathlib import Path

import pytest

from tests.conftest import skip_no_graphviz, skip_no_kill_chain

pytestmark = skip_no_kill_chain


@skip_no_graphviz
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "render_engine,fmt", [("graphviz", "png"), ("graphviz", "dot"), ("svg", "svg")]
)
async def test_generate_kill_chain(sample_kill_chain_config, render_engine, fmt):
    from usecvislib_mcp.tools.kill_chain import generate_kill_chain

    parsed = json.loads(
        await generate_kill_chain(sample_kill_chain_config, format=fmt, render_engine=render_engine)
    )
    assert "error" not in parsed, parsed
    assert Path(parsed["output_path"]).stat().st_size > 0


@pytest.mark.asyncio
async def test_validate_kill_chain(sample_kill_chain_config):
    from usecvislib_mcp.tools.kill_chain import validate_kill_chain

    parsed = json.loads(await validate_kill_chain(sample_kill_chain_config))
    assert parsed["valid"] is True, parsed


@pytest.mark.asyncio
async def test_validate_kill_chain_unknown_phase(sample_kill_chain_config):
    from usecvislib_mcp.tools.kill_chain import validate_kill_chain

    sample_kill_chain_config["techniques"]["T2"]["phase"] = "Nowhere"
    parsed = json.loads(await validate_kill_chain(sample_kill_chain_config))
    assert parsed.get("valid") is False or "error" in parsed


@pytest.mark.asyncio
async def test_get_kill_chain_stats(sample_kill_chain_config):
    from usecvislib_mcp.tools.kill_chain import get_kill_chain_stats

    parsed = json.loads(await get_kill_chain_stats(sample_kill_chain_config))
    assert parsed["total_techniques"] == 3
    assert parsed["detected_techniques"] == 2


@pytest.mark.asyncio
async def test_analyze_kill_chain_coverage(sample_kill_chain_config):
    from usecvislib_mcp.tools.kill_chain import analyze_kill_chain_coverage

    parsed = json.loads(await analyze_kill_chain_coverage(sample_kill_chain_config))
    assert parsed["undetected"] == ["T2"]
    assert set(parsed["unmitigated"]) == {"T1", "T2"}
    assert parsed["critical_gaps"] == []


@skip_no_graphviz
@pytest.mark.asyncio
async def test_atlas_framework_and_inferred_technique():
    """framework = 'atlas' lays techniques on the ATLAS tactics; inferred ones are counted."""
    from usecvislib_mcp.tools.kill_chain import generate_kill_chain, get_kill_chain_stats

    config = {
        "killchain": {"name": "Agent prompt injection", "framework": "atlas"},
        "techniques": {
            "AML.T0051": {
                "name": "LLM Prompt Injection",
                "phase": "AML.TA0005",
                "severity": "critical",
            },
            "AML.T0054": {
                "name": "LLM Jailbreak",
                "phase": "Privilege Escalation",
                "inferred": True,
            },
        },
    }
    parsed = json.loads(await generate_kill_chain(config, format="svg", render_engine="svg"))
    assert "error" not in parsed, parsed
    svg = Path(parsed["output_path"]).read_text(encoding="utf-8")
    assert "usv-node--inferred" in svg
    stats = json.loads(await get_kill_chain_stats(config))
    assert stats["framework"] == "atlas"
    assert stats["inferred_techniques"] == 1
