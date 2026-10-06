#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_vuln_tree.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for vulnerability dependency tree tools."""

import json
from pathlib import Path

import pytest

from tests.conftest import skip_no_graphviz, skip_no_vuln_tree

pytestmark = skip_no_vuln_tree


@skip_no_graphviz
@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["tree", "vulnerable_only", "critical_path"])
@pytest.mark.parametrize("render_engine", ["graphviz", "svg"])
async def test_generate_vuln_tree(sample_vuln_tree_config, mode, render_engine):
    from usecvislib_mcp.tools.vuln_tree import generate_vuln_tree

    parsed = json.loads(
        await generate_vuln_tree(
            sample_vuln_tree_config, format="svg", mode=mode, render_engine=render_engine
        )
    )
    assert "error" not in parsed, parsed
    assert Path(parsed["output_path"]).stat().st_size > 0


@skip_no_graphviz
@pytest.mark.asyncio
async def test_vulnerable_only_prunes_clean_package(sample_vuln_tree_config):
    from usecvislib_mcp.tools.vuln_tree import generate_vuln_tree

    parsed = json.loads(
        await generate_vuln_tree(sample_vuln_tree_config, format="dot", mode="vulnerable_only")
    )
    dot = Path(parsed["output_path"]).read_text(encoding="utf-8")
    assert "core" in dot
    assert '"clean"' not in dot and "clean [" not in dot


@pytest.mark.asyncio
async def test_generate_vuln_tree_rejects_bad_mode(sample_vuln_tree_config):
    from usecvislib_mcp.tools.vuln_tree import generate_vuln_tree

    parsed = json.loads(await generate_vuln_tree(sample_vuln_tree_config, mode="forest"))
    assert parsed["error"] == "ValueError"


@pytest.mark.asyncio
async def test_validate_vuln_tree(sample_vuln_tree_config):
    from usecvislib_mcp.tools.vuln_tree import validate_vuln_tree

    parsed = json.loads(await validate_vuln_tree(sample_vuln_tree_config))
    assert parsed["valid"] is True, parsed


@pytest.mark.asyncio
async def test_get_vuln_tree_stats(sample_vuln_tree_config):
    from usecvislib_mcp.tools.vuln_tree import get_vuln_tree_stats

    parsed = json.loads(await get_vuln_tree_stats(sample_vuln_tree_config))
    assert parsed["vulnerable_dependencies"] == 1
    assert parsed["exploited_vulnerabilities"] == 1
    assert parsed["max_cvss"] == 10.0
    assert "app" in parsed["impacted_roots"]
