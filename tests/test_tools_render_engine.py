#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_render_engine.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the render_engine and shine options on the existing generate tools."""

import json
from pathlib import Path

import pytest

from tests.conftest import skip_no_component_diagram, skip_no_dependency_graph, skip_no_graphviz


def _svg(result: str) -> str:
    parsed = json.loads(result)
    assert "error" not in parsed, parsed
    return Path(parsed["output_path"]).read_text(encoding="utf-8")


@skip_no_graphviz
@pytest.mark.asyncio
async def test_attack_tree_svg_engine_default_style(sample_attack_tree_config):
    """The tool's Graphviz default style (at_default) maps to the SVG engine's default."""
    from usecvislib_mcp.tools.attack_trees import generate_attack_tree

    svg = _svg(
        await generate_attack_tree(sample_attack_tree_config, format="svg", render_engine="svg")
    )
    assert "usv-node" in svg


@skip_no_graphviz
@pytest.mark.asyncio
async def test_attack_graph_svg_engine(sample_attack_graph_config):
    from usecvislib_mcp.tools.attack_graphs import generate_attack_graph

    svg = _svg(
        await generate_attack_graph(sample_attack_graph_config, format="svg", render_engine="svg")
    )
    assert "usv-node" in svg


@skip_no_graphviz
@pytest.mark.asyncio
async def test_threat_model_svg_engine(sample_threat_model_config):
    from usecvislib_mcp.tools.threat_models import generate_threat_model

    svg = _svg(
        await generate_threat_model(sample_threat_model_config, format="svg", render_engine="svg")
    )
    assert "usv-node" in svg


@skip_no_component_diagram
@skip_no_graphviz
@pytest.mark.asyncio
async def test_component_diagram_svg_engine(sample_component_diagram_config):
    from usecvislib_mcp.tools.architecture import generate_component_diagram

    svg = _svg(
        await generate_component_diagram(
            sample_component_diagram_config, format="svg", render_engine="svg"
        )
    )
    assert "usv-node" in svg


@skip_no_dependency_graph
@skip_no_graphviz
@pytest.mark.asyncio
async def test_dependency_graph_svg_engine(sample_dependency_graph_config):
    from usecvislib_mcp.tools.architecture import generate_dependency_graph

    svg = _svg(
        await generate_dependency_graph(
            sample_dependency_graph_config, format="svg", render_engine="svg"
        )
    )
    assert "usv-node" in svg


@skip_no_graphviz
@pytest.mark.asyncio
async def test_attack_tree_shine(sample_attack_tree_config):
    from usecvislib_mcp.tools.attack_trees import generate_attack_tree

    svg = _svg(await generate_attack_tree(sample_attack_tree_config, format="svg", shine=True))
    assert 'data-usv-shine="1"' in svg


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"format": "png", "shine": True},
        {"format": "svg", "shine": True, "render_engine": "svg"},
        {"format": "dot", "render_engine": "svg"},
        {"render_engine": "canvas"},
    ],
)
async def test_invalid_engine_options_rejected(sample_attack_tree_config, kwargs):
    from usecvislib_mcp.tools.attack_trees import generate_attack_tree

    parsed = json.loads(await generate_attack_tree(sample_attack_tree_config, **kwargs))
    assert parsed["error"] == "ValueError"


@skip_no_component_diagram
@skip_no_graphviz
@pytest.mark.asyncio
async def test_component_diagram_default_style_exists(sample_component_diagram_config):
    """The default style must be a real preset (it was comp_default, which does not exist)."""
    import inspect

    from usecvislib import ComponentDiagram

    from usecvislib_mcp.tools.architecture import generate_component_diagram

    default = inspect.signature(generate_component_diagram).parameters["style"].default
    assert default == ComponentDiagram.DEFAULT_STYLE_ID
