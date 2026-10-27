#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_grouping_drift.py
# Author: Simon Roses Femerling
# Created: 2026-10-27
# Last Modified: 2026-10-27
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for grouping / collapse / keep, the privilege-gradient SVG engine,
the drift picture (render_drift) and batch render_engine."""

import copy
import json
import os
from pathlib import Path

import pytest

from tests.conftest import skip_no_graphviz, skip_no_privilege_gradient


def _ok(result: str) -> dict:
    parsed = json.loads(result)
    assert "error" not in parsed, parsed
    return parsed


def _svg(result: str) -> str:
    return Path(_ok(result)["output_path"]).read_text(encoding="utf-8")


@pytest.fixture
def grouped_gradient_config(sample_privilege_gradient_config):
    """Three web components in the DMZ share a role; the CDN controls one of them."""
    config = copy.deepcopy(sample_privilege_gradient_config)
    config["components"].update(
        {
            "cdn": {"label": "CDN", "zone": "external", "role": "edge"},
            "web_app": {"label": "Web App", "zone": "dmz", "role": "web"},
            "web_2": {"label": "Web 2", "zone": "dmz", "role": "web"},
            "web_3": {"label": "Web 3", "zone": "dmz", "role": "web"},
            "api": {"label": "API Server", "zone": "internal", "role": "core"},
        }
    )
    config["influences"] = [
        {"from": "cdn", "to": "web_app", "type": "control"},
        {"from": "api", "to": "web_2", "type": "data"},  # downward: not an inversion
    ]
    return config


# ── Attack graph grouping ──────────────────────────────────────────


@skip_no_graphviz
@pytest.mark.asyncio
async def test_attack_graph_group_and_collapse(sample_attack_graph_config):
    from usecvislib_mcp.tools.attack_graphs import generate_attack_graph

    svg = _svg(
        await generate_attack_graph(
            sample_attack_graph_config,
            format="svg",
            render_engine="svg",
            group_by="zone",
            collapse="all",
        )
    )
    assert 'data-collapsed="true"' in svg


@skip_no_graphviz
@pytest.mark.asyncio
async def test_attack_graph_group_expanded_clusters(sample_attack_graph_config):
    from usecvislib_mcp.tools.attack_graphs import generate_attack_graph

    svg = _svg(
        await generate_attack_graph(
            sample_attack_graph_config, format="svg", render_engine="svg", group_by="zone"
        )
    )
    assert "usv-cluster" in svg and 'data-collapsed="true"' not in svg


@pytest.mark.asyncio
async def test_attack_graph_stats_groups(sample_attack_graph_config):
    from usecvislib_mcp.tools.attack_graphs import get_attack_graph_stats

    stats = _ok(await get_attack_graph_stats(sample_attack_graph_config, group_by="zone"))
    assert set(stats["groups"]) == {"external", "dmz", "internal"}
    assert "groups" not in _ok(await get_attack_graph_stats(sample_attack_graph_config))


@pytest.mark.asyncio
async def test_attack_graph_max_nodes_range(sample_attack_graph_config):
    from usecvislib_mcp.tools.attack_graphs import generate_attack_graph

    result = json.loads(
        await generate_attack_graph(sample_attack_graph_config, collapse="auto", max_nodes=0)
    )
    assert "max_nodes" in result["message"]


# ── Privilege gradient: SVG engine, grouping, keep ─────────────────


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_privilege_gradient_svg_engine(sample_privilege_gradient_config):
    """The tool's Graphviz default (pg_default) maps to the SVG engine's default."""
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    svg = _svg(
        await generate_privilege_gradient(
            sample_privilege_gradient_config, format="svg", render_engine="svg"
        )
    )
    assert "usv-node" in svg and 'data-trust-level="2"' in svg


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_privilege_gradient_collapse_keep_inversions(grouped_gradient_config):
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    svg = _svg(
        await generate_privilege_gradient(
            grouped_gradient_config,
            format="svg",
            render_engine="svg",
            group_by="role",
            collapse="all",
            keep="inversions",
        )
    )
    assert 'data-collapsed="true"' in svg
    assert "data-kept" in svg  # web_app (target of the CDN inversion) stays drawn


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_privilege_gradient_keep_ids_graphviz(grouped_gradient_config):
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    result = _ok(
        await generate_privilege_gradient(
            grouped_gradient_config,
            format="svg",
            group_by="role",
            collapse="all",
            keep_ids=["web_2"],
        )
    )
    assert result["size_bytes"] > 0


@pytest.mark.xfail(
    strict=True,
    reason="usecvislib SVG painter: KeyError when keep='inversions' keeps an ungrouped "
    "component (svgengine/painters/privilegegradient.py, view.groups[None])",
)
@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_privilege_gradient_keep_ungrouped_endpoint_svg(grouped_gradient_config):
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    del grouped_gradient_config["components"]["cdn"]["role"]
    _svg(
        await generate_privilege_gradient(
            grouped_gradient_config,
            format="svg",
            render_engine="svg",
            group_by="role",
            collapse="all",
            keep="inversions",
        )
    )


@pytest.mark.asyncio
async def test_privilege_gradient_invalid_keep(grouped_gradient_config):
    from usecvislib_mcp.tools.privilege_gradient import generate_privilege_gradient

    result = json.loads(await generate_privilege_gradient(grouped_gradient_config, keep="all"))
    assert "keep" in result["message"]


@skip_no_privilege_gradient
@pytest.mark.asyncio
async def test_privilege_gradient_stats_groups(grouped_gradient_config):
    from usecvislib_mcp.tools.privilege_gradient import get_privilege_gradient_stats

    stats = _ok(await get_privilege_gradient_stats(grouped_gradient_config, group_by="role"))
    assert "dmz/web" in stats["groups"]


# ── Drift picture ──────────────────────────────────────────────────


@skip_no_graphviz
@pytest.mark.asyncio
@pytest.mark.parametrize("engine", ["graphviz", "svg"])
async def test_render_drift_attack_graph(sample_attack_graph_config, engine):
    from usecvislib_mcp.tools.analysis import render_drift

    new = copy.deepcopy(sample_attack_graph_config)
    new["hosts"].append({"id": "backup", "label": "Backup", "ip": "10.0.2.30", "zone": "internal"})
    new["vulnerabilities"][0]["cvss"] = 7.5
    result = _ok(
        await render_drift(sample_attack_graph_config, new, format="svg", render_engine=engine)
    )
    assert result["summary"]["added"] == 1 and result["summary"]["modified"] == 1
    assert result["has_changes"] is True
    assert {c["type"] for c in result["changes"]} == {"added", "modified"}
    assert "inversions" not in result
    assert "old_source" not in result
    assert Path(result["output_path"]).stat().st_size == result["size_bytes"] > 0


@skip_no_privilege_gradient
@skip_no_graphviz
@pytest.mark.asyncio
async def test_render_drift_privilege_gradient_inversions(grouped_gradient_config):
    """A new, a fixed and a changed inversion between two versions."""
    from usecvislib_mcp.tools.analysis import render_drift

    old = copy.deepcopy(grouped_gradient_config)
    old["influences"].append({"from": "web_2", "to": "api", "type": "control"})  # dmz -> internal
    new = copy.deepcopy(grouped_gradient_config)
    new["influences"] = [
        {"from": "cdn", "to": "web_app", "type": "control"},  # unchanged inversion
        {"from": "cdn", "to": "api", "type": "control"},  # new (external -> internal)
    ]
    new["zones"]["dmz"]["trust_level"] = 0  # cdn -> web_app no longer crosses up: fixed
    new["influences"].append({"from": "web_2", "to": "api", "type": "control"})  # gap 1 -> 2

    result = _ok(
        await render_drift(
            old,
            new,
            viz_type="privilege_gradient",
            format="svg",
            render_engine="svg",
            group_by="role",
            collapse="all",
            keep="inversions",
        )
    )
    inversions = result["inversions"]
    pairs = {k: [(i["from"], i["to"]) for i in v] for k, v in inversions.items()}
    assert pairs["new"] == [("cdn", "api")]
    assert pairs["fixed"] == [("cdn", "web_app")]
    assert pairs["changed"] == [("web_2", "api")]
    assert inversions["changed"][0]["old_severity"] == "medium"
    assert inversions["changed"][0]["new_severity"] == "high"
    svg = Path(result["output_path"]).read_text(encoding="utf-8")
    assert 'data-inversion="new"' in svg


@pytest.mark.asyncio
async def test_render_drift_rejects_other_types(sample_attack_tree_config):
    from usecvislib_mcp.tools.analysis import render_drift

    result = json.loads(
        await render_drift(
            sample_attack_tree_config, sample_attack_tree_config, viz_type="attack_tree"
        )
    )
    assert "attack_graph" in result["message"]


@pytest.mark.asyncio
async def test_render_drift_keep_is_gradient_only(sample_attack_graph_config):
    from usecvislib_mcp.tools.analysis import render_drift

    result = json.loads(
        await render_drift(
            sample_attack_graph_config, sample_attack_graph_config, keep="inversions"
        )
    )
    assert "privilege gradients" in result["message"]


@skip_no_graphviz
@pytest.mark.asyncio
async def test_render_drift_base64_mode(sample_attack_graph_config):
    from usecvislib_mcp.tools.analysis import render_drift

    os.environ["USECVISLIB_MCP_OUTPUT_MODE"] = "base64"  # restored by the autouse fixture
    result = _ok(
        await render_drift(sample_attack_graph_config, sample_attack_graph_config, format="png")
    )
    assert result["has_changes"] is False and result["data_base64"]
    assert "output_path" not in result


# ── Batch ──────────────────────────────────────────────────────────


@skip_no_graphviz
@pytest.mark.asyncio
async def test_batch_render_engine_svg(sample_attack_graph_config):
    from usecvislib_mcp.tools.batch import batch_process

    result = _ok(
        await batch_process(
            "attack_graph", [sample_attack_graph_config], format="svg", render_engine="svg"
        )
    )
    assert result["failures"] == {} and len(result["successes"]) == 1
    output = next(iter(result["successes"].values()))["output"]
    assert "usv-node" in Path(output).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_batch_invalid_render_engine(sample_attack_graph_config):
    from usecvislib_mcp.tools.batch import batch_process

    result = json.loads(
        await batch_process("attack_graph", [sample_attack_graph_config], render_engine="vector")
    )
    assert "render_engine" in result["message"]


# ── Schemas and styles ─────────────────────────────────────────────


def test_kill_chain_schema_atlas_and_inferred():
    from usecvislib_mcp.resources.schemas import get_kill_chain_schema

    schema = json.loads(get_kill_chain_schema())["sections"]
    assert "atlas" in schema["killchain"]["fields"]["framework"]["values"]
    assert "inferred" in schema["techniques"]["value_fields"]


def test_attack_graph_schema_grouping_sources_inferred():
    from usecvislib_mcp.resources.schemas import get_attack_graph_schema

    schema = json.loads(get_attack_graph_schema())
    assert {"group_by", "collapse", "max_nodes"} <= set(schema["sections"]["graph"]["fields"])
    assert "inferred" in schema["sections"]["network_edges"]["fields"]
    assert "sources" in schema["common_fields"]["fields"]


def test_privilege_gradient_styles_include_svg_presets():
    from usecvislib_mcp.resources.styles import list_styles_for_type

    styles = json.loads(list_styles_for_type("privilege-gradient"))["styles"]
    assert "pg_default" in styles and "sv_default" in styles
