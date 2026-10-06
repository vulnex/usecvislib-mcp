#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_detection.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Config detection, Mermaid conversion, reports and diffs across all module types."""

import json
import os

import pytest

FIXTURES = {
    "attack_tree": "sample_attack_tree_config",
    "attack_graph": "sample_attack_graph_config",
    "threat_model": "sample_threat_model_config",
    "privilege_gradient": "sample_privilege_gradient_config",
    "component_diagram": "sample_component_diagram_config",
    "dependency_graph": "sample_dependency_graph_config",
    "cloud_diagram": "sample_cloud_diagram_config",
    "custom_diagram": "sample_custom_diagram_config",
    "kill_chain": "sample_kill_chain_config",
    "incident_timeline": "sample_timeline_config",
    "vuln_tree": "sample_vuln_tree_config",
    "maestro": "sample_maestro_config",
}

# File-based modules the library can report on and diff
FILE_MODULES = [t for t in FIXTURES if t not in ("cloud_diagram", "custom_diagram")]


@pytest.mark.asyncio
@pytest.mark.parametrize("viz_type,fixture", FIXTURES.items())
async def test_detect_config_type(request, viz_type, fixture):
    """Every module's config is detected as its own type, with high confidence."""
    from usecvislib_mcp.tools.utilities import detect_config_type

    parsed = json.loads(await detect_config_type(request.getfixturevalue(fixture)))
    assert parsed == {"type": viz_type, "confidence": "high"}


@pytest.mark.asyncio
async def test_detect_config_type_unknown():
    from usecvislib_mcp.tools.utilities import detect_config_type

    parsed = json.loads(await detect_config_type({"hello": "world"}))
    assert parsed["type"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "directory,viz_type",
    [
        ("attack-trees", "attack_tree"),
        ("attack-graphs", "attack_graph"),
        ("threat-models", "threat_model"),
        ("privilege-gradient", "privilege_gradient"),
        ("kill-chains", "kill_chain"),
        ("timelines", "incident_timeline"),
        ("vuln-trees", "vuln_tree"),
        ("maestro", "maestro"),
    ],
)
async def test_detect_config_type_on_bundled_templates(directory, viz_type):
    """The library's own templates are detected correctly."""
    from usecvislib.utils import parse_content

    from usecvislib_mcp.config import resolve_templates_dir
    from usecvislib_mcp.tools.utilities import detect_config_type

    folder = resolve_templates_dir() / directory
    if not folder.is_dir():
        pytest.skip("templates not available")
    fmts = {".tml": "toml", ".toml": "toml", ".json": "json", ".yaml": "yaml"}
    for path in sorted(folder.iterdir()):
        if path.suffix in fmts:
            config = parse_content(path.read_text(encoding="utf-8"), fmts[path.suffix])
            parsed = json.loads(await detect_config_type(config))
            assert parsed["type"] == viz_type, (path.name, parsed)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "viz_type", ["kill_chain", "incident_timeline", "vuln_tree", "maestro", "component_diagram"]
)
async def test_convert_to_mermaid_newer_modules(request, viz_type):
    from usecvislib_mcp.tools.utilities import convert_to_mermaid

    parsed = json.loads(await convert_to_mermaid(request.getfixturevalue(FIXTURES[viz_type])))
    assert "error" not in parsed, parsed
    assert parsed["viz_type"] == viz_type
    assert parsed["mermaid_source"].strip()


@pytest.mark.asyncio
async def test_convert_to_mermaid_rejects_mismatched_hint(sample_threat_model_config):
    """viz_type used to be passed to the library as the Mermaid diagram type."""
    from usecvislib_mcp.tools.utilities import convert_to_mermaid

    ok = json.loads(await convert_to_mermaid(sample_threat_model_config, viz_type="threat_model"))
    assert ok["mermaid_source"].lstrip().startswith("flowchart")
    bad = json.loads(await convert_to_mermaid(sample_threat_model_config, viz_type="attack_tree"))
    assert bad["error"] == "ValueError"


@pytest.mark.asyncio
@pytest.mark.parametrize("viz_type", FILE_MODULES)
async def test_generate_report_every_file_module(request, viz_type):
    """Reports work for every file-based module and list only files that exist."""
    from usecvislib_mcp.tools.export import generate_report

    parsed = json.loads(
        await generate_report(request.getfixturevalue(FIXTURES[viz_type]), viz_type)
    )
    assert "error" not in parsed, parsed
    assert {"json", "md"} <= set(parsed["files"])
    for path in parsed["files"].values():
        assert os.path.getsize(path) > 0, path


@pytest.mark.asyncio
@pytest.mark.parametrize("viz_type", FILE_MODULES)
async def test_compare_visualizations_every_file_module(request, viz_type):
    from usecvislib.batch import BatchProcessor

    from usecvislib_mcp.tools.analysis import compare_visualizations

    if viz_type not in BatchProcessor._get_modules():
        pytest.skip(f"installed usecvislib cannot diff {viz_type}")
    import copy

    config = request.getfixturevalue(FIXTURES[viz_type])
    same = json.loads(await compare_visualizations(config, config, viz_type))
    assert "error" not in same, same
    assert same["has_changes"] is False

    changed = copy.deepcopy(config)
    changed["mcp_test_marker"] = {"note": "added"}
    diff = json.loads(await compare_visualizations(config, changed, viz_type))
    assert diff["has_changes"] is True
    assert any("mcp_test_marker" in c["path"] for c in diff["changes"])
