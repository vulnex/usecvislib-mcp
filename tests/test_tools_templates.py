#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_tools_templates.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Every bundled USecVisLib template for the newer modules validates through the MCP tools."""

import json

import pytest

from usecvislib_mcp.config import resolve_templates_dir

TEMPLATES = resolve_templates_dir()

# template directory -> (tool module, validate tool)
MODULES = {
    "kill-chains": ("kill_chain", "validate_kill_chain"),
    "timelines": ("timeline", "validate_incident_timeline"),
    "vuln-trees": ("vuln_tree", "validate_vuln_tree"),
    "maestro": ("maestro", "validate_maestro_threat_model"),
}


def _cases():
    for directory, (module, tool) in MODULES.items():
        if not (TEMPLATES / directory).is_dir():
            continue
        for path in sorted((TEMPLATES / directory).iterdir()):
            if path.suffix in (".toml", ".tml", ".json", ".yaml"):
                yield pytest.param(path, module, tool, id=f"{directory}/{path.name}")


def _load(path):
    from usecvislib.utils import parse_content

    fmt = {".tml": "toml", ".toml": "toml", ".json": "json", ".yaml": "yaml"}[path.suffix]
    return parse_content(path.read_text(encoding="utf-8"), fmt)


@pytest.mark.asyncio
@pytest.mark.parametrize("path,module,tool", list(_cases()))
async def test_bundled_template_validates(path, module, tool):
    import importlib

    validate = getattr(importlib.import_module(f"usecvislib_mcp.tools.{module}"), tool)
    parsed = json.loads(await validate(_load(path)))
    assert parsed.get("valid") is True, parsed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,tool",
    [
        ("component-diagram-example.json", "validate_component_diagram"),
        ("dependency-graph-example.json", "validate_dependency_graph"),
    ],
)
async def test_bundled_architecture_template_validates(name, tool):
    """The documented schemas match the library: its own examples validate."""
    from usecvislib_mcp.tools import architecture

    path = TEMPLATES / "architecture" / name
    if not path.is_file():
        pytest.skip("architecture templates not available")
    parsed = json.loads(await getattr(architecture, tool)(_load(path)))
    assert parsed.get("valid") is True, parsed
