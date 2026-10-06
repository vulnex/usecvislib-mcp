#
# VULNEX -Universal Security Visualization Library-
#
# File: resources/styles.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP resources for browsing USecVisLib style presets."""

import json
import logging
from pathlib import Path

from ..config import resolve_models_dir
from ..server import mcp

logger = logging.getLogger("usecvislib_mcp")

# Map visualization types to their config file names
STYLE_CONFIG_MAP = {
    "attack-trees": "config_attacktrees.tml",
    "attack-graphs": "config_attackgraphs.tml",
    "threat-models": "config_threatmodeling.tml",
    "custom-diagrams": "config_customdiagrams.tml",
    "cloud-diagrams": "config_clouddiagrams.tml",
    "privilege-gradient": "config_privilegegradient.tml",
    "component-diagram": "config_componentdiagram.tml",
    "dependency-graph": "config_dependencygraph.tml",
    "binary-visualization": "config_binvis.tml",
    "kill-chain": "config_killchain.tml",
    "incident-timeline": "config_timeline.tml",
    "vuln-tree": "config_vulntree.tml",
    "maestro": "config_maestro.tml",
}


def _parse_style_ids(config_path: Path) -> list[str]:
    """Parse top-level TOML section keys as style IDs."""
    style_ids = []
    if not config_path.is_file():
        return style_ids

    try:
        import toml

        data = toml.load(str(config_path))
        style_ids = list(data.keys())
    except Exception as exc:
        logger.warning("TOML parsing failed for %s (%s), using fallback parser", config_path, exc)
        # Fallback: parse [section] headers manually
        try:
            content = config_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("[") and not line.startswith("[["):
                    # Extract section name, handling dotted keys
                    section = line.strip("[]").strip()
                    if "." not in section:
                        style_ids.append(section)
        except OSError:
            pass

    return style_ids


def _get_all_styles() -> dict[str, list[str]]:
    """Get all style IDs grouped by visualization type."""
    models_dir = resolve_models_dir()
    result = {}
    for viz_type, config_file in STYLE_CONFIG_MAP.items():
        config_path = models_dir / config_file
        styles = _parse_style_ids(config_path)
        if styles:
            result[viz_type] = styles
    return result


@mcp.resource("usecvislib://styles/list")
def list_all_styles() -> str:
    """List all available style presets grouped by visualization type."""
    styles = _get_all_styles()
    return json.dumps(styles, indent=2)


@mcp.resource("usecvislib://styles/{visualization_type}")
def list_styles_for_type(visualization_type: str) -> str:
    """List style presets available for a specific visualization type."""
    models_dir = resolve_models_dir()
    config_file = STYLE_CONFIG_MAP.get(visualization_type)

    if not config_file:
        return json.dumps(
            {
                "error": f"Unknown visualization type: {visualization_type}",
                "available_types": list(STYLE_CONFIG_MAP.keys()),
            }
        )

    styles = _parse_style_ids(models_dir / config_file)
    return json.dumps({"visualization_type": visualization_type, "styles": styles}, indent=2)
