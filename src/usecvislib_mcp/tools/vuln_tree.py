#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/vuln_tree.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for vulnerability dependency trees (software supply chain / SCA)."""

import json

from usecvislib import VulnDependencyTree
from usecvislib.vulntree import SUPPORTED_MODES

from ..helpers import build_and_analyze, build_visualization, format_error, log_tool_call
from ..server import mcp


@mcp.tool()
@log_tool_call
async def generate_vuln_tree(
    config: dict,
    format: str = "png",
    style: str = "vt_default",
    mode: str = "tree",
    render_engine: str = "graphviz",
):
    """Generate a vulnerability dependency tree from a configuration dictionary.

    Draws the package dependency tree with CVEs attached: node color is the
    worst CVE severity, direct dependencies get a bolder border, and edges
    into packages with an exploited CVE are highlighted. The config should
    contain a 'vulntree' section (name, optional root_packages) and
    'dependencies' keyed by package ID (name, version, direct, dependencies
    list, and a 'vulnerabilities' list with id, severity, cvss,
    fixed_version, exploited, cwe).

    Args:
        config: Vulnerability tree configuration dict.
        format: Output format — png, pdf, svg, or dot (dot is Graphviz only).
        style: Style preset ID (vt_default, vt_dark, vt_security, vt_corporate,
               vt_minimal; sv_default, sv_dark, sv_security, sv_corporate,
               sv_minimal with the SVG engine).
        mode: tree (default, every reachable package), vulnerable_only (paths
              to any CVE), or critical_path (paths to high/critical CVEs).
        render_engine: graphviz (default) or svg (the stdlib SVG engine: interactive,
               self-contained SVG; png/pdf via cairosvg; sv_* style presets).
    """
    try:
        if mode not in SUPPORTED_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Allowed: {', '.join(SUPPORTED_MODES)}")
        return await build_visualization(
            VulnDependencyTree,
            config,
            "vuln_tree",
            fmt=format,
            styleid=style,
            render_engine=render_engine,
            mode=mode,
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def validate_vuln_tree(config: dict) -> str:
    """Validate a vulnerability dependency tree configuration and return any errors.

    Args:
        config: Vulnerability tree configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(VulnDependencyTree, config, "validate")
        errors = json.loads(result)
        return json.dumps({"valid": len(errors) == 0, "errors": errors}, indent=2, default=str)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_vuln_tree_stats(config: dict) -> str:
    """Get vulnerability tree statistics — direct/transitive and vulnerable
    package counts, CVE severity distribution, exploited CVEs, max CVSS, root
    packages exposed through transitive CVEs (impact propagation) and
    remediation hints (fixed versions).

    Args:
        config: Vulnerability tree configuration to analyze.
    """
    try:
        return await build_and_analyze(VulnDependencyTree, config, "get_stats")
    except Exception as e:
        return format_error(e)
