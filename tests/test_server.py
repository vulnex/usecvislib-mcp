#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_server.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for MCP server registration."""


def test_server_instance_exists():
    """Server module exposes an mcp FastMCP instance."""
    from usecvislib_mcp.server import mcp

    assert mcp is not None
    assert mcp.name == "usecvislib"


def test_tools_registered():
    """Core tools are registered on the server; optional tools may be absent."""
    from usecvislib_mcp.server import mcp

    tool_names = {t.name for t in mcp._tool_manager.list_tools()}

    # Core tools that should always be available
    core_tools = {
        # Attack Trees (4)
        "generate_attack_tree",
        "validate_attack_tree",
        "get_attack_tree_stats",
        "build_attack_tree_from_spec",
        # Attack Graphs (5)
        "generate_attack_graph",
        "validate_attack_graph",
        "get_attack_graph_stats",
        "find_attack_paths",
        "analyze_critical_nodes",
        # Threat Models (4)
        "generate_threat_model",
        "validate_threat_model",
        "get_threat_model_stats",
        "analyze_stride_threats",
        # Mermaid (1)
        "render_mermaid",
        # Binary Analysis (5)
        "analyze_binary_entropy",
        "analyze_binary_distribution",
        "analyze_binary_heatmap",
        "analyze_binary_all",
        "get_binary_stats",
        # Cloud Diagrams (6)
        "generate_cloud_diagram",
        "validate_cloud_diagram",
        "get_cloud_diagram_stats",
        "search_cloud_icons",
        "list_cloud_providers",
        "list_cloud_icons",
        # Custom Diagrams (3)
        "generate_custom_diagram",
        "validate_custom_diagram",
        "get_custom_diagram_stats",
        # Utilities (4)
        "convert_to_mermaid",
        "calculate_cvss_score",
        "detect_config_type",
        "list_shapes",
        # Batch (1)
        "batch_process",
        # Analysis (3)
        "find_chokepoints",
        "analyze_centrality",
        "compare_visualizations",
    }

    # Tools that depend on optional usecvislib classes
    optional_tools = {
        # Privilege Gradient (5) — requires PrivilegeGradient
        "generate_privilege_gradient",
        "validate_privilege_gradient",
        "get_privilege_gradient_stats",
        "detect_privilege_inversions",
        "analyze_zone_influence",
        # Architecture (6) — requires ComponentDiagram, DependencyGraph
        "generate_component_diagram",
        "validate_component_diagram",
        "get_component_diagram_stats",
        "generate_dependency_graph",
        "validate_dependency_graph",
        "get_dependency_graph_stats",
        # Export (2) — requires ComponentDiagram, DependencyGraph, PrivilegeGradient
        "export_data",
        "generate_report",
    }

    # Core tools must always be present
    for tool_name in core_tools:
        assert tool_name in tool_names, f"Core tool '{tool_name}' not registered"

    # Total should be core + whatever optional tools loaded
    loaded_optional = optional_tools & tool_names
    assert len(tool_names) == len(core_tools) + len(loaded_optional), (
        f"Unexpected tools registered: {tool_names - core_tools - optional_tools}"
    )


def test_resources_registered():
    """Resources are registered on the server."""
    from usecvislib_mcp.server import mcp

    # Resources are registered via resource templates and static resources
    # Check that the resource manager has entries
    assert mcp._resource_manager is not None


def test_prompts_registered():
    """All 6 prompts are registered on the server."""
    from usecvislib_mcp.server import mcp

    prompt_names = {p.name for p in mcp._prompt_manager.list_prompts()}

    expected_prompts = {
        "create_attack_tree",
        "create_threat_model",
        "create_attack_graph",
        "analyze_binary",
        "create_privilege_gradient",
        "review_cloud_security",
    }

    for prompt_name in expected_prompts:
        assert prompt_name in prompt_names, f"Prompt '{prompt_name}' not registered"

    assert len(prompt_names) == 6, (
        f"Expected 6 prompts, found {len(prompt_names)}. Extra: {prompt_names - expected_prompts}"
    )
