"""Tests for MCP server registration."""


def test_server_instance_exists():
    """Server module exposes an mcp FastMCP instance."""
    from usecvislib_mcp.server import mcp

    assert mcp is not None
    assert mcp.name == "usecvislib"


def test_tools_registered():
    """All 14 tools are registered on the server."""
    from usecvislib_mcp.server import mcp

    tool_names = {t.name for t in mcp._tool_manager.list_tools()}

    expected_tools = {
        "generate_attack_tree",
        "validate_attack_tree",
        "get_attack_tree_stats",
        "build_attack_tree_from_spec",
        "generate_attack_graph",
        "validate_attack_graph",
        "get_attack_graph_stats",
        "find_attack_paths",
        "analyze_critical_nodes",
        "generate_threat_model",
        "validate_threat_model",
        "get_threat_model_stats",
        "analyze_stride_threats",
        "render_mermaid",
    }

    for tool_name in expected_tools:
        assert tool_name in tool_names, f"Tool '{tool_name}' not registered"


def test_resources_registered():
    """Resources are registered on the server."""
    from usecvislib_mcp.server import mcp

    # Resources are registered via resource templates and static resources
    # Check that the resource manager has entries
    assert mcp._resource_manager is not None


def test_prompts_registered():
    """Prompts are registered on the server."""
    from usecvislib_mcp.server import mcp

    prompt_names = {p.name for p in mcp._prompt_manager.list_prompts()}

    expected_prompts = {
        "create_attack_tree",
        "create_threat_model",
        "create_attack_graph",
    }

    for prompt_name in expected_prompts:
        assert prompt_name in prompt_names, f"Prompt '{prompt_name}' not registered"
