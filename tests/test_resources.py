"""Tests for MCP resources."""

import json


def test_list_template_categories():
    """Template categories resource returns valid JSON."""
    from usecvislib_mcp.resources.templates import list_template_categories

    result = json.loads(list_template_categories())
    assert "categories" in result
    assert isinstance(result["categories"], list)
    assert len(result["categories"]) > 0

    # Each category has name and template_count
    for cat in result["categories"]:
        assert "name" in cat
        assert "template_count" in cat


def test_list_templates_in_category():
    """Template listing returns templates for a known category."""
    from usecvislib_mcp.resources.templates import list_templates

    result = json.loads(list_templates("attack-trees"))
    assert result["category"] == "attack-trees"
    assert "templates" in result
    assert len(result["templates"]) > 0


def test_get_template_content():
    """Getting a specific template returns its content."""
    from usecvislib_mcp.resources.templates import get_template

    result = json.loads(get_template("attack-trees", "web_application_attack"))
    assert result["category"] == "attack-trees"
    assert result["name"] == "web_application_attack"
    assert "content" in result
    assert len(result["content"]) > 0


def test_get_nonexistent_template():
    """Getting a missing template returns error."""
    from usecvislib_mcp.resources.templates import get_template

    result = json.loads(get_template("attack-trees", "nonexistent"))
    assert "error" in result


def test_list_all_styles():
    """Style listing returns all visualization types."""
    from usecvislib_mcp.resources.styles import list_all_styles

    result = json.loads(list_all_styles())
    assert isinstance(result, dict)
    assert len(result) > 0
    # Should have attack-trees at minimum
    assert "attack-trees" in result
    assert len(result["attack-trees"]) > 0


def test_list_styles_for_type():
    """Style listing for a specific type returns style IDs."""
    from usecvislib_mcp.resources.styles import list_styles_for_type

    result = json.loads(list_styles_for_type("attack-trees"))
    assert result["visualization_type"] == "attack-trees"
    assert "styles" in result
    assert "at_default" in result["styles"]


def test_list_styles_unknown_type():
    """Unknown viz type returns error with available types."""
    from usecvislib_mcp.resources.styles import list_styles_for_type

    result = json.loads(list_styles_for_type("nonexistent"))
    assert "error" in result
    assert "available_types" in result


def test_attack_tree_schema():
    """Attack tree schema resource returns valid JSON."""
    from usecvislib_mcp.resources.schemas import get_attack_tree_schema

    result = json.loads(get_attack_tree_schema())
    assert "description" in result
    assert "sections" in result
    assert "tree" in result["sections"]
    assert "nodes" in result["sections"]
    assert "edges" in result["sections"]


def test_attack_graph_schema():
    """Attack graph schema resource returns valid JSON."""
    from usecvislib_mcp.resources.schemas import get_attack_graph_schema

    result = json.loads(get_attack_graph_schema())
    assert "description" in result
    assert "sections" in result
    assert "hosts" in result["sections"]
    assert "vulnerabilities" in result["sections"]


def test_threat_model_schema():
    """Threat model schema resource returns valid JSON."""
    from usecvislib_mcp.resources.schemas import get_threat_model_schema

    result = json.loads(get_threat_model_schema())
    assert "description" in result
    assert "sections" in result
    assert "processes" in result["sections"]
    assert "dataflows" in result["sections"]


def test_mermaid_schema():
    """Mermaid schema resource returns valid JSON."""
    from usecvislib_mcp.resources.schemas import get_mermaid_schema

    result = json.loads(get_mermaid_schema())
    assert "parameters" in result
    assert "source" in result["parameters"]
    assert "supported_diagram_types" in result
