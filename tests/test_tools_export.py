"""Tests for export and report generation tools."""

import json

import pytest

from tests.conftest import skip_no_graphviz


@pytest.mark.asyncio
async def test_export_data_json():
    """export_data returns JSON formatted content."""
    from usecvislib_mcp.tools.export import export_data

    data = {"name": "test", "score": 9.8, "severity": "Critical"}
    result = await export_data(data, format="json")
    parsed = json.loads(result)
    assert parsed["format"] == "json"
    assert "content" in parsed


@pytest.mark.asyncio
async def test_export_data_yaml():
    """export_data returns YAML formatted content."""
    from usecvislib_mcp.tools.export import export_data

    data = {"name": "test", "value": 42}
    result = await export_data(data, format="yaml")
    parsed = json.loads(result)
    assert parsed["format"] == "yaml"
    assert "content" in parsed


@pytest.mark.asyncio
async def test_export_data_csv():
    """export_data writes CSV to file."""
    from usecvislib_mcp.tools.export import export_data

    data = [
        {"name": "vuln1", "score": 9.8},
        {"name": "vuln2", "score": 7.5},
    ]
    result = await export_data(data, format="csv")
    parsed = json.loads(result)
    assert parsed["format"] == "csv"
    assert "output_path" in parsed
    assert parsed["rows_written"] == 2


@pytest.mark.asyncio
async def test_export_data_markdown():
    """export_data returns markdown table."""
    from usecvislib_mcp.tools.export import export_data

    data = [
        {"host": "web", "ip": "10.0.1.10"},
        {"host": "db", "ip": "10.0.2.20"},
    ]
    result = await export_data(data, format="md")
    parsed = json.loads(result)
    assert parsed["format"] == "markdown"
    assert "content" in parsed
    assert "|" in parsed["content"]


@pytest.mark.asyncio
async def test_export_data_unsupported_format():
    """export_data returns error for unsupported format."""
    from usecvislib_mcp.tools.export import export_data

    result = await export_data({"a": 1}, format="xml")
    parsed = json.loads(result)
    assert "error" in parsed


@skip_no_graphviz
@pytest.mark.asyncio
async def test_generate_report_attack_graph(sample_attack_graph_config):
    """generate_report produces report files for attack graph."""
    from usecvislib_mcp.tools.export import generate_report

    result = await generate_report(
        config=sample_attack_graph_config,
        viz_type="attack_graph",
        formats=["json"],
    )
    parsed = json.loads(result)
    if "error" not in parsed:
        assert "report_dir" in parsed
        assert "files" in parsed


@pytest.mark.asyncio
async def test_generate_report_invalid_viz_type():
    """generate_report returns error for unknown viz_type."""
    from usecvislib_mcp.tools.export import generate_report

    result = await generate_report(
        config={"dummy": "config"},
        viz_type="nonexistent",
    )
    parsed = json.loads(result)
    assert "error" in parsed
    assert "supported" in parsed
