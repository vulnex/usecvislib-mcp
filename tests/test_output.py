"""Tests for output module."""

import json

from usecvislib_mcp.output import OutputHandler


def test_make_output_path(tmp_path):
    """make_output_path creates unique file paths."""
    handler = OutputHandler(mode="file")
    path1 = handler.make_output_path("test", "png")
    path2 = handler.make_output_path("test", "png")
    assert path1 != path2
    assert path1.endswith(".png")
    assert "test_" in path1


def test_format_result_file_mode(tmp_path):
    """File mode returns JSON with path info."""
    handler = OutputHandler(mode="file")
    # Create a temp file to test with
    test_file = tmp_path / "test.png"
    test_file.write_bytes(b"fake png data")

    result = handler.format_result(str(test_file), "png")
    parsed = json.loads(result)

    assert parsed["output_path"] == str(test_file)
    assert parsed["format"] == "png"
    assert parsed["size_bytes"] == 13


def test_format_result_file_mode_with_metadata(tmp_path):
    """File mode includes metadata when provided."""
    handler = OutputHandler(mode="file")
    test_file = tmp_path / "test.png"
    test_file.write_bytes(b"fake png data")

    result = handler.format_result(
        str(test_file), "png", metadata={"style": "default"}
    )
    parsed = json.loads(result)
    assert parsed["metadata"] == {"style": "default"}


def test_format_result_base64_mode(tmp_path):
    """Base64 mode returns encoded data."""
    handler = OutputHandler(mode="base64")
    test_file = tmp_path / "test.pdf"
    test_file.write_bytes(b"fake pdf data")

    result = handler.format_result(str(test_file), "pdf")
    parsed = json.loads(result)

    assert parsed["format"] == "pdf"
    assert "data_base64" in parsed
    assert parsed["size_bytes"] == 13


def test_format_result_missing_file(tmp_path):
    """Missing file returns error in base64 mode."""
    handler = OutputHandler(mode="base64")
    result = handler.format_result(str(tmp_path / "missing.png"), "png")
    parsed = json.loads(result)
    assert "error" in parsed
