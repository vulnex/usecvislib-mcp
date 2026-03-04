#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_helpers.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for helper functions."""

import json
from pathlib import Path

import pytest

from usecvislib_mcp.config import get_temp_dir
from usecvislib_mcp.helpers import (
    ALLOWED_ANALYSIS_METHODS,
    ALLOWED_BUILD_METHODS,
    format_error,
    temp_config_file,
    validate_config_size,
    validate_format,
    validate_int_range,
)


def test_temp_config_file_creates_and_cleans_up():
    """temp_config_file creates a file and removes it after."""
    config = {"test": "data"}
    temp_path = None

    with temp_config_file(config) as path:
        temp_path = path
        assert Path(path).exists()
        content = json.loads(Path(path).read_text())
        assert content == config

    assert not Path(temp_path).exists()


def test_temp_config_file_cleans_up_on_exception():
    """temp_config_file removes file even if exception occurs."""
    config = {"test": "data"}
    temp_path = None

    with pytest.raises(ValueError):
        with temp_config_file(config) as path:
            temp_path = path
            raise ValueError("test error")

    assert not Path(temp_path).exists()


def test_temp_config_file_rejects_oversized_config(monkeypatch):
    """temp_config_file raises on configs exceeding max size."""
    monkeypatch.setenv("USECVISLIB_MCP_MAX_CONFIG_SIZE", "100")
    config = {"data": "x" * 200}

    with pytest.raises(ValueError, match="exceeds maximum"):
        with temp_config_file(config):
            pass


def test_temp_config_file_path_in_temp_dir():
    """temp_config_file writes to the configured temp dir."""
    config = {"test": True}
    temp_dir = get_temp_dir()

    with temp_config_file(config) as path:
        assert str(temp_dir) in path


def test_format_error_basic():
    """format_error handles basic exceptions."""
    err = ValueError("something went wrong")
    result = json.loads(format_error(err))
    assert result["error"] == "ValueError"
    assert result["message"] == "something went wrong"


def test_format_error_with_context():
    """format_error includes context from USecVisLib errors."""
    try:
        from usecvislib import USecVisLibError

        err = USecVisLibError("test error")
        result = json.loads(format_error(err))
        assert result["error"] == "USecVisLibError"
        assert result["message"] == "test error"
    except ImportError:
        pytest.skip("usecvislib not installed")


# ── Validation helpers ──────────────────────────────────────────────


def test_validate_format_valid():
    """validate_format accepts valid formats."""
    validate_format("png")
    validate_format("pdf")
    validate_format("svg")
    validate_format("dot")


def test_validate_format_invalid():
    """validate_format rejects invalid formats."""
    with pytest.raises(ValueError, match="Invalid format"):
        validate_format("exe")


def test_validate_int_range_valid():
    """validate_int_range accepts values within range."""
    assert validate_int_range(5, "test", 1, 10) == 5


def test_validate_int_range_rejects_bool():
    """validate_int_range rejects boolean values."""
    with pytest.raises(ValueError, match="must be an integer"):
        validate_int_range(True, "test")


def test_validate_int_range_rejects_out_of_bounds():
    """validate_int_range rejects values outside range."""
    with pytest.raises(ValueError, match="must be between"):
        validate_int_range(0, "test", 1, 10)
    with pytest.raises(ValueError, match="must be between"):
        validate_int_range(11, "test", 1, 10)


def test_validate_config_size_valid():
    """validate_config_size accepts small configs."""
    validate_config_size({"key": "value"})


def test_validate_config_size_rejects_oversized(monkeypatch):
    """validate_config_size rejects oversized configs."""
    monkeypatch.setenv("USECVISLIB_MCP_MAX_CONFIG_SIZE", "50")
    with pytest.raises(ValueError, match="exceeds maximum"):
        validate_config_size({"data": "x" * 100})


# ── Method whitelist tests ──────────────────────────────────────────


def test_allowed_analysis_methods_rejects_dangerous():
    """ALLOWED_ANALYSIS_METHODS does not contain dangerous methods."""
    for dangerous in ["__init__", "__del__", "exec", "eval", "build", "render"]:
        assert dangerous not in ALLOWED_ANALYSIS_METHODS


def test_allowed_build_methods_rejects_dangerous():
    """ALLOWED_BUILD_METHODS does not contain dangerous methods."""
    for dangerous in ["__init__", "__del__", "exec", "eval", "load", "validate"]:
        assert dangerous not in ALLOWED_BUILD_METHODS


@pytest.mark.asyncio
async def test_build_and_analyze_rejects_disallowed_method():
    """build_and_analyze raises ValueError for methods not in whitelist."""
    from usecvislib_mcp.helpers import build_and_analyze

    with pytest.raises(ValueError, match="not allowed"):
        await build_and_analyze(object, {}, "__init__")


@pytest.mark.asyncio
async def test_build_pattern_b_rejects_disallowed_method():
    """build_pattern_b raises ValueError for methods not in whitelist."""
    from usecvislib_mcp.helpers import build_pattern_b

    with pytest.raises(ValueError, match="not allowed"):
        await build_pattern_b(object, {}, "test", build_method="__init__")


@pytest.mark.asyncio
async def test_analyze_pattern_b_rejects_disallowed_method():
    """analyze_pattern_b raises ValueError for methods not in whitelist."""
    from usecvislib_mcp.helpers import analyze_pattern_b

    with pytest.raises(ValueError, match="not allowed"):
        await analyze_pattern_b(object, {}, "__init__")
