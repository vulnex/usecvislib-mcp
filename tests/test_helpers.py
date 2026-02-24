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
import os
from pathlib import Path

import pytest

from usecvislib_mcp.config import get_temp_dir
from usecvislib_mcp.helpers import format_error, temp_config_file


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


def test_temp_config_file_rejects_oversized_config():
    """temp_config_file raises on configs exceeding max size."""
    os.environ["USECVISLIB_MCP_MAX_CONFIG_SIZE"] = "100"
    config = {"data": "x" * 200}

    with pytest.raises(ValueError, match="exceeds maximum"):
        with temp_config_file(config):
            pass

    os.environ["USECVISLIB_MCP_MAX_CONFIG_SIZE"] = "10485760"


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
