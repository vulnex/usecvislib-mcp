#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_config.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for config module."""

import os

import pytest

from usecvislib_mcp.config import (
    configure_logging,
    ensure_directories,
    get_api_key,
    get_default_format,
    get_host,
    get_max_config_size,
    get_output_dir,
    get_output_mode,
    get_port,
    get_temp_dir,
    get_transport,
    resolve_models_dir,
    resolve_templates_dir,
)


def test_get_env_defaults():
    """Environment variables use defaults when unset."""
    os.environ.pop("USECVISLIB_MCP_TRANSPORT", None)
    assert get_transport() == "stdio"


def test_get_env_override():
    """Environment variables can be overridden."""
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "sse"
    assert get_transport() == "sse"
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "stdio"


def test_output_mode_defaults_to_file_for_stdio():
    """Output mode defaults to 'file' for stdio transport."""
    os.environ.pop("USECVISLIB_MCP_OUTPUT_MODE", None)
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "stdio"
    assert get_output_mode() == "file"


def test_output_mode_defaults_to_base64_for_sse():
    """Output mode defaults to 'base64' for sse transport."""
    os.environ.pop("USECVISLIB_MCP_OUTPUT_MODE", None)
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "sse"
    assert get_output_mode() == "base64"
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "stdio"


def test_output_mode_explicit_override():
    """Explicit output mode overrides transport-based default."""
    os.environ["USECVISLIB_MCP_OUTPUT_MODE"] = "base64"
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "stdio"
    assert get_output_mode() == "base64"


def test_get_max_config_size():
    """Max config size is returned as int."""
    assert get_max_config_size() == 10485760


def test_get_default_format():
    """Default format returns 'png'."""
    os.environ.pop("USECVISLIB_MCP_DEFAULT_FORMAT", None)
    assert get_default_format() == "png"


def test_get_output_dir(tmp_path):
    """Output dir comes from env var."""
    assert get_output_dir().is_dir()


def test_get_temp_dir(tmp_path):
    """Temp dir comes from env var."""
    assert get_temp_dir().is_dir()


def test_configure_logging():
    """Logging configures to stderr."""
    logger = configure_logging()
    assert logger.name == "usecvislib_mcp"
    assert len(logger.handlers) >= 1


def test_resolve_templates_dir():
    """Templates dir resolves to an existing directory when available."""
    templates = resolve_templates_dir()
    # Templates may not be available when usecvislib is installed as a wheel
    # (they live in the usecvislib source repo, not inside the package)
    if not templates.is_dir():
        pytest.skip("Templates directory not available in this environment")


def test_resolve_models_dir():
    """Models dir resolves to an existing directory."""
    models = resolve_models_dir()
    assert models.is_dir()


def test_get_host_default():
    """Host defaults to 127.0.0.1."""
    os.environ.pop("USECVISLIB_MCP_HOST", None)
    assert get_host() == "127.0.0.1"


def test_get_host_override():
    """Host can be overridden."""
    os.environ["USECVISLIB_MCP_HOST"] = "0.0.0.0"
    assert get_host() == "0.0.0.0"
    os.environ.pop("USECVISLIB_MCP_HOST", None)


def test_get_port_default():
    """Port defaults to 8000."""
    os.environ.pop("USECVISLIB_MCP_PORT", None)
    assert get_port() == 8000


def test_get_port_override():
    """Port can be overridden."""
    os.environ["USECVISLIB_MCP_PORT"] = "9000"
    assert get_port() == 9000
    os.environ.pop("USECVISLIB_MCP_PORT", None)


def test_get_api_key_default():
    """API key defaults to empty string."""
    os.environ.pop("USECVISLIB_MCP_API_KEY", None)
    assert get_api_key() == ""


def test_get_api_key_override():
    """API key can be set."""
    os.environ["USECVISLIB_MCP_API_KEY"] = "my-secret"
    assert get_api_key() == "my-secret"
    os.environ.pop("USECVISLIB_MCP_API_KEY", None)


def test_output_mode_defaults_to_base64_for_streamable_http():
    """Output mode defaults to 'base64' for streamable-http transport."""
    os.environ.pop("USECVISLIB_MCP_OUTPUT_MODE", None)
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "streamable-http"
    assert get_output_mode() == "base64"
    os.environ["USECVISLIB_MCP_TRANSPORT"] = "stdio"


def test_ensure_directories(tmp_path):
    """ensure_directories creates output and temp dirs."""
    os.environ["USECVISLIB_MCP_OUTPUT_DIR"] = str(tmp_path / "new_output")
    os.environ["USECVISLIB_MCP_TEMP_DIR"] = str(tmp_path / "new_temp")
    ensure_directories()
    assert (tmp_path / "new_output").is_dir()
    assert (tmp_path / "new_temp").is_dir()
