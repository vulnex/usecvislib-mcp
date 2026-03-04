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


def test_get_env_defaults(monkeypatch):
    """Environment variables use defaults when unset."""
    monkeypatch.delenv("USECVISLIB_MCP_TRANSPORT", raising=False)
    assert get_transport() == "stdio"


def test_get_env_override(monkeypatch):
    """Environment variables can be overridden."""
    monkeypatch.setenv("USECVISLIB_MCP_TRANSPORT", "sse")
    assert get_transport() == "sse"


def test_output_mode_defaults_to_file_for_stdio(monkeypatch):
    """Output mode defaults to 'file' for stdio transport."""
    monkeypatch.delenv("USECVISLIB_MCP_OUTPUT_MODE", raising=False)
    monkeypatch.setenv("USECVISLIB_MCP_TRANSPORT", "stdio")
    assert get_output_mode() == "file"


def test_output_mode_defaults_to_base64_for_sse(monkeypatch):
    """Output mode defaults to 'base64' for sse transport."""
    monkeypatch.delenv("USECVISLIB_MCP_OUTPUT_MODE", raising=False)
    monkeypatch.setenv("USECVISLIB_MCP_TRANSPORT", "sse")
    assert get_output_mode() == "base64"


def test_output_mode_explicit_override(monkeypatch):
    """Explicit output mode overrides transport-based default."""
    monkeypatch.setenv("USECVISLIB_MCP_OUTPUT_MODE", "base64")
    monkeypatch.setenv("USECVISLIB_MCP_TRANSPORT", "stdio")
    assert get_output_mode() == "base64"


def test_get_max_config_size():
    """Max config size is returned as int."""
    assert get_max_config_size() == 10485760


def test_get_default_format(monkeypatch):
    """Default format returns 'png'."""
    monkeypatch.delenv("USECVISLIB_MCP_DEFAULT_FORMAT", raising=False)
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


def test_get_host_default(monkeypatch):
    """Host defaults to 127.0.0.1."""
    monkeypatch.delenv("USECVISLIB_MCP_HOST", raising=False)
    assert get_host() == "127.0.0.1"


def test_get_host_override(monkeypatch):
    """Host can be overridden."""
    monkeypatch.setenv("USECVISLIB_MCP_HOST", "0.0.0.0")
    assert get_host() == "0.0.0.0"


def test_get_port_default(monkeypatch):
    """Port defaults to 8000."""
    monkeypatch.delenv("USECVISLIB_MCP_PORT", raising=False)
    assert get_port() == 8000


def test_get_port_override(monkeypatch):
    """Port can be overridden."""
    monkeypatch.setenv("USECVISLIB_MCP_PORT", "9000")
    assert get_port() == 9000


def test_get_api_key_default(monkeypatch):
    """API key defaults to empty string."""
    monkeypatch.delenv("USECVISLIB_MCP_API_KEY", raising=False)
    assert get_api_key() == ""


def test_get_api_key_override(monkeypatch):
    """API key can be set."""
    monkeypatch.setenv("USECVISLIB_MCP_API_KEY", "my-secret")
    assert get_api_key() == "my-secret"


def test_output_mode_defaults_to_base64_for_streamable_http(monkeypatch):
    """Output mode defaults to 'base64' for streamable-http transport."""
    monkeypatch.delenv("USECVISLIB_MCP_OUTPUT_MODE", raising=False)
    monkeypatch.setenv("USECVISLIB_MCP_TRANSPORT", "streamable-http")
    assert get_output_mode() == "base64"


def test_ensure_directories(tmp_path, monkeypatch):
    """ensure_directories creates output and temp dirs."""
    monkeypatch.setenv("USECVISLIB_MCP_OUTPUT_DIR", str(tmp_path / "new_output"))
    monkeypatch.setenv("USECVISLIB_MCP_TEMP_DIR", str(tmp_path / "new_temp"))
    ensure_directories()
    assert (tmp_path / "new_output").is_dir()
    assert (tmp_path / "new_temp").is_dir()
