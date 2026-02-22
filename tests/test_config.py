"""Tests for config module."""

import os

from usecvislib_mcp.config import (
    configure_logging,
    ensure_directories,
    get_default_format,
    get_env,
    get_log_level,
    get_max_config_size,
    get_output_dir,
    get_output_mode,
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
    """Templates dir resolves to an existing directory."""
    templates = resolve_templates_dir()
    assert templates.is_dir()


def test_resolve_models_dir():
    """Models dir resolves to an existing directory."""
    models = resolve_models_dir()
    assert models.is_dir()


def test_ensure_directories(tmp_path):
    """ensure_directories creates output and temp dirs."""
    os.environ["USECVISLIB_MCP_OUTPUT_DIR"] = str(tmp_path / "new_output")
    os.environ["USECVISLIB_MCP_TEMP_DIR"] = str(tmp_path / "new_temp")
    ensure_directories()
    assert (tmp_path / "new_output").is_dir()
    assert (tmp_path / "new_temp").is_dir()
