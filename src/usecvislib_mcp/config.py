"""Configuration and environment variable management for usecvislib-mcp."""

import logging
import os
import sys
from pathlib import Path


# Environment variable defaults
DEFAULTS = {
    "USECVISLIB_MCP_LOG_LEVEL": "INFO",
    "USECVISLIB_MCP_TRANSPORT": "stdio",
    "USECVISLIB_MCP_OUTPUT_DIR": "/tmp/usecvislib-mcp-output",
    "USECVISLIB_MCP_TEMP_DIR": "/tmp/usecvislib-mcp-temp",
    "USECVISLIB_MCP_MAX_CONFIG_SIZE": "10485760",
    "USECVISLIB_MCP_DEFAULT_FORMAT": "png",
    "USECVISLIB_MCP_HOST": "127.0.0.1",
    "USECVISLIB_MCP_PORT": "8000",
    "USECVISLIB_MCP_API_KEY": "",
}


def get_env(name: str) -> str:
    """Get environment variable with default fallback."""
    return os.environ.get(name, DEFAULTS.get(name, ""))


def get_log_level() -> str:
    return get_env("USECVISLIB_MCP_LOG_LEVEL")


def get_transport() -> str:
    return get_env("USECVISLIB_MCP_TRANSPORT")


def get_host() -> str:
    return get_env("USECVISLIB_MCP_HOST")


def get_port() -> int:
    return int(get_env("USECVISLIB_MCP_PORT"))


def get_api_key() -> str:
    return get_env("USECVISLIB_MCP_API_KEY")


def get_output_mode() -> str:
    """Get output mode, defaulting based on transport."""
    explicit = os.environ.get("USECVISLIB_MCP_OUTPUT_MODE")
    if explicit:
        return explicit
    return "base64" if get_transport() in ("sse", "streamable-http") else "file"


def get_output_dir() -> Path:
    return Path(get_env("USECVISLIB_MCP_OUTPUT_DIR"))


def get_temp_dir() -> Path:
    return Path(get_env("USECVISLIB_MCP_TEMP_DIR"))


def get_max_config_size() -> int:
    return int(get_env("USECVISLIB_MCP_MAX_CONFIG_SIZE"))


def get_default_format() -> str:
    return get_env("USECVISLIB_MCP_DEFAULT_FORMAT")


def configure_logging() -> logging.Logger:
    """Configure logging to stderr only (stdout is MCP JSON-RPC)."""
    logger = logging.getLogger("usecvislib_mcp")
    logger.setLevel(get_log_level())

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(get_log_level())
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def resolve_templates_dir() -> Path:
    """Auto-detect templates directory from usecvislib package location."""
    try:
        import usecvislib

        pkg_dir = Path(usecvislib.__file__).parent
        # Templates are at the repo root level: usecvislib/templates/
        # Package is at: usecvislib/src/usecvislib/
        repo_root = pkg_dir.parent.parent
        templates_dir = repo_root / "templates"
        if templates_dir.is_dir():
            return templates_dir
    except (ImportError, AttributeError):
        pass

    # Fallback: check common locations
    for candidate in [
        Path("/Users/conde/vulnex/usecvislib/templates"),
        Path.cwd() / "templates",
    ]:
        if candidate.is_dir():
            return candidate

    return Path("templates")


def resolve_models_dir() -> Path:
    """Auto-detect models directory from usecvislib package location."""
    try:
        import usecvislib

        pkg_dir = Path(usecvislib.__file__).parent
        models_dir = pkg_dir / "models"
        if models_dir.is_dir():
            return models_dir
    except (ImportError, AttributeError):
        pass

    return Path("models")


def ensure_directories() -> None:
    """Create output and temp directories if they don't exist."""
    get_output_dir().mkdir(parents=True, exist_ok=True)
    get_temp_dir().mkdir(parents=True, exist_ok=True)
