#
# VULNEX -Universal Security Visualization Library-
#
# File: config.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Configuration and environment variable management for usecvislib-mcp."""

import contextvars
import logging
import os
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

# Context variable for per-request client identification (set by middleware)
current_client_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_client_id", default=""
)

# Build user-scoped default directories to avoid predictable shared paths.
# On Unix, includes UID; on Windows, tempfile.gettempdir() is already per-user.
_base_tmp = Path(tempfile.gettempdir())
try:
    _uid_suffix = f"-{os.getuid()}"
except AttributeError:
    _uid_suffix = ""  # Windows — tempdir is already user-scoped

# Environment variable defaults
DEFAULTS = {
    "USECVISLIB_MCP_LOG_LEVEL": "INFO",
    "USECVISLIB_MCP_TRANSPORT": "stdio",
    "USECVISLIB_MCP_OUTPUT_DIR": str(_base_tmp / f"usecvislib-mcp-output{_uid_suffix}"),
    "USECVISLIB_MCP_TEMP_DIR": str(_base_tmp / f"usecvislib-mcp-temp{_uid_suffix}"),
    "USECVISLIB_MCP_MAX_CONFIG_SIZE": "10485760",
    "USECVISLIB_MCP_DEFAULT_FORMAT": "png",
    "USECVISLIB_MCP_HOST": "127.0.0.1",
    "USECVISLIB_MCP_PORT": "8000",
    "USECVISLIB_MCP_API_KEY": "",
    "USECVISLIB_MCP_OUTPUT_TTL_SECONDS": "3600",
    "USECVISLIB_MCP_ISSUER_URL": "https://localhost",
    "USECVISLIB_MCP_TOOL_TIMEOUT": "300",
}


def get_env(name: str) -> str:
    """Get environment variable with default fallback."""
    return os.environ.get(name, DEFAULTS.get(name, ""))


def _get_int_env(name: str) -> int:
    """Get an environment variable as an integer with clear error on bad values."""
    raw = get_env(name)
    try:
        return int(raw)
    except (ValueError, TypeError):
        raise ValueError(f"Environment variable {name} must be an integer, got '{raw}'") from None


def get_log_level() -> str:
    return get_env("USECVISLIB_MCP_LOG_LEVEL")


def get_transport() -> str:
    return get_env("USECVISLIB_MCP_TRANSPORT")


def get_host() -> str:
    return get_env("USECVISLIB_MCP_HOST")


def get_port() -> int:
    return _get_int_env("USECVISLIB_MCP_PORT")


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
    return _get_int_env("USECVISLIB_MCP_MAX_CONFIG_SIZE")


def get_default_format() -> str:
    return get_env("USECVISLIB_MCP_DEFAULT_FORMAT")


def get_output_ttl_seconds() -> int:
    """Get max age for output files in seconds. 0 = no cleanup."""
    return _get_int_env("USECVISLIB_MCP_OUTPUT_TTL_SECONDS")


def get_issuer_url() -> str:
    """Get OAuth/OIDC issuer URL for HTTP auth settings."""
    return get_env("USECVISLIB_MCP_ISSUER_URL")


def get_tool_timeout() -> int:
    """Get max seconds a tool execution may run before being cancelled. 0 = no timeout."""
    return _get_int_env("USECVISLIB_MCP_TOOL_TIMEOUT")


def configure_logging() -> logging.Logger:
    """Configure logging to stderr only (stdout is MCP JSON-RPC)."""
    logger = logging.getLogger("usecvislib_mcp")
    logger.setLevel(get_log_level())

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(get_log_level())
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
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


def get_allowed_input_dirs() -> list[Path]:
    """Get list of directories from which input files may be read.

    Set via USECVISLIB_MCP_ALLOWED_INPUT_DIRS (comma-separated paths).
    When empty, input path validation is skipped (unrestricted local mode).
    For HTTP deployments, operators SHOULD set this to restrict file access.
    """
    raw = os.environ.get("USECVISLIB_MCP_ALLOWED_INPUT_DIRS", "")
    if not raw.strip():
        return []
    return [Path(d.strip()).resolve() for d in raw.split(",") if d.strip()]


_allowed_input_dirs_warned = False


def warn_if_unrestricted_http() -> None:
    """Log a warning if HTTP transport is active with no input dir restrictions.

    Called once at startup to alert operators that binary analysis tools
    can read any file accessible to the process user.
    """
    global _allowed_input_dirs_warned
    if _allowed_input_dirs_warned:
        return
    _allowed_input_dirs_warned = True

    transport = get_transport()
    if transport in ("sse", "streamable-http") and not get_allowed_input_dirs():
        logger = logging.getLogger("usecvislib_mcp")
        logger.warning(
            "HTTP transport (%s) running WITHOUT input directory restrictions. "
            "Binary analysis tools can read any file the process user can access. "
            "Set USECVISLIB_MCP_ALLOWED_INPUT_DIRS to restrict file access.",
            transport,
        )


def validate_input_path(file_path: str) -> Path:
    """Validate and resolve an input file path.

    Prevents path traversal attacks by:
    - Rejecting null bytes
    - Resolving to a real absolute path (follows symlinks)
    - Checking the file exists and is a regular file
    - Enforcing allowed directory restrictions when configured

    Args:
        file_path: User-provided file path to validate.

    Returns:
        Resolved Path object.

    Raises:
        ValueError: If the path is invalid or outside allowed directories.
    """
    if "\x00" in file_path:
        raise ValueError("Invalid file path: null bytes not allowed")

    resolved = Path(file_path).resolve()

    if not resolved.exists():
        raise ValueError(f"File not found: {resolved.name}")

    if not resolved.is_file():
        raise ValueError(f"Not a regular file: {resolved.name}")

    allowed_dirs = get_allowed_input_dirs()
    if allowed_dirs:
        if not any(
            resolved == d or str(resolved).startswith(str(d) + os.sep) for d in allowed_dirs
        ):
            raise ValueError("Access denied: path is outside allowed input directories")

    return resolved


def get_rate_limit() -> int:
    """Get max tool calls per minute. 0 = unlimited."""
    raw = os.environ.get("USECVISLIB_MCP_RATE_LIMIT", "60")
    try:
        return int(raw)
    except (ValueError, TypeError):
        raise ValueError(
            f"Environment variable USECVISLIB_MCP_RATE_LIMIT must be an integer, got '{raw}'"
        ) from None


class RateLimiter:
    """In-memory rate limiter using a sliding window.

    Supports both per-tool (global) and per-client+tool buckets.
    When a client_id is provided, rate limits are enforced independently
    per client, preventing one aggressive client from exhausting the
    budget for all others in multi-tenant HTTP deployments.
    """

    def __init__(self, max_calls_per_minute: int = 60):
        self.max_calls = max_calls_per_minute
        self._calls: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, tool_name: str, client_id: str = "") -> None:
        """Check if the call is allowed. Raises ValueError if rate exceeded.

        Args:
            tool_name: Name of the tool being invoked.
            client_id: Optional client identifier (e.g. IP address).
                       When provided, rate limits are per client+tool.
        """
        if self.max_calls <= 0:
            return  # Unlimited

        # Use composite key for per-client isolation
        bucket_key = f"{client_id}:{tool_name}" if client_id else tool_name

        with self._lock:
            now = time.time()
            window_start = now - 60.0

            # Clean old entries
            calls = self._calls[bucket_key]
            self._calls[bucket_key] = [t for t in calls if t > window_start]

            if len(self._calls[bucket_key]) >= self.max_calls:
                raise ValueError(
                    f"Rate limit exceeded for '{tool_name}': max {self.max_calls} calls/minute"
                )

            self._calls[bucket_key].append(now)


# Global rate limiter instance (initialized lazily, thread-safe)
_rate_limiter: RateLimiter | None = None
_rate_limiter_lock = threading.Lock()


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter (thread-safe)."""
    global _rate_limiter
    if _rate_limiter is None:
        with _rate_limiter_lock:
            if _rate_limiter is None:
                _rate_limiter = RateLimiter(max_calls_per_minute=get_rate_limit())
    return _rate_limiter


def ensure_directories() -> None:
    """Create output and temp directories with restrictive permissions.

    Checks ownership of existing directories to detect potential
    directory pre-creation attacks on multi-user systems.
    """
    logger = logging.getLogger("usecvislib_mcp")
    for d in (get_output_dir(), get_temp_dir()):
        d.mkdir(parents=True, exist_ok=True)
        # Set restrictive permissions (owner-only) to protect sensitive configs
        try:
            d.chmod(0o700)
        except OSError:
            pass  # Best-effort on platforms that don't support chmod
        # Verify ownership on Unix systems
        try:
            dir_stat = d.stat()
            current_uid = os.getuid()
            if dir_stat.st_uid != current_uid:
                logger.warning(
                    "Directory %s is owned by uid %d, not current user %d. "
                    "This may indicate a directory pre-creation attack. "
                    "Consider using a different path via environment variables.",
                    d,
                    dir_stat.st_uid,
                    current_uid,
                )
        except (AttributeError, OSError):
            pass  # os.getuid() not available on Windows; stat may fail
