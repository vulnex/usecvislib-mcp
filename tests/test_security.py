#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_security.py
# Author: Simon Roses Femerling
# Created: 2026-03-01
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for security-critical functions: validate_input_path and RateLimiter."""

import os
import time

import pytest

from usecvislib_mcp.config import RateLimiter, validate_input_path


# ── validate_input_path tests ──────────────────────────────────────


class TestValidateInputPath:
    """Tests for the validate_input_path function."""

    def test_valid_file(self, tmp_path):
        """Accepts a valid existing file."""
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = validate_input_path(str(f))
        assert result == f.resolve()

    def test_rejects_null_bytes(self, tmp_path):
        """Rejects paths containing null bytes."""
        with pytest.raises(ValueError, match="null bytes"):
            validate_input_path("/tmp/evil\x00file.txt")

    def test_rejects_nonexistent_file(self, tmp_path):
        """Rejects paths to files that don't exist."""
        with pytest.raises(ValueError, match="File not found"):
            validate_input_path(str(tmp_path / "nonexistent.txt"))

    def test_rejects_directory(self, tmp_path):
        """Rejects paths that point to directories."""
        with pytest.raises(ValueError, match="Not a regular file"):
            validate_input_path(str(tmp_path))

    def test_resolves_symlinks(self, tmp_path):
        """Resolves symlinks and validates the real path."""
        real_file = tmp_path / "real.txt"
        real_file.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)
        result = validate_input_path(str(link))
        assert result == real_file.resolve()

    def test_rejects_symlink_to_nonexistent(self, tmp_path):
        """Rejects symlinks pointing to nonexistent files."""
        link = tmp_path / "broken_link.txt"
        link.symlink_to(tmp_path / "does_not_exist.txt")
        with pytest.raises(ValueError, match="File not found"):
            validate_input_path(str(link))

    def test_allowed_dirs_permits_file_inside(self, tmp_path, monkeypatch):
        """Allows files inside allowed directories."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        f = allowed_dir / "data.bin"
        f.write_text("binary data")
        monkeypatch.setenv(
            "USECVISLIB_MCP_ALLOWED_INPUT_DIRS", str(allowed_dir)
        )
        result = validate_input_path(str(f))
        assert result == f.resolve()

    def test_allowed_dirs_rejects_file_outside(self, tmp_path, monkeypatch):
        """Rejects files outside allowed directories."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("secret")
        monkeypatch.setenv(
            "USECVISLIB_MCP_ALLOWED_INPUT_DIRS", str(allowed_dir)
        )
        with pytest.raises(ValueError, match="Access denied"):
            validate_input_path(str(outside_file))

    def test_allowed_dirs_multiple(self, tmp_path, monkeypatch):
        """Supports multiple comma-separated allowed directories."""
        dir_a = tmp_path / "dir_a"
        dir_b = tmp_path / "dir_b"
        dir_a.mkdir()
        dir_b.mkdir()
        file_b = dir_b / "file.txt"
        file_b.write_text("ok")
        monkeypatch.setenv(
            "USECVISLIB_MCP_ALLOWED_INPUT_DIRS",
            f"{dir_a},{dir_b}",
        )
        result = validate_input_path(str(file_b))
        assert result == file_b.resolve()

    def test_allowed_dirs_empty_permits_all(self, tmp_path, monkeypatch):
        """Empty ALLOWED_INPUT_DIRS means no restriction (local mode)."""
        monkeypatch.setenv("USECVISLIB_MCP_ALLOWED_INPUT_DIRS", "")
        f = tmp_path / "anywhere.txt"
        f.write_text("data")
        result = validate_input_path(str(f))
        assert result == f.resolve()

    def test_path_traversal_blocked(self, tmp_path, monkeypatch):
        """Blocks directory traversal attempts via allowed dirs."""
        allowed_dir = tmp_path / "jail"
        allowed_dir.mkdir()
        # Create a file outside the jail
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
        monkeypatch.setenv(
            "USECVISLIB_MCP_ALLOWED_INPUT_DIRS", str(allowed_dir)
        )
        # Try traversal
        traversal_path = str(allowed_dir / ".." / "secret.txt")
        with pytest.raises(ValueError, match="Access denied"):
            validate_input_path(traversal_path)


# ── RateLimiter tests ──────────────────────────────────────────────


class TestRateLimiter:
    """Tests for the RateLimiter class."""

    def test_allows_calls_under_limit(self):
        """Allows calls when under the rate limit."""
        limiter = RateLimiter(max_calls_per_minute=5)
        for _ in range(5):
            limiter.check("test_tool")  # Should not raise

    def test_blocks_calls_over_limit(self):
        """Raises ValueError when rate limit exceeded."""
        limiter = RateLimiter(max_calls_per_minute=3)
        for _ in range(3):
            limiter.check("test_tool")
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            limiter.check("test_tool")

    def test_per_tool_isolation(self):
        """Rate limits are tracked per tool name."""
        limiter = RateLimiter(max_calls_per_minute=2)
        limiter.check("tool_a")
        limiter.check("tool_a")
        # tool_a is at limit, but tool_b should still work
        limiter.check("tool_b")  # Should not raise
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            limiter.check("tool_a")

    def test_unlimited_when_zero(self):
        """max_calls_per_minute=0 means unlimited."""
        limiter = RateLimiter(max_calls_per_minute=0)
        for _ in range(100):
            limiter.check("test_tool")  # Should never raise

    def test_window_cleanup(self):
        """Old entries outside the 60s window are cleaned up."""
        limiter = RateLimiter(max_calls_per_minute=2)
        # Manually inject old timestamps
        old_time = time.time() - 120  # 2 minutes ago
        limiter._calls["test_tool"] = [old_time, old_time]
        # These should be cleaned up, so new calls should succeed
        limiter.check("test_tool")  # Should not raise

    def test_error_message_includes_tool_name(self):
        """Error message includes the tool name and limit."""
        limiter = RateLimiter(max_calls_per_minute=1)
        limiter.check("my_tool")
        with pytest.raises(ValueError, match="my_tool") as exc_info:
            limiter.check("my_tool")
        assert "1 calls/minute" in str(exc_info.value)

    def test_exactly_at_limit(self):
        """Exactly at the limit should still succeed, one more should fail."""
        limiter = RateLimiter(max_calls_per_minute=5)
        for i in range(5):
            limiter.check("tool")
        with pytest.raises(ValueError):
            limiter.check("tool")
