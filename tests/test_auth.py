"""Tests for API key authentication."""

import pytest

from usecvislib_mcp.auth import ApiKeyVerifier


@pytest.fixture
def verifier():
    return ApiKeyVerifier("test-secret-key")


@pytest.mark.asyncio
async def test_valid_token(verifier):
    """Valid API key returns an AccessToken."""
    result = await verifier.verify_token("test-secret-key")
    assert result is not None
    assert result.client_id == "api-key-user"
    assert result.scopes == ["usecvislib"]


@pytest.mark.asyncio
async def test_invalid_token(verifier):
    """Wrong API key returns None."""
    result = await verifier.verify_token("wrong-key")
    assert result is None


@pytest.mark.asyncio
async def test_empty_token(verifier):
    """Empty token returns None."""
    result = await verifier.verify_token("")
    assert result is None


def test_empty_key_raises():
    """Empty API key raises ValueError."""
    with pytest.raises(ValueError, match="must not be empty"):
        ApiKeyVerifier("")
