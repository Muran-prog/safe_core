"""Tests for rate limiting functionality."""

import pytest
import time

from safe_core import (
    SafeCore,
    RateLimitedSafeCore,
    AuthenticationRateLimiter,
    RateLimitError,
    AuthenticationError,
)


class TestRateLimiter:
    """Test AuthenticationRateLimiter class."""

    def test_rate_limiter_allows_under_limit(self):
        """Test that attempts under limit are allowed."""
        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)

        # Should allow 3 attempts
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

    def test_rate_limiter_blocks_over_limit(self):
        """Test that attempts over limit are blocked."""
        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)

        # First 3 attempts should work
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

        # 4th attempt should be blocked
        with pytest.raises(RateLimitError) as exc_info:
            limiter.check_and_record("user1")

        assert exc_info.value.wait_seconds > 0

    def test_rate_limiter_resets_after_success(self):
        """Test that successful auth resets the counter."""
        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)

        # Make 2 attempts
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

        # Reset (simulating successful auth)
        limiter.reset("user1")

        # Should be able to make 3 more attempts
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

    def test_rate_limiter_separate_identifiers(self):
        """Test that different identifiers have separate limits."""
        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)

        # User1 makes 2 attempts
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

        # User1 is now blocked
        with pytest.raises(RateLimitError):
            limiter.check_and_record("user1")

        # User2 should still be allowed
        limiter.check_and_record("user2")
        limiter.check_and_record("user2")

    def test_rate_limiter_window_expiry(self):
        """Test that rate limit expires after time window."""
        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=1)

        # Make 2 attempts
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

        # Should be blocked
        with pytest.raises(RateLimitError):
            limiter.check_and_record("user1")

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        limiter.check_and_record("user1")

    def test_rate_limiter_clear_all(self):
        """Test clearing all rate limit data."""
        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)

        # Make attempts for multiple users
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")
        limiter.check_and_record("user2")
        limiter.check_and_record("user2")

        # Both should be blocked
        with pytest.raises(RateLimitError):
            limiter.check_and_record("user1")
        with pytest.raises(RateLimitError):
            limiter.check_and_record("user2")

        # Clear all
        limiter.clear_all()

        # Both should be allowed again
        limiter.check_and_record("user1")
        limiter.check_and_record("user2")

    def test_rate_limiter_wait_seconds_accurate(self):
        """Test that wait_seconds is reasonably accurate."""
        limiter = AuthenticationRateLimiter(max_attempts=1, window_seconds=10)

        limiter.check_and_record("user1")

        with pytest.raises(RateLimitError) as exc_info:
            limiter.check_and_record("user1")

        # Wait time should be close to window_seconds
        assert 8 <= exc_info.value.wait_seconds <= 10


class TestRateLimitedSafeCore:
    """Test RateLimitedSafeCore wrapper."""

    def test_rate_limited_auth_success(self, initialized_storage):
        """Test successful authentication with rate limiting."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]
        expected_dek = initialized_storage["dek"]

        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)
        rate_limited_core = RateLimitedSafeCore(core, limiter)

        # Should work
        dek = rate_limited_core.authenticate_and_get_key("user1", password, vb)
        assert dek == expected_dek

    def test_rate_limited_auth_resets_on_success(self, initialized_storage):
        """Test that rate limit resets on successful auth."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]

        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)
        rate_limited_core = RateLimitedSafeCore(core, limiter)

        # Make 2 failed attempts
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                rate_limited_core.authenticate_and_get_key("user1", b"wrong", vb)

        # Successful auth should reset
        rate_limited_core.authenticate_and_get_key("user1", password, vb)

        # Should be able to make 3 more attempts
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                rate_limited_core.authenticate_and_get_key("user1", b"wrong", vb)

        # This should still work (not blocked)
        rate_limited_core.authenticate_and_get_key("user1", password, vb)

    def test_rate_limited_auth_blocks_after_failures(self, initialized_storage):
        """Test that authentication is blocked after too many failures."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]

        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)
        rate_limited_core = RateLimitedSafeCore(core, limiter)

        # Make 3 failed attempts
        for _ in range(3):
            with pytest.raises(AuthenticationError):
                rate_limited_core.authenticate_and_get_key("user1", b"wrong", vb)

        # 4th attempt should be rate limited
        with pytest.raises(RateLimitError):
            rate_limited_core.authenticate_and_get_key("user1", b"wrong", vb)

    def test_rate_limited_auth_different_users(self, initialized_storage):
        """Test that different users have separate rate limits."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]

        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)
        rate_limited_core = RateLimitedSafeCore(core, limiter)

        # User1 makes 2 failed attempts
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                rate_limited_core.authenticate_and_get_key("user1", b"wrong", vb)

        # User1 is now blocked
        with pytest.raises(RateLimitError):
            rate_limited_core.authenticate_and_get_key("user1", b"wrong", vb)

        # User2 should still work
        with pytest.raises(AuthenticationError):
            rate_limited_core.authenticate_and_get_key("user2", b"wrong", vb)

    @pytest.mark.asyncio
    async def test_rate_limited_auth_async(self, initialized_storage):
        """Test async authentication with rate limiting."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]
        expected_dek = initialized_storage["dek"]

        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)
        rate_limited_core = RateLimitedSafeCore(core, limiter)

        dek = await rate_limited_core.authenticate_and_get_key_async("user1", password, vb)
        assert dek == expected_dek

    @pytest.mark.asyncio
    async def test_rate_limited_auth_async_blocks(self, initialized_storage):
        """Test async authentication blocking."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]

        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)
        rate_limited_core = RateLimitedSafeCore(core, limiter)

        # Make 2 failed attempts
        for _ in range(2):
            with pytest.raises(AuthenticationError):
                await rate_limited_core.authenticate_and_get_key_async("user1", b"wrong", vb)

        # 3rd attempt should be rate limited
        with pytest.raises(RateLimitError):
            await rate_limited_core.authenticate_and_get_key_async("user1", b"wrong", vb)


class TestRateLimiterConfiguration:
    """Test rate limiter configuration."""

    def test_custom_max_attempts(self):
        """Test custom max attempts configuration."""
        limiter = AuthenticationRateLimiter(max_attempts=5, window_seconds=60)

        # Should allow 5 attempts
        for _ in range(5):
            limiter.check_and_record("user1")

        # 6th should be blocked
        with pytest.raises(RateLimitError):
            limiter.check_and_record("user1")

    def test_custom_window_seconds(self):
        """Test custom window seconds configuration."""
        limiter = AuthenticationRateLimiter(max_attempts=1, window_seconds=2)

        limiter.check_and_record("user1")

        with pytest.raises(RateLimitError):
            limiter.check_and_record("user1")

        # Wait for window to expire
        time.sleep(2.1)

        # Should work again
        limiter.check_and_record("user1")

    def test_rate_limiter_invalid_config(self):
        """Test that invalid configuration is rejected."""
        from safe_core import ConfigurationError

        with pytest.raises(ConfigurationError):
            AuthenticationRateLimiter(max_attempts=0, window_seconds=60)

        with pytest.raises(ConfigurationError):
            AuthenticationRateLimiter(max_attempts=3, window_seconds=0)

        with pytest.raises(ConfigurationError):
            AuthenticationRateLimiter(max_attempts=-1, window_seconds=60)


class TestRateLimiterEdgeCases:
    """Test edge cases in rate limiting."""

    def test_rate_limiter_exact_boundary(self):
        """Test behavior at exact rate limit boundary."""
        limiter = AuthenticationRateLimiter(max_attempts=3, window_seconds=60)

        # Exactly 3 attempts should work
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")
        limiter.check_and_record("user1")

        # One more should fail
        with pytest.raises(RateLimitError):
            limiter.check_and_record("user1")

    def test_rate_limiter_empty_identifier(self):
        """Test rate limiter with empty identifier."""
        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)

        limiter.check_and_record("")
        limiter.check_and_record("")

        with pytest.raises(RateLimitError):
            limiter.check_and_record("")

    def test_rate_limiter_unicode_identifier(self):
        """Test rate limiter with unicode identifier."""
        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)

        identifier = "пользователь123"

        limiter.check_and_record(identifier)
        limiter.check_and_record(identifier)

        with pytest.raises(RateLimitError):
            limiter.check_and_record(identifier)

    def test_rate_limiter_concurrent_identifiers(self):
        """Test rate limiter with many concurrent identifiers."""
        limiter = AuthenticationRateLimiter(max_attempts=2, window_seconds=60)

        # Create 100 different identifiers
        for i in range(100):
            identifier = f"user{i}"
            limiter.check_and_record(identifier)
            limiter.check_and_record(identifier)

            # Each should be blocked on 3rd attempt
            with pytest.raises(RateLimitError):
                limiter.check_and_record(identifier)
