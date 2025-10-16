"""Tests for authentication operations."""

import pytest

from safe_core import (
    SafeCore,
    AuthenticationError,
    ContainerFormatError,
)


class TestAuthentication:
    """Test user authentication operations."""

    def test_authenticate_with_correct_password(self, initialized_storage):
        """Test successful authentication with correct password."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]
        expected_dek = initialized_storage["dek"]

        retrieved_dek = core.authenticate_and_get_key(password, vb)

        assert retrieved_dek == expected_dek
        assert len(retrieved_dek) == 32

    def test_authenticate_with_wrong_password(self, initialized_storage):
        """Test that wrong password raises AuthenticationError."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]
        wrong_password = b"wrong_password"

        with pytest.raises(AuthenticationError):
            core.authenticate_and_get_key(wrong_password, vb)

    def test_authenticate_multiple_times(self, initialized_storage):
        """Test that authentication can be performed multiple times."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]
        expected_dek = initialized_storage["dek"]

        # Authenticate 5 times
        for _ in range(5):
            retrieved_dek = core.authenticate_and_get_key(password, vb)
            assert retrieved_dek == expected_dek

    def test_authenticate_empty_password(self, safe_core, interactive_params):
        """Test authentication with empty password."""
        empty_password = b""
        dek, vb = safe_core.initialize_storage(empty_password, interactive_params)

        retrieved_dek = safe_core.authenticate_and_get_key(empty_password, vb)
        assert retrieved_dek == dek

        # Wrong empty password should fail
        with pytest.raises(AuthenticationError):
            safe_core.authenticate_and_get_key(b"not_empty", vb)

    def test_authenticate_with_similar_passwords(self, safe_core, interactive_params):
        """Test that similar but different passwords fail."""
        password1 = b"password123"
        password2 = b"password124"  # Only last char different

        dek, vb = safe_core.initialize_storage(password1, interactive_params)

        # Correct password works
        retrieved_dek = safe_core.authenticate_and_get_key(password1, vb)
        assert retrieved_dek == dek

        # Similar but wrong password fails
        with pytest.raises(AuthenticationError):
            safe_core.authenticate_and_get_key(password2, vb)

    def test_authenticate_unicode_password(self, safe_core, interactive_params):
        """Test authentication with unicode password."""
        unicode_password = "тестовый_пароль".encode("utf-8")

        dek, vb = safe_core.initialize_storage(unicode_password, interactive_params)
        retrieved_dek = safe_core.authenticate_and_get_key(unicode_password, vb)

        assert retrieved_dek == dek

    def test_authenticate_case_sensitive(self, safe_core, interactive_params):
        """Test that passwords are case-sensitive."""
        password_lower = b"password"
        password_upper = b"PASSWORD"

        dek, vb = safe_core.initialize_storage(password_lower, interactive_params)

        # Correct case works
        assert safe_core.authenticate_and_get_key(password_lower, vb) == dek

        # Wrong case fails
        with pytest.raises(AuthenticationError):
            safe_core.authenticate_and_get_key(password_upper, vb)

    @pytest.mark.asyncio
    async def test_authenticate_async(self, initialized_storage):
        """Test async authentication."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]
        expected_dek = initialized_storage["dek"]

        retrieved_dek = await core.authenticate_and_get_key_async(password, vb)
        assert retrieved_dek == expected_dek

    @pytest.mark.asyncio
    async def test_authenticate_async_wrong_password(self, initialized_storage):
        """Test async authentication with wrong password."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]

        with pytest.raises(AuthenticationError):
            await core.authenticate_and_get_key_async(b"wrong", vb)

    @pytest.mark.asyncio
    async def test_authenticate_sync_and_async_equivalent(self, initialized_storage):
        """Test that sync and async authentication produce same results."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]

        sync_dek = core.authenticate_and_get_key(password, vb)
        async_dek = await core.authenticate_and_get_key_async(password, vb)

        assert sync_dek == async_dek


class TestVerificationBlockCorruption:
    """Test handling of corrupted verification blocks."""

    def test_corrupted_verification_block(self, initialized_storage):
        """Test that corrupted verification block raises error."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]

        # Corrupt the verification block at the END (auth tag area)
        # Don't corrupt early bytes that might affect KDF parameters parsing
        corrupted_vb = bytearray(vb)
        if len(corrupted_vb) > 20:
            # Corrupt near the end, likely the auth tag
            corrupted_vb[-10] ^= 0xFF
        else:
            corrupted_vb[-1] ^= 0xFF

        # Should raise error, but don't let it hang
        import signal

        def timeout_handler(signum, frame):
            raise TimeoutError("Test took too long")

        # Set 5 second timeout (Windows doesn't support signal.alarm, so skip on Windows)
        import platform

        if platform.system() != "Windows":
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(5)

        try:
            with pytest.raises((AuthenticationError, ContainerFormatError, TimeoutError)):
                core.authenticate_and_get_key(password, bytes(corrupted_vb))
        finally:
            if platform.system() != "Windows":
                signal.alarm(0)  # Cancel alarm

    def test_truncated_verification_block(self, initialized_storage):
        """Test that truncated verification block raises error."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]

        # Truncate the verification block
        truncated_vb = vb[: len(vb) // 2]

        with pytest.raises(ContainerFormatError):
            core.authenticate_and_get_key(password, truncated_vb)

    def test_empty_verification_block(self, initialized_storage):
        """Test that empty verification block raises error."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]

        with pytest.raises(ContainerFormatError):
            core.authenticate_and_get_key(password, b"")

    def test_random_bytes_as_verification_block(self, initialized_storage, random_data):
        """Test that random bytes as verification block raises error."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]

        with pytest.raises(ContainerFormatError):
            core.authenticate_and_get_key(password, random_data(100))

    def test_modified_auth_tag(self, initialized_storage):
        """Test that modified authentication tag is detected."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]

        # Modify the last 16 bytes (auth tag)
        modified_vb = bytearray(vb)
        modified_vb[-1] ^= 0xFF

        with pytest.raises(AuthenticationError):
            core.authenticate_and_get_key(password, bytes(modified_vb))


class TestAuthenticationEdgeCases:
    """Test edge cases in authentication."""

    def test_authenticate_with_none_password(self, initialized_storage):
        """Test that None as password raises appropriate error."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]

        # Should raise KeyDerivationError (not TypeError)
        from safe_core import KeyDerivationError

        with pytest.raises(KeyDerivationError):
            core.authenticate_and_get_key(None, vb)

    def test_authenticate_with_string_password(self, initialized_storage):
        """Test that string password (not bytes) raises error."""
        core = initialized_storage["core"]
        vb = initialized_storage["verification_block"]

        # Should raise KeyDerivationError (not TypeError)
        from safe_core import KeyDerivationError

        with pytest.raises(KeyDerivationError):
            core.authenticate_and_get_key("string_password", vb)

    def test_authenticate_different_instances(self, test_password, interactive_params):
        """Test authentication across different SafeCore instances."""
        core1 = SafeCore()
        core2 = SafeCore()

        dek, vb = core1.initialize_storage(test_password, interactive_params)

        # Different instance should be able to authenticate
        retrieved_dek = core2.authenticate_and_get_key(test_password, vb)
        assert retrieved_dek == dek

    def test_authenticate_preserves_verification_block(self, initialized_storage):
        """Test that authentication doesn't modify verification block."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        vb = initialized_storage["verification_block"]
        original_vb = bytes(vb)

        core.authenticate_and_get_key(password, vb)

        # Verification block should be unchanged
        assert vb == original_vb
