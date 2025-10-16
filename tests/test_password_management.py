"""Tests for password and DEK management."""

import pytest

from safe_core import (
    SafeCore,
    AuthenticationError,
    get_default_crypto_params,
)


class TestPasswordChange:
    """Test password change operations."""

    def test_change_password_basic(self, initialized_storage, alternative_password):
        """Test basic password change."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]

        # Change password
        new_vb = core.change_master_password(old_password, alternative_password, old_vb)

        # Old password should no longer work
        with pytest.raises(AuthenticationError):
            core.authenticate_and_get_key(old_password, new_vb)

        # New password should work and return same DEK
        retrieved_dek = core.authenticate_and_get_key(alternative_password, new_vb)
        assert retrieved_dek == dek

    def test_change_password_preserves_dek(self, initialized_storage, alternative_password):
        """Test that password change preserves the DEK."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        original_dek = initialized_storage["dek"]

        # Change password multiple times
        passwords = [alternative_password, b"third_password", b"fourth_password"]
        current_vb = old_vb

        for new_password in passwords:
            current_vb = core.change_master_password(
                (
                    old_password
                    if current_vb == old_vb
                    else passwords[passwords.index(new_password) - 1]
                ),
                new_password,
                current_vb,
            )

            # DEK should remain the same
            retrieved_dek = core.authenticate_and_get_key(new_password, current_vb)
            assert retrieved_dek == original_dek

    def test_change_password_with_wrong_old_password(
        self, initialized_storage, alternative_password
    ):
        """Test that wrong old password prevents password change."""
        core = initialized_storage["core"]
        old_vb = initialized_storage["verification_block"]

        with pytest.raises(AuthenticationError):
            core.change_master_password(b"wrong_old_password", alternative_password, old_vb)

    def test_change_password_encrypted_data_still_accessible(
        self, initialized_storage, alternative_password
    ):
        """Test that encrypted data is still accessible after password change."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Encrypt some data
        plaintext = b"important secret data"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Change password
        new_vb = core.change_master_password(old_password, alternative_password, old_vb)

        # Get DEK with new password
        new_dek = core.authenticate_and_get_key(alternative_password, new_vb)

        # Should still be able to decrypt
        decrypted = core.decrypt_block(encrypted, new_dek)
        assert decrypted == plaintext

    def test_change_password_to_empty(self, initialized_storage):
        """Test changing to empty password."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]

        new_vb = core.change_master_password(old_password, b"", old_vb)

        retrieved_dek = core.authenticate_and_get_key(b"", new_vb)
        assert retrieved_dek == dek

    def test_change_password_from_empty(self, safe_core, interactive_params, alternative_password):
        """Test changing from empty password."""
        empty_password = b""
        dek, old_vb = safe_core.initialize_storage(empty_password, interactive_params)

        new_vb = safe_core.change_master_password(empty_password, alternative_password, old_vb)

        retrieved_dek = safe_core.authenticate_and_get_key(alternative_password, new_vb)
        assert retrieved_dek == dek

    def test_change_password_with_new_crypto_params(
        self, initialized_storage, alternative_password, custom_crypto_params
    ):
        """Test changing password with different crypto parameters."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]

        new_vb = core.change_master_password(
            old_password, alternative_password, old_vb, crypto_params=custom_crypto_params
        )

        # Should work with new parameters
        retrieved_dek = core.authenticate_and_get_key(alternative_password, new_vb)
        assert retrieved_dek == dek

    @pytest.mark.asyncio
    async def test_change_password_async(self, initialized_storage, alternative_password):
        """Test async password change."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]

        new_vb = await core.change_master_password_async(old_password, alternative_password, old_vb)

        retrieved_dek = await core.authenticate_and_get_key_async(alternative_password, new_vb)
        assert retrieved_dek == dek


class TestDekRotation:
    """Test DEK rotation operations."""

    def test_rotate_dek_basic(self, initialized_storage):
        """Test basic DEK rotation."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        old_dek = initialized_storage["dek"]

        # Rotate DEK
        new_dek, new_vb = core.rotate_dek(password, old_vb)

        # New DEK should be different
        assert new_dek != old_dek
        assert len(new_dek) == 32

        # Should authenticate with same password
        retrieved_dek = core.authenticate_and_get_key(password, new_vb)
        assert retrieved_dek == new_dek

        # Old verification block should still work
        old_dek_retrieved = core.authenticate_and_get_key(password, old_vb)
        assert old_dek_retrieved == old_dek

    def test_rotate_dek_requires_correct_password(self, initialized_storage):
        """Test that DEK rotation requires correct password."""
        core = initialized_storage["core"]
        old_vb = initialized_storage["verification_block"]

        with pytest.raises(AuthenticationError):
            core.rotate_dek(b"wrong_password", old_vb)

    def test_rotate_dek_old_encrypted_data_inaccessible(self, initialized_storage):
        """Test that old encrypted data can't be decrypted with new DEK."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        old_dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Encrypt data with old DEK
        plaintext = b"secret data"
        encrypted = core.encrypt_block(plaintext, old_dek, params)

        # Rotate DEK
        new_dek, new_vb = core.rotate_dek(password, old_vb)

        # Old data can't be decrypted with new DEK
        from safe_core import DataIntegrityError

        with pytest.raises(DataIntegrityError):
            core.decrypt_block(encrypted, new_dek)

        # But can still be decrypted with old DEK
        decrypted = core.decrypt_block(encrypted, old_dek)
        assert decrypted == plaintext

    def test_rotate_dek_multiple_times(self, initialized_storage):
        """Test multiple DEK rotations."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        current_vb = initialized_storage["verification_block"]

        deks = [initialized_storage["dek"]]

        # Rotate 5 times
        for _ in range(5):
            new_dek, new_vb = core.rotate_dek(password, current_vb)
            deks.append(new_dek)
            current_vb = new_vb

        # All DEKs should be different
        assert len(set(deks)) == len(deks)

        # Last DEK should be retrievable
        retrieved_dek = core.authenticate_and_get_key(password, current_vb)
        assert retrieved_dek == deks[-1]

    def test_rotate_dek_with_new_crypto_params(self, initialized_storage, custom_crypto_params):
        """Test DEK rotation with different crypto parameters."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]

        new_dek, new_vb = core.rotate_dek(password, old_vb, crypto_params=custom_crypto_params)

        retrieved_dek = core.authenticate_and_get_key(password, new_vb)
        assert retrieved_dek == new_dek

    @pytest.mark.asyncio
    async def test_rotate_dek_async(self, initialized_storage):
        """Test async DEK rotation."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        old_dek = initialized_storage["dek"]

        new_dek, new_vb = await core.rotate_dek_async(password, old_vb)

        assert new_dek != old_dek
        retrieved_dek = await core.authenticate_and_get_key_async(password, new_vb)
        assert retrieved_dek == new_dek


class TestPasswordAndDekCombinations:
    """Test combinations of password changes and DEK rotations."""

    def test_rotate_dek_then_change_password(self, initialized_storage, alternative_password):
        """Test DEK rotation followed by password change."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]

        # Rotate DEK
        new_dek, vb_after_rotation = core.rotate_dek(old_password, old_vb)

        # Change password
        final_vb = core.change_master_password(
            old_password, alternative_password, vb_after_rotation
        )

        # Should authenticate with new password and get new DEK
        retrieved_dek = core.authenticate_and_get_key(alternative_password, final_vb)
        assert retrieved_dek == new_dek

    def test_change_password_then_rotate_dek(self, initialized_storage, alternative_password):
        """Test password change followed by DEK rotation."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        old_dek = initialized_storage["dek"]

        # Change password
        vb_after_password_change = core.change_master_password(
            old_password, alternative_password, old_vb
        )

        # Rotate DEK
        new_dek, final_vb = core.rotate_dek(alternative_password, vb_after_password_change)

        # Should authenticate with new password and get new DEK
        retrieved_dek = core.authenticate_and_get_key(alternative_password, final_vb)
        assert retrieved_dek == new_dek
        assert new_dek != old_dek

    def test_multiple_operations_preserve_functionality(self, safe_core, test_password):
        """Test that multiple password/DEK operations preserve functionality."""
        params = get_default_crypto_params("interactive")

        # Initialize
        dek1, vb1 = safe_core.initialize_storage(test_password, params)

        # Encrypt some data
        plaintext = b"test data"
        encrypted1 = safe_core.encrypt_block(plaintext, dek1, params)

        # Change password
        new_password = b"new_password"
        vb2 = safe_core.change_master_password(test_password, new_password, vb1)
        dek2 = safe_core.authenticate_and_get_key(new_password, vb2)

        # Old data should still be accessible
        assert safe_core.decrypt_block(encrypted1, dek2) == plaintext

        # Rotate DEK
        dek3, vb3 = safe_core.rotate_dek(new_password, vb2)

        # Encrypt new data with new DEK
        encrypted2 = safe_core.encrypt_block(plaintext, dek3, params)

        # New data should be accessible
        assert safe_core.decrypt_block(encrypted2, dek3) == plaintext

        # Old data should still work with old DEK
        assert safe_core.decrypt_block(encrypted1, dek2) == plaintext


class TestPasswordEdgeCases:
    """Test edge cases in password management."""

    def test_change_password_to_same_password(self, initialized_storage):
        """Test changing password to the same password."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]

        # Change to same password
        new_vb = core.change_master_password(password, password, old_vb)

        # Should still work
        retrieved_dek = core.authenticate_and_get_key(password, new_vb)
        assert retrieved_dek == dek

        # Verification blocks should be different (new salt)
        assert new_vb != old_vb

    def test_change_password_very_long_new_password(self, initialized_storage):
        """Test changing to very long password."""
        core = initialized_storage["core"]
        old_password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]
        dek = initialized_storage["dek"]

        long_password = b"a" * 100000
        new_vb = core.change_master_password(old_password, long_password, old_vb)

        retrieved_dek = core.authenticate_and_get_key(long_password, new_vb)
        assert retrieved_dek == dek

    def test_rotate_dek_preserves_password(self, initialized_storage):
        """Test that DEK rotation doesn't affect password."""
        core = initialized_storage["core"]
        password = initialized_storage["password"]
        old_vb = initialized_storage["verification_block"]

        new_dek, new_vb = core.rotate_dek(password, old_vb)

        # Same password should still work
        retrieved_dek = core.authenticate_and_get_key(password, new_vb)
        assert retrieved_dek == new_dek
