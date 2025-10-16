"""Integration tests for complete workflows."""

import pytest
import io

from safe_core import (
    SafeCore,
    get_default_crypto_params,
    KeyPurpose,
)


class TestCompleteWorkflow:
    """Test complete end-to-end workflows."""

    def test_full_lifecycle(self, test_password):
        """Test complete lifecycle: init -> encrypt -> decrypt -> password change -> rotate DEK."""
        core = SafeCore()
        params = get_default_crypto_params("interactive")

        # 1. Initialize storage
        dek, vb = core.initialize_storage(test_password, params)

        # 2. Encrypt some data
        data1 = b"First secret document"
        data2 = b"Second secret document"
        encrypted1 = core.encrypt_block(data1, dek, params)
        encrypted2 = core.encrypt_block(data2, dek, params)

        # 3. Verify decryption
        assert core.decrypt_block(encrypted1, dek) == data1
        assert core.decrypt_block(encrypted2, dek) == data2

        # 4. Authenticate
        auth_dek = core.authenticate_and_get_key(test_password, vb)
        assert auth_dek == dek

        # 5. Change password
        new_password = b"new_password"
        new_vb = core.change_master_password(test_password, new_password, vb)

        # 6. Authenticate with new password
        new_dek = core.authenticate_and_get_key(new_password, new_vb)
        assert new_dek == dek

        # 7. Old data still accessible
        assert core.decrypt_block(encrypted1, new_dek) == data1
        assert core.decrypt_block(encrypted2, new_dek) == data2

        # 8. Rotate DEK
        rotated_dek, rotated_vb = core.rotate_dek(new_password, new_vb)
        assert rotated_dek != dek

        # 9. Encrypt new data with rotated DEK
        data3 = b"Third secret document"
        encrypted3 = core.encrypt_block(data3, rotated_dek, params)

        # 10. New data works with new DEK
        assert core.decrypt_block(encrypted3, rotated_dek) == data3

        # 11. Old data still works with old DEK
        assert core.decrypt_block(encrypted1, new_dek) == data1

    def test_multi_user_simulation(self):
        """Simulate multiple users with separate storages."""
        core = SafeCore()
        params = get_default_crypto_params("interactive")

        # User 1
        user1_password = b"user1_password"
        user1_dek, user1_vb = core.initialize_storage(user1_password, params)
        user1_data = b"User 1 secret data"
        user1_encrypted = core.encrypt_block(user1_data, user1_dek, params)

        # User 2
        user2_password = b"user2_password"
        user2_dek, user2_vb = core.initialize_storage(user2_password, params)
        user2_data = b"User 2 secret data"
