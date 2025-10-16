"""Tests for data encryption and decryption."""

import pytest

from safe_core import (
    SafeCore,
    KeyPurpose,
    DataIntegrityError,
    ContainerFormatError,
)


class TestBasicEncryptionDecryption:
    """Test basic encryption and decryption operations."""

    def test_encrypt_decrypt_simple(self, initialized_storage):
        """Test basic encrypt/decrypt cycle."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"Hello, World!"
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_data(self, initialized_storage):
        """Test encryption/decryption of empty data."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b""
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_decrypt_large_data(self, initialized_storage, random_data):
        """Test encryption/decryption of large data."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = random_data(1024 * 1024)  # 1 MB
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_decrypt_binary_data(self, initialized_storage):
        """Test encryption/decryption of binary data with all byte values."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = bytes(range(256))
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext(self, initialized_storage):
        """Test that encrypting same data twice produces different ciphertext."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"
        encrypted1 = core.encrypt_block(plaintext, dek, params)
        encrypted2 = core.encrypt_block(plaintext, dek, params)

        # Ciphertexts should be different (different nonces)
        assert encrypted1 != encrypted2

        # But both should decrypt to same plaintext
        assert core.decrypt_block(encrypted1, dek) == plaintext
        assert core.decrypt_block(encrypted2, dek) == plaintext

    def test_ciphertext_longer_than_plaintext(self, initialized_storage):
        """Test that ciphertext is longer than plaintext (overhead)."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Ciphertext should be longer (includes nonce, tag, metadata)
        assert len(encrypted) > len(plaintext)

    def test_decrypt_with_wrong_dek(self, initialized_storage, random_data):
        """Test that decryption with wrong DEK fails."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"secret data"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Try to decrypt with different DEK
        wrong_dek = random_data(32)

        with pytest.raises(DataIntegrityError):
            core.decrypt_block(encrypted, wrong_dek)

    def test_decrypt_corrupted_ciphertext(self, initialized_storage):
        """Test that corrupted ciphertext is detected."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Corrupt the ciphertext
        corrupted = bytearray(encrypted)
        corrupted[len(corrupted) // 2] ^= 0xFF

        with pytest.raises(DataIntegrityError):
            core.decrypt_block(bytes(corrupted), dek)

    def test_decrypt_truncated_ciphertext(self, initialized_storage):
        """Test that truncated ciphertext raises error."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Truncate the ciphertext
        truncated = encrypted[: len(encrypted) // 2]

        with pytest.raises((ContainerFormatError, DataIntegrityError)):
            core.decrypt_block(truncated, dek)


class TestKeyPurposeSeparation:
    """Test key purpose domain separation."""

    def test_different_purposes_produce_different_ciphertext(self, initialized_storage):
        """Test that different key purposes produce different ciphertexts."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"

        encrypted_data = core.encrypt_block(
            plaintext, dek, params, key_purpose=KeyPurpose.DATA_ENCRYPTION
        )
        encrypted_file = core.encrypt_block(
            plaintext, dek, params, key_purpose=KeyPurpose.FILE_ENCRYPTION
        )
        encrypted_metadata = core.encrypt_block(
            plaintext, dek, params, key_purpose=KeyPurpose.METADATA
        )

        # All should be different
        assert encrypted_data != encrypted_file
        assert encrypted_data != encrypted_metadata
        assert encrypted_file != encrypted_metadata

    def test_decrypt_requires_correct_purpose(self, initialized_storage):
        """Test that decryption requires the same key purpose."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"
        encrypted = core.encrypt_block(
            plaintext, dek, params, key_purpose=KeyPurpose.DATA_ENCRYPTION
        )

        # Correct purpose works
        decrypted = core.decrypt_block(encrypted, dek, key_purpose=KeyPurpose.DATA_ENCRYPTION)
        assert decrypted == plaintext

        # Wrong purpose fails
        with pytest.raises(DataIntegrityError):
            core.decrypt_block(encrypted, dek, key_purpose=KeyPurpose.FILE_ENCRYPTION)

    def test_all_key_purposes_work(self, initialized_storage):
        """Test that all key purposes can be used."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"
        purposes = [
            KeyPurpose.VERIFICATION,
            KeyPurpose.DATA_ENCRYPTION,
            KeyPurpose.FILE_ENCRYPTION,
            KeyPurpose.METADATA,
            KeyPurpose.SEARCH_TOKENS,
        ]

        for purpose in purposes:
            encrypted = core.encrypt_block(plaintext, dek, params, key_purpose=purpose)
            decrypted = core.decrypt_block(encrypted, dek, key_purpose=purpose)
            assert decrypted == plaintext


class TestAssociatedData:
    """Test authenticated encryption with associated data."""

    def test_encrypt_decrypt_with_associated_data(self, initialized_storage):
        """Test encryption/decryption with associated data."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"secret message"
        associated_data = b"user_id:12345"

        encrypted = core.encrypt_block(plaintext, dek, params, associated_data=associated_data)
        decrypted = core.decrypt_block(encrypted, dek, associated_data=associated_data)

        assert decrypted == plaintext

    def test_decrypt_requires_same_associated_data(self, initialized_storage):
        """Test that decryption requires the same associated data."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"secret message"
        associated_data = b"context:important"

        encrypted = core.encrypt_block(plaintext, dek, params, associated_data=associated_data)

        # Correct AAD works
        decrypted = core.decrypt_block(encrypted, dek, associated_data=associated_data)
        assert decrypted == plaintext

        # Wrong AAD fails
        with pytest.raises(DataIntegrityError):
            core.decrypt_block(encrypted, dek, associated_data=b"context:wrong")

        # Missing AAD fails
        with pytest.raises(DataIntegrityError):
            core.decrypt_block(encrypted, dek)

    def test_encrypt_without_aad_decrypt_with_aad_fails(self, initialized_storage):
        """Test that providing AAD when it wasn't used fails."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Trying to decrypt with AAD should fail
        with pytest.raises(DataIntegrityError):
            core.decrypt_block(encrypted, dek, associated_data=b"extra")

    def test_associated_data_combined_with_purpose(self, initialized_storage):
        """Test that AAD and key purpose work together."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test"
        aad = b"context"
        purpose = KeyPurpose.METADATA

        encrypted = core.encrypt_block(
            plaintext, dek, params, associated_data=aad, key_purpose=purpose
        )

        # Both must match
        decrypted = core.decrypt_block(encrypted, dek, associated_data=aad, key_purpose=purpose)
        assert decrypted == plaintext

        # Wrong purpose fails
        with pytest.raises(DataIntegrityError):
            core.decrypt_block(
                encrypted, dek, associated_data=aad, key_purpose=KeyPurpose.DATA_ENCRYPTION
            )


class TestMultipleCiphers:
    """Test encryption with different cipher algorithms."""

    def test_encrypt_decrypt_with_chacha20(self, safe_core, test_password, custom_crypto_params):
        """Test encryption/decryption with ChaCha20-Poly1305."""
        dek, vb = safe_core.initialize_storage(test_password, custom_crypto_params)

        plaintext = b"test data with chacha20"
        encrypted = safe_core.encrypt_block(plaintext, dek, custom_crypto_params)
        decrypted = safe_core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_ciphertext_from_different_algorithms_incompatible(
        self, safe_core, test_password, interactive_params, custom_crypto_params
    ):
        """Test that ciphertext from different algorithms can't be decrypted with wrong algorithm."""
        # Create storage with AES
        dek_aes, vb_aes = safe_core.initialize_storage(test_password, interactive_params)

        # Create storage with ChaCha20
        dek_chacha, vb_chacha = safe_core.initialize_storage(test_password, custom_crypto_params)

        plaintext = b"test"

        # Encrypt with AES
        encrypted_aes = safe_core.encrypt_block(plaintext, dek_aes, interactive_params)

        # Should decrypt correctly with AES key
        assert safe_core.decrypt_block(encrypted_aes, dek_aes) == plaintext

        # Should fail with ChaCha20 key (even though it's a valid DEK)
        with pytest.raises(DataIntegrityError):
            safe_core.decrypt_block(encrypted_aes, dek_chacha)


class TestEncryptionEdgeCases:
    """Test edge cases in encryption."""

    def test_encrypt_very_large_data(self, initialized_storage):
        """Test encryption of very large data (10 MB)."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # 10 MB of data
        plaintext = b"x" * (10 * 1024 * 1024)
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_single_byte(self, initialized_storage):
        """Test encryption of single byte."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"A"
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_null_bytes(self, initialized_storage):
        """Test encryption of null bytes."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"\x00" * 1000
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext

    def test_encrypt_unicode_text_as_bytes(self, initialized_storage):
        """Test encryption of unicode text encoded as bytes."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = "Привет мир! 你好世界!".encode("utf-8")
        encrypted = core.encrypt_block(plaintext, dek, params)
        decrypted = core.decrypt_block(encrypted, dek)

        assert decrypted == plaintext
        assert decrypted.decode("utf-8") == "Привет мир! 你好世界!"

    def test_multiple_encryptions_in_sequence(self, initialized_storage, random_data):
        """Test multiple encryptions in sequence."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        # Encrypt and decrypt 100 different messages
        for i in range(100):
            plaintext = random_data(100)
            encrypted = core.encrypt_block(plaintext, dek, params)
            decrypted = core.decrypt_block(encrypted, dek)
            assert decrypted == plaintext

    def test_encrypted_data_is_serializable(self, initialized_storage):
        """Test that encrypted data can be serialized and deserialized."""
        core = initialized_storage["core"]
        dek = initialized_storage["dek"]
        params = initialized_storage["params"]

        plaintext = b"test data"
        encrypted = core.encrypt_block(plaintext, dek, params)

        # Encrypted data should be bytes and serializable
        assert isinstance(encrypted, bytes)

        # Should be able to save to file and read back
        import io

        buffer = io.BytesIO()
        buffer.write(encrypted)
        buffer.seek(0)
        read_encrypted = buffer.read()

        decrypted = core.decrypt_block(read_encrypted, dek)
        assert decrypted == plaintext
