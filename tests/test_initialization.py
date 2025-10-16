"""Tests for storage initialization."""

import pytest

from safe_core import (
    SafeCore,
    get_default_crypto_params,
    ConfigurationError,
    KdfParams,
    CryptoParams,
    KdfId,
    CipherId,
)


class TestStorageInitialization:
    """Test storage initialization operations."""

    def test_initialize_storage_basic(self, safe_core, test_password, interactive_params):
        """Test basic storage initialization."""
        dek, verification_block = safe_core.initialize_storage(test_password, interactive_params)

        # DEK should be 32 bytes
        assert len(dek) == 32
        assert isinstance(dek, bytes)

        # Verification block should be non-empty
        assert len(verification_block) > 0
        assert isinstance(verification_block, bytes)

    def test_initialize_storage_different_passwords(self, safe_core, interactive_params):
        """Test that different passwords produce different verification blocks."""
        password1 = b"password1"
        password2 = b"password2"

        dek1, vb1 = safe_core.initialize_storage(password1, interactive_params)
        dek2, vb2 = safe_core.initialize_storage(password2, interactive_params)

        # DEKs should be different (randomly generated)
        assert dek1 != dek2

        # Verification blocks should be different
        assert vb1 != vb2

    def test_initialize_storage_multiple_times(self, safe_core, test_password, interactive_params):
        """Test that multiple initializations produce unique DEKs."""
        dek1, vb1 = safe_core.initialize_storage(test_password, interactive_params)
        dek2, vb2 = safe_core.initialize_storage(test_password, interactive_params)

        # Even with same password, DEKs should be different (random generation)
        assert dek1 != dek2
        assert vb1 != vb2

    def test_initialize_storage_all_security_levels(self, safe_core, test_password):
        """Test initialization with all security levels."""
        for level in ["interactive", "moderate", "high", "paranoid"]:
            params = get_default_crypto_params(level)
            dek, vb = safe_core.initialize_storage(test_password, params)

            assert len(dek) == 32
            assert len(vb) > 0

    def test_initialize_storage_chacha20(self, safe_core, test_password):
        """Test initialization with ChaCha20-Poly1305 cipher."""
        params = CryptoParams(
            kdf_id=KdfId.ARGON2ID,
            cipher_id=CipherId.CHACHA20_POLY1305,
            kdf_params=KdfParams(memory_cost=8192, time_cost=1, parallelism=1, key_length=32),
        )

        dek, vb = safe_core.initialize_storage(test_password, params)

        assert len(dek) == 32
        assert len(vb) > 0

    def test_initialize_storage_empty_password(self, safe_core, interactive_params):
        """Test initialization with empty password (should work)."""
        dek, vb = safe_core.initialize_storage(b"", interactive_params)

        assert len(dek) == 32
        assert len(vb) > 0

    def test_initialize_storage_long_password(self, safe_core, interactive_params):
        """Test initialization with very long password."""
        long_password = b"a" * 10000
        dek, vb = safe_core.initialize_storage(long_password, interactive_params)

        assert len(dek) == 32
        assert len(vb) > 0

    def test_initialize_storage_unicode_password(self, safe_core, interactive_params):
        """Test initialization with unicode password (as bytes)."""
        unicode_password = "пароль123".encode("utf-8")
        dek, vb = safe_core.initialize_storage(unicode_password, interactive_params)

        assert len(dek) == 32
        assert len(vb) > 0

    @pytest.mark.asyncio
    async def test_initialize_storage_async(self, safe_core, test_password, interactive_params):
        """Test async storage initialization."""
        dek, vb = await safe_core.initialize_storage_async(test_password, interactive_params)

        assert len(dek) == 32
        assert len(vb) > 0

    @pytest.mark.asyncio
    async def test_initialize_storage_async_produces_valid_blocks(
        self, safe_core, test_password, interactive_params
    ):
        """Test that async initialization produces valid verification blocks."""
        dek, vb = await safe_core.initialize_storage_async(test_password, interactive_params)

        # Should be able to authenticate with the verification block
        retrieved_dek = safe_core.authenticate_and_get_key(test_password, vb)
        assert retrieved_dek == dek


class TestInvalidConfiguration:
    """Test invalid configuration handling."""

    def test_invalid_kdf_params_low_memory(self, safe_core, test_password):
        """Test that invalid KDF params are rejected."""
        with pytest.raises(ConfigurationError):
            invalid_params = CryptoParams(
                kdf_id=KdfId.ARGON2ID,
                cipher_id=CipherId.AES_256_GCM,
                kdf_params=KdfParams(
                    memory_cost=4, time_cost=1, parallelism=1, key_length=32  # Too low (< 8)
                ),
            )

    def test_invalid_kdf_params_zero_time(self, safe_core, test_password):
        """Test that zero time cost is rejected."""
        with pytest.raises(ConfigurationError):
            invalid_params = CryptoParams(
                kdf_id=KdfId.ARGON2ID,
                cipher_id=CipherId.AES_256_GCM,
                kdf_params=KdfParams(
                    memory_cost=8192, time_cost=0, parallelism=1, key_length=32  # Invalid
                ),
            )

    def test_invalid_kdf_params_zero_parallelism(self, safe_core, test_password):
        """Test that zero parallelism is rejected."""
        with pytest.raises(ConfigurationError):
            invalid_params = CryptoParams(
                kdf_id=KdfId.ARGON2ID,
                cipher_id=CipherId.AES_256_GCM,
                kdf_params=KdfParams(
                    memory_cost=8192, time_cost=1, parallelism=0, key_length=32  # Invalid
                ),
            )

    def test_invalid_kdf_params_bad_key_length(self, safe_core, test_password):
        """Test that invalid key length is rejected."""
        with pytest.raises(ConfigurationError):
            invalid_params = CryptoParams(
                kdf_id=KdfId.ARGON2ID,
                cipher_id=CipherId.AES_256_GCM,
                kdf_params=KdfParams(
                    memory_cost=8192,
                    time_cost=1,
                    parallelism=1,
                    key_length=24,  # Invalid (must be 16 or 32)
                ),
            )


class TestConfigurationPresets:
    """Test configuration preset functions."""

    def test_get_all_preset_levels(self):
        """Test that all preset levels are available."""
        levels = ["interactive", "moderate", "high", "paranoid"]

        for level in levels:
            params = get_default_crypto_params(level)
            assert params.kdf_id == KdfId.ARGON2ID
            assert params.cipher_id == CipherId.AES_256_GCM
            assert params.kdf_params.key_length == 32

    def test_preset_security_progression(self):
        """Test that higher security levels have stronger parameters."""
        interactive = get_default_crypto_params("interactive")
        moderate = get_default_crypto_params("moderate")
        high = get_default_crypto_params("high")
        paranoid = get_default_crypto_params("paranoid")

        # Memory cost should increase
        assert interactive.kdf_params.memory_cost < moderate.kdf_params.memory_cost
        assert moderate.kdf_params.memory_cost < high.kdf_params.memory_cost
        assert high.kdf_params.memory_cost < paranoid.kdf_params.memory_cost

        # Time cost should increase
        assert interactive.kdf_params.time_cost <= moderate.kdf_params.time_cost
        assert moderate.kdf_params.time_cost <= high.kdf_params.time_cost
        assert high.kdf_params.time_cost <= paranoid.kdf_params.time_cost

    def test_invalid_preset_level(self):
        """Test that invalid preset level raises error."""
        with pytest.raises(ConfigurationError):
            get_default_crypto_params("invalid_level")

    def test_preset_default_is_high(self):
        """Test that default preset is 'high' security."""
        default = get_default_crypto_params()
        high = get_default_crypto_params("high")

        assert default.kdf_params.memory_cost == high.kdf_params.memory_cost
        assert default.kdf_params.time_cost == high.kdf_params.time_cost
