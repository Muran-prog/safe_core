"""Pytest configuration and shared fixtures."""

import pytest
import secrets

from safe_core import (
    SafeCore,
    get_default_crypto_params,
    CryptoParams,
    KdfParams,
    KdfId,
    CipherId,
)


@pytest.fixture
def safe_core():
    """Create a fresh SafeCore instance."""
    return SafeCore()


@pytest.fixture
def interactive_params():
    """Get interactive security level params (fast for tests)."""
    return get_default_crypto_params("interactive")


@pytest.fixture
def moderate_params():
    """Get moderate security level params."""
    return get_default_crypto_params("moderate")


@pytest.fixture
def high_params():
    """Get high security level params."""
    return get_default_crypto_params("high")


@pytest.fixture
def test_password():
    """Standard test password."""
    return b"test_password_123"


@pytest.fixture
def alternative_password():
    """Alternative password for testing password changes."""
    return b"new_password_456"


@pytest.fixture
def random_data():
    """Generate random test data."""

    def _generate(size=1024):
        return secrets.token_bytes(size)

    return _generate


@pytest.fixture
def initialized_storage(safe_core, test_password, interactive_params):
    """Create initialized storage with DEK and verification block."""
    dek, verification_block = safe_core.initialize_storage(test_password, interactive_params)
    return {
        "core": safe_core,
        "dek": dek,
        "verification_block": verification_block,
        "password": test_password,
        "params": interactive_params,
    }


@pytest.fixture
def custom_crypto_params():
    """Create custom crypto params for testing."""
    return CryptoParams(
        kdf_id=KdfId.ARGON2ID,
        cipher_id=CipherId.CHACHA20_POLY1305,
        kdf_params=KdfParams(
            memory_cost=8192, time_cost=1, parallelism=1, key_length=32  # 8 MB for fast tests
        ),
    )


@pytest.fixture
def large_data():
    """Generate large test data for streaming tests."""
    return secrets.token_bytes(5 * 1024 * 1024)  # 5 MB
